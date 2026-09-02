"""The metered call layer: role → provider → key → HTTP, with rotation and bookkeeping.

Every LLM call in Hive goes through :meth:`Engine.call`, which is what makes the promises in
the README true:

* the right model for the role (cost-tiered routing, with fallbacks)
* the right key (most headroom first), retired the moment it dies
* retries on throttling, rotation on quota/auth failures
* pause-and-wait when a provider has no live key left, resume when you add one
* every token, dollar and credit written to SQLite before the result is returned
* a global spend cap that stops the run instead of surprising you on an invoice
"""

from __future__ import annotations

import random
import threading
import time

from .config import Config
from .keys import KeyPool, KeyRecord, NoKeysAvailable
from .notify import Notifier
from .providers import (
    AuthError,
    BadRequestError,
    Block,
    Completion,
    Message,
    ProviderError,
    QuotaError,
    RateLimitError,
    TransientError,
    build_provider,
)
from .roster import ROLES, Candidate, Router
from .store import Store
from .util import LOG, human_usd

MAX_TRANSIENT_RETRIES = 3


class BudgetExceeded(RuntimeError):
    pass


class NoModelAvailable(RuntimeError):
    pass


class Engine:
    def __init__(self, cfg: Config, store: Store, pool: KeyPool, notifier: Notifier):
        self.cfg = cfg
        self.store = store
        self.pool = pool
        self.notifier = notifier
        self.router = Router(cfg, pool.live_providers())
        self._lock = threading.Lock()
        self._spend_usd = float(store.totals()["cost_usd"])

    # ------------------------------------------------------------------ helpers
    def refresh_router(self) -> None:
        self.router.available = self.pool.live_providers()

    @property
    def spend_usd(self) -> float:
        with self._lock:
            return self._spend_usd

    def _charge(self, completion: Completion, key: KeyRecord) -> None:
        usage = completion.usage
        self.pool.record_usage(key, usage.cost_usd, usage.input_tokens, usage.output_tokens)
        with self._lock:
            self._spend_usd += usage.cost_usd
            total = self._spend_usd
        if self.cfg.max_spend_usd > 0 and total >= self.cfg.max_spend_usd:
            self.notifier.event(
                "budget_exhausted",
                f"global spend cap reached: {human_usd(total)} of {human_usd(self.cfg.max_spend_usd)}",
                "Raise HIVE_MAX_SPEND_USD in .env to continue.",
            )
            raise BudgetExceeded(f"spend cap reached ({human_usd(total)})")

    # ------------------------------------------------------------------ main entry
    def call(
        self,
        role: str,
        *,
        system: list[Block],
        messages: list[Message],
        task_id: str = "",
        phase: str = "",
        attempt: int = 1,
        max_tokens: int | None = None,
        temperature: float = 0.2,
        avoid_provider: str | None = None,
        allow_wait: bool = True,
    ) -> Completion:
        role_def = ROLES.get(role) or ROLES["backend"]
        limit = max_tokens or min(role_def.max_output, self.cfg.max_output_tokens)
        self.refresh_router()
        candidates = self.router.candidates(role, avoid_provider=avoid_provider)
        if not candidates:
            # Nothing configured/live at all: wait for a key rather than crashing the run.
            waited = self._wait_for_any_provider(role)
            if not waited:
                raise NoModelAvailable(f"no provider available for role '{role}'")
            candidates = self.router.candidates(role, avoid_provider=avoid_provider)
            if not candidates:
                raise NoModelAvailable(f"no provider available for role '{role}'")

        last_error: Exception | None = None
        keys_missing = False
        for candidate in candidates:
            try:
                return self._call_candidate(
                    candidate,
                    role=role,
                    system=system,
                    messages=messages,
                    task_id=task_id,
                    phase=phase,
                    attempt=attempt,
                    max_tokens=limit,
                    temperature=temperature,
                )
            except (NoKeysAvailable, _CandidateDead) as exc:
                last_error = exc
                keys_missing = keys_missing or isinstance(exc, NoKeysAvailable)
                LOG.warning("candidate %s:%s unusable (%s) — falling back", candidate.provider, candidate.model, exc)
                continue
            except BudgetExceeded:
                raise

        # Every candidate is dead. Only *missing keys* are worth waiting for — anything else
        # (bad model name, provider outage, empty replies) would just spin forever.
        if keys_missing and allow_wait and self._wait_for_any_provider(role):
            return self.call(
                role,
                system=system,
                messages=messages,
                task_id=task_id,
                phase=phase,
                attempt=attempt,
                max_tokens=limit,
                temperature=temperature,
                avoid_provider=avoid_provider,
                allow_wait=False,
            )
        raise NoModelAvailable(f"all candidates failed for role '{role}': {last_error}")

    # ------------------------------------------------------------------ internals
    def _call_candidate(
        self,
        candidate: Candidate,
        *,
        role: str,
        system: list[Block],
        messages: list[Message],
        task_id: str,
        phase: str,
        attempt: int,
        max_tokens: int,
        temperature: float,
    ) -> Completion:
        provider = build_provider(candidate.provider, self.cfg)
        transient = 0
        while True:
            key = self.pool.acquire(candidate.provider)  # raises NoKeysAvailable
            try:
                completion = provider.complete(
                    model=candidate.model,
                    system=system,
                    messages=messages,
                    api_key="" if key.secret.startswith("keyless:") else key.secret,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            except (AuthError, QuotaError) as exc:
                self.pool.retire(key, "invalid" if isinstance(exc, AuthError) else "quota", str(exc))
                self._record(task_id, attempt, role, candidate, key, "key_dead", str(exc), None)
                continue  # try the next key of the same provider
            except (RateLimitError, TransientError) as exc:
                transient += 1
                self._record(task_id, attempt, role, candidate, key, "retry", str(exc), None)
                if transient > MAX_TRANSIENT_RETRIES:
                    raise _CandidateDead(f"{type(exc).__name__}: {exc}") from exc
                delay = _backoff(transient, getattr(exc, "status", 0))
                LOG.info("%s throttled/transient (%s) — retry in %.1fs", candidate.provider, exc, delay)
                time.sleep(delay)
                continue
            except BadRequestError as exc:
                self._record(task_id, attempt, role, candidate, key, "bad_request", str(exc), None)
                raise _CandidateDead(f"bad request: {exc}") from exc
            except ProviderError as exc:
                self._record(task_id, attempt, role, candidate, key, "error", str(exc), None)
                raise _CandidateDead(str(exc)) from exc

            if not completion.text.strip():
                transient += 1
                self._record(task_id, attempt, role, candidate, key, "empty", completion.stop_reason, completion)
                if transient > MAX_TRANSIENT_RETRIES:
                    raise _CandidateDead("empty responses")
                continue

            self._charge(completion, key)
            self._record(task_id, attempt, role, candidate, key, f"ok:{phase}" if phase else "ok", "", completion)
            LOG.info(
                "%-18s %-9s %-28s in=%d cached=%d out=%d %s",
                f"{role}/{phase or 'call'}",
                candidate.provider,
                candidate.model,
                completion.usage.input_tokens,
                completion.usage.cached_input_tokens,
                completion.usage.output_tokens,
                human_usd(completion.usage.cost_usd),
            )
            return completion

    def _record(
        self,
        task_id: str,
        attempt: int,
        role: str,
        candidate: Candidate,
        key: KeyRecord,
        outcome: str,
        detail: str,
        completion: Completion | None,
    ) -> None:
        usage = completion.usage if completion else None
        self.store.add_attempt(
            task_id=task_id or "-",
            n=attempt,
            role=role,
            provider=candidate.provider,
            model=candidate.model,
            key_id=key.id,
            outcome=outcome,
            detail=detail[:1000],
            input_tokens=usage.input_tokens if usage else 0,
            output_tokens=usage.output_tokens if usage else 0,
            cached_tokens=usage.cached_input_tokens if usage else 0,
            cost_usd=usage.cost_usd if usage else 0.0,
        )
        if task_id and usage:
            self.store.bump_task_cost(task_id, usage.cost_usd, usage.total_tokens)

    def _wait_for_any_provider(self, role: str) -> bool:
        """Pause the run until at least one provider has a live key again."""
        role_def = ROLES.get(role) or ROLES["backend"]
        target = next((p for p in role_def.prefer if self.pool.keys_for(p)), None)
        target = target or next(iter({k.provider for k in self.pool.keys.values()}), "")
        if not target:
            self.notifier.event(
                "blocked",
                "no API keys configured at all",
                f"Add at least one provider key to {self.cfg.env_file} (see .env.example).",
            )
        try:
            self.pool.wait_for_key(target or "anthropic")
        except NoKeysAvailable:
            return False
        self.refresh_router()
        return bool(self.router.available)


class _CandidateDead(RuntimeError):
    """This provider/model cannot serve the request; try the next candidate."""


def _backoff(attempt: int, status: int = 0) -> float:
    base = 2.0 if status == 429 else 1.5
    return min(60.0, base**attempt + random.uniform(0, 1.0))
