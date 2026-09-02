"""The key pool: discovery, per-key credit accounting, rotation, and waiting for a refill.

Discovery from ``.env`` (all forms are accepted):

    ANTHROPIC_API_KEY=sk-ant-...            # single key
    ANTHROPIC_API_KEY_2=sk-ant-...          # extra slots, any number
    OPENAI_API_KEYS=sk-a,sk-b,sk-c          # comma separated list
    DEEPSEEK_API_KEY=sk-...
    ANTHROPIC_KEY_BUDGET=45000              # per-provider budget override

Accounting: every call is converted to credits (see ``pricing.to_credits``) and charged to
the key that made it. At 80% of its budget the key emits a warning; when the budget is used
up — or the API answers "out of credits" — the key is retired and the pool rotates. When a
provider runs out of live keys entirely, ``wait_for_key`` re-reads ``.env`` on a timer, so
you can drop in a fresh key while the run is paused instead of restarting it.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

from . import pricing
from .config import PROVIDERS, Config, env_layers
from .notify import Notifier
from .store import Store
from .util import LOG, human_usd, now

# Extra env names people actually use for the same provider.
ALIASES: dict[str, str] = {
    "GOOGLE_API_KEY": "gemini",
    "GEMINI_API_KEY": "gemini",
    "CLAUDE_API_KEY": "anthropic",
    "OPENROUTER_KEY": "openrouter",
}

WARN_RATIO = 0.8


@dataclass
class KeyRecord:
    id: str
    provider: str
    secret: str
    budget_credits: float
    spent_credits: float = 0.0
    spent_usd: float = 0.0
    tokens: int = 0
    calls: int = 0
    status: str = "live"  # live | exhausted | invalid
    last_error: str = ""
    warned: bool = False

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.secret)

    @property
    def remaining(self) -> float:
        if self.budget_credits <= 0:
            return float("inf")
        return max(0.0, self.budget_credits - self.spent_credits)

    @property
    def label(self) -> str:
        tail = self.secret[-4:] if len(self.secret) > 8 else "****"
        return f"{self.id} (…{tail})"


def fingerprint(secret: str) -> str:
    return hashlib.sha256((secret or "").encode("utf-8")).hexdigest()[:16]


class NoKeysAvailable(RuntimeError):
    def __init__(self, provider: str):
        super().__init__(f"no live API key for provider '{provider}'")
        self.provider = provider


class KeyPool:
    def __init__(self, cfg: Config, store: Store, notifier: Notifier):
        self.cfg = cfg
        self.store = store
        self.notifier = notifier
        self._lock = threading.RLock()
        self.keys: dict[str, KeyRecord] = {}
        self._round_robin: dict[str, int] = {}
        self.load()

    # ------------------------------------------------------------------ discovery
    def load(self, env: dict[str, str] | None = None) -> int:
        """(Re)discover keys from the environment. Returns the number of new keys found."""
        env = env if env is not None else env_layers(self.cfg.env_file)
        found: dict[str, list[str]] = {}

        def add(provider: str, secret: str) -> None:
            secret = (secret or "").strip()
            if not secret or secret.lower().startswith(("your-", "sk-xxx", "changeme", "<")):
                return
            bucket = found.setdefault(provider, [])
            if secret not in bucket:
                bucket.append(secret)

        for name, value in env.items():
            upper = name.upper()
            if upper in ALIASES:
                add(ALIASES[upper], value)
                continue
            for provider in PROVIDERS:
                prefix = provider.upper()
                if upper == f"{prefix}_API_KEY" or (
                    upper.startswith(f"{prefix}_API_KEY_") and upper[len(prefix) + 9 :].isdigit()
                ):
                    add(provider, value)
                elif upper == f"{prefix}_API_KEYS":
                    for part in value.split(","):
                        add(provider, part)

        # keyless providers (local Ollama, mock) are usable if explicitly enabled
        for provider, meta in PROVIDERS.items():
            if meta.get("keyless") and env.get(f"HIVE_ENABLE_{provider.upper()}", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }:
                add(provider, f"keyless:{provider}")

        new_keys = 0
        with self._lock:
            for provider, secrets in found.items():
                budget = self._budget_for(provider, env)
                for index, secret in enumerate(secrets, start=1):
                    key_id = f"{provider}#{index}"
                    row = self.store.sync_key(key_id, provider, fingerprint(secret), budget)
                    existing = self.keys.get(key_id)
                    record = KeyRecord(
                        id=key_id,
                        provider=provider,
                        secret=secret,
                        budget_credits=float(row["budget_credits"]),
                        spent_credits=float(row["spent_credits"]),
                        spent_usd=float(row["spent_usd"]),
                        tokens=int(row["tokens"]),
                        calls=int(row["calls"]),
                        status=str(row["status"]),
                        last_error=str(row["last_error"]),
                    )
                    if existing is None:
                        new_keys += 1
                    elif existing.secret != secret:
                        new_keys += 1
                        LOG.info("key %s replaced with a fresh secret — budget reset", key_id)
                    self.keys[key_id] = record
        return new_keys

    def _budget_for(self, provider: str, env: dict[str, str]) -> float:
        raw = env.get(f"{provider.upper()}_KEY_BUDGET") or env.get("HIVE_KEY_BUDGET")
        if raw is None:
            return float(self.cfg.default_key_budget)
        try:
            return float(str(raw).replace("_", "").strip())
        except ValueError:
            return float(self.cfg.default_key_budget)

    # ------------------------------------------------------------------ selection
    def live_keys(self, provider: str | None = None) -> list[KeyRecord]:
        with self._lock:
            return [
                k
                for k in self.keys.values()
                if k.status == "live" and (provider is None or k.provider == provider)
            ]

    def live_providers(self) -> list[str]:
        return sorted({k.provider for k in self.live_keys()})

    def acquire(self, provider: str) -> KeyRecord:
        """Pick the live key with the most headroom (ties → round-robin)."""
        with self._lock:
            candidates = self.live_keys(provider)
            if not candidates:
                raise NoKeysAvailable(provider)
            candidates.sort(key=lambda k: (-k.remaining if k.remaining != float("inf") else 0, k.id))
            if candidates[0].remaining == float("inf"):
                idx = self._round_robin.get(provider, 0) % len(candidates)
                self._round_robin[provider] = idx + 1
                return candidates[idx]
            return candidates[0]

    # ------------------------------------------------------------------ accounting
    def record_usage(self, key: KeyRecord, usage_cost_usd: float, input_tokens: int, output_tokens: int) -> None:
        credits = pricing.to_credits(
            self.cfg.credit_unit,
            cost=usage_cost_usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        with self._lock:
            key.spent_credits += credits
            key.spent_usd += usage_cost_usd
            key.tokens += input_tokens + output_tokens
            key.calls += 1
            self.store.record_key_usage(key.id, credits, usage_cost_usd, input_tokens + output_tokens)
            if key.budget_credits > 0:
                ratio = key.spent_credits / key.budget_credits
                if ratio >= 1.0:
                    self.retire(key, "budget", f"spent {key.spent_credits:.0f}/{key.budget_credits:.0f} credits")
                elif ratio >= WARN_RATIO and not key.warned:
                    key.warned = True
                    self.notifier.event(
                        "key_warning",
                        f"{key.label} is at {ratio * 100:.0f}% of its budget",
                        f"{key.remaining:.0f} credits left ({human_usd(key.spent_usd)} spent). "
                        f"Have the next key ready.",
                    )

    def retire(self, key: KeyRecord, reason: str, detail: str = "") -> None:
        """Take a key out of rotation and shout about it."""
        status = "invalid" if reason == "invalid" else "exhausted"
        with self._lock:
            key.status = status
            key.last_error = detail
            self.store.set_key_status(key.id, status, detail)
            remaining_here = len(self.live_keys(key.provider))
        kind = "key_invalid" if status == "invalid" else "key_exhausted"
        title = (
            f"{key.label} is {'invalid' if status == 'invalid' else 'out of credits'}"
            f" — {remaining_here} live key(s) left for {key.provider}"
        )
        body = (
            f"{detail}\n\nAdd a replacement to {self.cfg.env_file}, e.g.\n"
            f"  {key.provider.upper()}_API_KEY_{len(self.keys_for(key.provider)) + 1}=<new key>\n"
            f"Hive re-reads the file automatically while it waits."
        )
        self.notifier.event(kind, title, body)

    def keys_for(self, provider: str) -> list[KeyRecord]:
        with self._lock:
            return [k for k in self.keys.values() if k.provider == provider]

    # ------------------------------------------------------------------ waiting
    def wait_for_key(self, provider: str, sleep: float | None = None, timeout: int | None = None) -> KeyRecord:
        """Block until a usable key for ``provider`` (or any provider, if it is empty) appears."""
        import time

        interval = float(sleep if sleep is not None else self.cfg.key_wait_seconds)
        deadline = None
        limit = self.cfg.key_wait_timeout if timeout is None else timeout
        if limit and limit > 0:
            deadline = now() + limit
        announced = False
        while True:
            try:
                return self.acquire(provider)
            except NoKeysAvailable:
                pass
            if not announced:
                self.notifier.event(
                    "blocked",
                    f"paused — no live key for {provider}",
                    f"Waiting for a new {provider.upper()}_API_KEY* entry in {self.cfg.env_file}. "
                    f"Checking every {interval:.0f}s.",
                )
                announced = True
            if deadline and now() > deadline:
                raise NoKeysAvailable(provider)
            time.sleep(interval)
            added = self.load()
            if added:
                LOG.info("picked up %d new key(s) from %s", added, self.cfg.env_file)
                self.notifier.clear_attention()

    # ------------------------------------------------------------------ reporting
    def summary(self) -> list[dict]:
        with self._lock:
            out = []
            for key in sorted(self.keys.values(), key=lambda k: k.id):
                out.append(
                    {
                        "id": key.id,
                        "provider": key.provider,
                        "status": key.status,
                        "budget": key.budget_credits,
                        "spent": round(key.spent_credits, 2),
                        "remaining": (None if key.remaining == float("inf") else round(key.remaining, 2)),
                        "usd": round(key.spent_usd, 4),
                        "tokens": key.tokens,
                        "calls": key.calls,
                        "last_error": key.last_error,
                    }
                )
            return out
