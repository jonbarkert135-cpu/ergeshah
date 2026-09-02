"""Provider abstraction: one method, one response shape, explicit error classes.

Error classification is the important part — the orchestrator reacts very differently to
"this key is out of money" (rotate + tell the human) and "slow down" (retry).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Block:
    """A piece of prompt. ``cache=True`` marks a stable prefix worth caching."""

    text: str
    cache: bool = False


@dataclass
class Message:
    role: str  # "user" | "assistant"
    content: str


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def merge(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cached_input_tokens + other.cached_input_tokens,
            self.cache_write_tokens + other.cache_write_tokens,
            self.cost_usd + other.cost_usd,
        )


@dataclass
class Completion:
    text: str
    model: str
    provider: str
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = ""


class ProviderError(Exception):
    """Base class. ``retryable`` decides whether the same key gets another chance."""

    retryable = False

    def __init__(self, message: str, status: int = 0, body: object = None):
        super().__init__(message)
        self.status = status
        self.body = body


class AuthError(ProviderError):
    """Key is invalid/revoked — never retry, mark the key dead."""


class QuotaError(ProviderError):
    """Key ran out of credits / hit a hard billing limit — rotate to the next key."""


class RateLimitError(ProviderError):
    """Temporary throttling — retry with backoff, key stays alive."""

    retryable = True


class TransientError(ProviderError):
    """5xx, timeouts, truncated responses — retry."""

    retryable = True


class BadRequestError(ProviderError):
    """Our fault: model name, context length, malformed payload."""


class Provider:
    kind = "base"

    def __init__(self, name: str, base_url: str, timeout: int = 300):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def complete(
        self,
        *,
        model: str,
        system: list[Block],
        messages: list[Message],
        api_key: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> Completion:  # pragma: no cover - interface
        raise NotImplementedError


QUOTA_MARKERS = (
    "insufficient_quota",
    "insufficient quota",
    "exceeded your current quota",
    "credit balance is too low",
    "billing_hard_limit_reached",
    "billing hard limit",
    "quota exceeded",
    "no credits",
    "insufficient balance",
    "payment required",
    "account_deactivated",
    "resource_exhausted",
    "out of credits",
    "spending limit",
)

AUTH_MARKERS = (
    "invalid api key",
    "invalid_api_key",
    "incorrect api key",
    "authentication_error",
    "unauthorized",
    "api key not valid",
    "invalid x-api-key",
    "permission_denied",
    "no auth credentials",
)


def classify(status: int, text: str, body: object = None) -> ProviderError:
    """Map an HTTP status + body onto the right error class."""
    low = (text or "").lower()
    if any(marker in low for marker in QUOTA_MARKERS):
        return QuotaError(_summarize(text), status, body)
    if status in (401, 403):
        return AuthError(_summarize(text), status, body)
    if status == 402:
        return QuotaError(_summarize(text), status, body)
    if status == 429:
        if any(marker in low for marker in AUTH_MARKERS):
            return AuthError(_summarize(text), status, body)
        return RateLimitError(_summarize(text), status, body)
    if status in (400, 404, 413, 422):
        if any(marker in low for marker in AUTH_MARKERS):
            return AuthError(_summarize(text), status, body)
        return BadRequestError(_summarize(text), status, body)
    if status >= 500 or status == 408:
        return TransientError(_summarize(text), status, body)
    return ProviderError(_summarize(text), status, body)


def _summarize(text: str, limit: int = 400) -> str:
    flat = " ".join((text or "").split())
    return flat[:limit] if flat else "no error body"
