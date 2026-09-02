"""Provider registry."""

from __future__ import annotations

from ..config import PROVIDERS, Config
from .anthropic import AnthropicProvider
from .base import (
    AuthError,
    BadRequestError,
    Block,
    Completion,
    Message,
    Provider,
    ProviderError,
    QuotaError,
    RateLimitError,
    TransientError,
    Usage,
)
from .gemini import GeminiProvider
from .mock import MockProvider
from .openai_compat import OpenAICompatProvider

__all__ = [
    "AuthError",
    "BadRequestError",
    "Block",
    "Completion",
    "Message",
    "Provider",
    "ProviderError",
    "QuotaError",
    "RateLimitError",
    "TransientError",
    "Usage",
    "build_provider",
    "known_providers",
]

_KINDS = {
    "anthropic": AnthropicProvider,
    "openai": OpenAICompatProvider,
    "gemini": GeminiProvider,
    "mock": MockProvider,
}

_CACHE: dict[str, Provider] = {}


def known_providers() -> list[str]:
    return sorted(PROVIDERS)


def build_provider(name: str, cfg: Config) -> Provider:
    """Return (and memoize) a provider client. Unknown names default to the OpenAI wire format."""
    if name in _CACHE:
        return _CACHE[name]
    kind = cfg.provider_kind(name)
    base_url = cfg.base_url(name)
    if not base_url:
        raise BadRequestError(
            f"provider '{name}' has no base URL — set HIVE_BASE_URL_{name.upper()} in .env"
        )
    cls = _KINDS.get(kind, OpenAICompatProvider)
    provider = cls(name, base_url, cfg.http_timeout)
    _CACHE[name] = provider
    return provider


def reset_cache() -> None:
    _CACHE.clear()
