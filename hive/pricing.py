"""Token pricing so every call can be converted into money and into "credits".

Prices are USD per 1M tokens and are matched by longest-prefix on the model id, so
``claude-sonnet-4-5-20250929`` matches the ``claude-sonnet-4`` entry. Unknown models fall
back to ``DEFAULT_PRICE`` and are reported by ``hive doctor`` so you can correct them here
instead of silently mis-accounting. Cached input tokens are billed at
``cache_read_multiplier`` of the input price.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Price:
    input_per_mtok: float
    output_per_mtok: float
    cache_read_multiplier: float = 0.1
    cache_write_multiplier: float = 1.25


DEFAULT_PRICE = Price(3.0, 15.0)

# Longest-prefix table. Keep entries short and generic; update when a provider re-prices.
PRICES: dict[str, Price] = {
    # Anthropic
    "claude-opus": Price(15.0, 75.0),
    "claude-sonnet": Price(3.0, 15.0),
    "claude-haiku": Price(0.8, 4.0),
    "claude-3-5-haiku": Price(0.8, 4.0),
    "claude-3-haiku": Price(0.25, 1.25),
    # OpenAI
    "gpt-5-mini": Price(0.25, 2.0),
    "gpt-5-nano": Price(0.05, 0.4),
    "gpt-5": Price(1.25, 10.0),
    "gpt-4.1-mini": Price(0.4, 1.6),
    "gpt-4.1-nano": Price(0.1, 0.4),
    "gpt-4.1": Price(2.0, 8.0),
    "gpt-4o-mini": Price(0.15, 0.6),
    "gpt-4o": Price(2.5, 10.0),
    "o4-mini": Price(1.1, 4.4),
    "o3-mini": Price(1.1, 4.4),
    "o3": Price(2.0, 8.0),
    # Google
    "gemini-2.5-pro": Price(1.25, 10.0),
    "gemini-2.5-flash-lite": Price(0.1, 0.4),
    "gemini-2.5-flash": Price(0.3, 2.5),
    "gemini-2.0-flash": Price(0.1, 0.4),
    # DeepSeek / others
    "deepseek-reasoner": Price(0.55, 2.19),
    "deepseek-chat": Price(0.27, 1.1),
    "qwen": Price(0.4, 1.2),
    "kimi": Price(0.6, 2.5),
    "moonshot": Price(0.6, 2.5),
    "grok-4": Price(3.0, 15.0),
    "grok": Price(2.0, 10.0),
    "mistral-large": Price(2.0, 6.0),
    "mistral": Price(0.4, 2.0),
    "llama": Price(0.2, 0.6),
    # Local / test
    "ollama": Price(0.0, 0.0),
    "mock": Price(0.0, 0.0),
}


def price_for(model: str) -> Price:
    name = (model or "").lower()
    best: tuple[int, Price] | None = None
    for prefix, price in PRICES.items():
        if prefix in name and (best is None or len(prefix) > best[0]):
            best = (len(prefix), price)
    return best[1] if best else DEFAULT_PRICE


def is_known(model: str) -> bool:
    name = (model or "").lower()
    return any(prefix in name for prefix in PRICES)


def cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_input_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    p = price_for(model)
    fresh_input = max(0, input_tokens - cached_input_tokens - cache_write_tokens)
    total = fresh_input * p.input_per_mtok
    total += cached_input_tokens * p.input_per_mtok * p.cache_read_multiplier
    total += cache_write_tokens * p.input_per_mtok * p.cache_write_multiplier
    total += output_tokens * p.output_per_mtok
    return total / 1_000_000.0


def to_credits(unit: str, *, cost: float, input_tokens: int, output_tokens: int) -> float:
    """Convert one call into the operator's chosen credit unit.

    ``usd_milli`` (default): 1 credit = $0.001, so a 45 000-credit key is a $45 budget.
    ``tokens``: 1 credit = 1 token (input + output).
    ``ktokens``: 1 credit = 1000 tokens.
    ``requests``: 1 credit = 1 API call.
    """
    unit = (unit or "usd_milli").lower()
    if unit == "tokens":
        return float(input_tokens + output_tokens)
    if unit == "ktokens":
        return (input_tokens + output_tokens) / 1000.0
    if unit == "requests":
        return 1.0
    if unit in {"usd", "dollars"}:
        return cost
    return cost * 1000.0  # usd_milli
