"""Anthropic Messages API with explicit prompt caching.

Blocks marked ``cache=True`` get ``cache_control: {"type": "ephemeral"}``, which is where
most of the savings in a long build come from: the system rules + repo map are re-sent on
every call but billed at ~10% after the first hit.
"""

from __future__ import annotations

from .. import pricing
from ..http import HttpFailure, request_json
from .base import Block, Completion, Message, Provider, TransientError, Usage, classify

API_VERSION = "2023-06-01"
MAX_CACHE_BLOCKS = 4  # Anthropic allows at most 4 cache_control breakpoints


class AnthropicProvider(Provider):
    kind = "anthropic"

    def complete(
        self,
        *,
        model: str,
        system: list[Block],
        messages: list[Message],
        api_key: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> Completion:
        system_blocks: list[dict] = []
        cache_marks = 0
        for block in system:
            if not block.text.strip():
                continue
            item: dict = {"type": "text", "text": block.text}
            if block.cache and cache_marks < MAX_CACHE_BLOCKS:
                item["cache_control"] = {"type": "ephemeral"}
                cache_marks += 1
            system_blocks.append(item)

        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_blocks,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        headers = {
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
        }
        try:
            res = request_json(
                f"{self.base_url}/v1/messages",
                payload=payload,
                headers=headers,
                timeout=self.timeout,
            )
        except HttpFailure as exc:
            raise TransientError(str(exc)) from exc

        if res.status >= 400 or not isinstance(res.body, dict):
            raise classify(res.status, res.text, res.body)

        body = res.body
        text = "".join(
            part.get("text", "") for part in body.get("content", []) if part.get("type") == "text"
        )
        raw_usage = body.get("usage", {}) or {}
        cached = int(raw_usage.get("cache_read_input_tokens", 0) or 0)
        written = int(raw_usage.get("cache_creation_input_tokens", 0) or 0)
        # Anthropic reports input_tokens excluding cached/created tokens.
        fresh = int(raw_usage.get("input_tokens", 0) or 0)
        out = int(raw_usage.get("output_tokens", 0) or 0)
        usage = Usage(
            input_tokens=fresh + cached + written,
            output_tokens=out,
            cached_input_tokens=cached,
            cache_write_tokens=written,
            cost_usd=pricing.cost_usd(model, fresh + cached + written, out, cached, written),
        )
        return Completion(
            text=text,
            model=body.get("model", model),
            provider=self.name,
            usage=usage,
            stop_reason=str(body.get("stop_reason") or ""),
        )
