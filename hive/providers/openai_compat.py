"""OpenAI-compatible ``/chat/completions``.

One class covers OpenAI, DeepSeek, OpenRouter, Groq, Mistral, xAI, Together, Moonshot and a
local Ollama server. Caching on these APIs is automatic (prefix caching), so we only have to
keep the prompt prefix byte-stable and read ``cached_tokens`` back out of the usage object.
"""

from __future__ import annotations

from .. import pricing
from ..http import HttpFailure, request_json
from .base import Block, Completion, Message, Provider, TransientError, Usage, classify

# Models that reject `temperature` or use `max_completion_tokens` instead of `max_tokens`.
RESTRICTED_PREFIXES = ("o1", "o3", "o4", "gpt-5")


class OpenAICompatProvider(Provider):
    kind = "openai"

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
        system_text = "\n\n".join(b.text for b in system if b.text.strip())
        wire: list[dict] = []
        if system_text:
            wire.append({"role": "system", "content": system_text})
        wire.extend({"role": m.role, "content": m.content} for m in messages)

        restricted = any(model.lower().startswith(p) for p in RESTRICTED_PREFIXES)
        payload: dict = {"model": model, "messages": wire}
        if restricted:
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["max_tokens"] = max_tokens
            payload["temperature"] = temperature

        headers = {"authorization": f"Bearer {api_key}"} if api_key else {}
        if "openrouter" in self.base_url:
            headers["http-referer"] = "https://github.com/hive-orchestrator"
            headers["x-title"] = "Hive"

        try:
            res = request_json(
                f"{self.base_url}/chat/completions",
                payload=payload,
                headers=headers,
                timeout=self.timeout,
            )
        except HttpFailure as exc:
            raise TransientError(str(exc)) from exc

        if res.status >= 400 or not isinstance(res.body, dict):
            raise classify(res.status, res.text, res.body)

        body = res.body
        choices = body.get("choices") or []
        if not choices:
            raise TransientError(f"no choices in response: {res.text[:200]}")
        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        if isinstance(text, list):  # some gateways return content parts
            text = "".join(part.get("text", "") for part in text if isinstance(part, dict))
        reasoning = message.get("reasoning_content")
        if not text and isinstance(reasoning, str):
            text = reasoning

        raw_usage = body.get("usage", {}) or {}
        prompt_tokens = int(raw_usage.get("prompt_tokens", 0) or 0)
        completion_tokens = int(raw_usage.get("completion_tokens", 0) or 0)
        details = raw_usage.get("prompt_tokens_details") or {}
        cached = int(details.get("cached_tokens", 0) or 0)
        if not cached:  # DeepSeek reports it at the top level
            cached = int(raw_usage.get("prompt_cache_hit_tokens", 0) or 0)
        usage = Usage(
            input_tokens=prompt_tokens,
            output_tokens=completion_tokens,
            cached_input_tokens=min(cached, prompt_tokens),
            cost_usd=pricing.cost_usd(model, prompt_tokens, completion_tokens, cached, 0),
        )
        return Completion(
            text=text,
            model=body.get("model", model),
            provider=self.name,
            usage=usage,
            stop_reason=str(choices[0].get("finish_reason") or ""),
        )
