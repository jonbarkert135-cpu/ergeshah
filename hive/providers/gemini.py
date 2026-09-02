"""Google Gemini ``generateContent``.

Gemini uses implicit caching for repeated prefixes, so the same "stable prefix" discipline
applies; ``cachedContentTokenCount`` tells us how much of it hit.
"""

from __future__ import annotations

from .. import pricing
from ..http import HttpFailure, request_json
from .base import Block, Completion, Message, Provider, TransientError, Usage, classify


class GeminiProvider(Provider):
    kind = "gemini"

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
        contents = [
            {
                "role": "model" if m.role == "assistant" else "user",
                "parts": [{"text": m.content}],
            }
            for m in messages
        ]
        payload: dict = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}

        url = f"{self.base_url}/models/{model}:generateContent"
        try:
            res = request_json(
                url,
                payload=payload,
                headers={"x-goog-api-key": api_key},
                timeout=self.timeout,
            )
        except HttpFailure as exc:
            raise TransientError(str(exc)) from exc

        if res.status >= 400 or not isinstance(res.body, dict):
            raise classify(res.status, res.text, res.body)

        body = res.body
        candidates = body.get("candidates") or []
        if not candidates:
            raise TransientError(f"no candidates: {res.text[:200]}")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))

        meta = body.get("usageMetadata", {}) or {}
        prompt_tokens = int(meta.get("promptTokenCount", 0) or 0)
        out_tokens = int(meta.get("candidatesTokenCount", 0) or 0)
        cached = int(meta.get("cachedContentTokenCount", 0) or 0)
        usage = Usage(
            input_tokens=prompt_tokens,
            output_tokens=out_tokens,
            cached_input_tokens=min(cached, prompt_tokens),
            cost_usd=pricing.cost_usd(model, prompt_tokens, out_tokens, cached, 0),
        )
        return Completion(
            text=text,
            model=model,
            provider=self.name,
            usage=usage,
            stop_reason=str(candidates[0].get("finishReason") or ""),
        )
