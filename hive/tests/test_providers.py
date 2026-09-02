"""Wire-format handling: usage/caching parsing and error classification per provider."""

from __future__ import annotations

import unittest
from unittest import mock

from hive.http import HttpFailure, HttpResult
from hive.providers.anthropic import AnthropicProvider
from hive.providers.base import (
    AuthError,
    BadRequestError,
    Block,
    Message,
    QuotaError,
    RateLimitError,
    TransientError,
    classify,
)
from hive.providers.gemini import GeminiProvider
from hive.providers.openai_compat import OpenAICompatProvider

SYSTEM = [Block("stable rules", cache=True), Block("role")]
MESSAGES = [Message("user", "do the thing")]


def result(status: int, body: dict | None, text: str = "") -> HttpResult:
    import json

    return HttpResult(status, body, text or (json.dumps(body) if body else ""), {})


class AnthropicTest(unittest.TestCase):
    def test_cache_control_is_attached_to_stable_blocks_only(self):
        captured = {}

        def fake(url, **kwargs):
            captured.update(kwargs["payload"])
            return result(
                200,
                {
                    "model": "claude-sonnet-4-5",
                    "content": [{"type": "text", "text": "done"}],
                    "usage": {
                        "input_tokens": 100,
                        "cache_read_input_tokens": 900,
                        "cache_creation_input_tokens": 0,
                        "output_tokens": 50,
                    },
                    "stop_reason": "end_turn",
                },
            )

        with mock.patch("hive.providers.anthropic.request_json", side_effect=fake):
            completion = AnthropicProvider("anthropic", "https://api.anthropic.com").complete(
                model="claude-sonnet-4-5", system=SYSTEM, messages=MESSAGES, api_key="sk-ant"
            )
        blocks = captured["system"]
        self.assertIn("cache_control", blocks[0])
        self.assertNotIn("cache_control", blocks[1])
        self.assertEqual(completion.text, "done")
        self.assertEqual(completion.usage.input_tokens, 1000)
        self.assertEqual(completion.usage.cached_input_tokens, 900)
        # cached input is billed at a tenth, so cost must be far below the uncached price
        self.assertLess(completion.usage.cost_usd, 1000 * 3.0 / 1e6)

    def test_http_failure_becomes_transient(self):
        with mock.patch("hive.providers.anthropic.request_json", side_effect=HttpFailure("timeout")):
            with self.assertRaises(TransientError):
                AnthropicProvider("anthropic", "https://x").complete(
                    model="m", system=SYSTEM, messages=MESSAGES, api_key="k"
                )

    def test_out_of_credits_is_a_quota_error(self):
        body = {"error": {"type": "invalid_request_error", "message": "Your credit balance is too low"}}
        with mock.patch("hive.providers.anthropic.request_json", return_value=result(400, body)):
            with self.assertRaises(QuotaError):
                AnthropicProvider("anthropic", "https://x").complete(
                    model="m", system=SYSTEM, messages=MESSAGES, api_key="k"
                )


class OpenAICompatTest(unittest.TestCase):
    def test_usage_and_cached_tokens(self):
        body = {
            "model": "gpt-5-mini",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 1200,
                "completion_tokens": 40,
                "prompt_tokens_details": {"cached_tokens": 1000},
            },
        }
        with mock.patch("hive.providers.openai_compat.request_json", return_value=result(200, body)):
            completion = OpenAICompatProvider("openai", "https://api.openai.com/v1").complete(
                model="gpt-5-mini", system=SYSTEM, messages=MESSAGES, api_key="sk"
            )
        self.assertEqual(completion.usage.cached_input_tokens, 1000)
        self.assertEqual(completion.usage.input_tokens, 1200)

    def test_deepseek_style_cache_hit_field(self):
        body = {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 500, "completion_tokens": 10, "prompt_cache_hit_tokens": 400},
        }
        with mock.patch("hive.providers.openai_compat.request_json", return_value=result(200, body)):
            completion = OpenAICompatProvider("deepseek", "https://api.deepseek.com/v1").complete(
                model="deepseek-chat", system=SYSTEM, messages=MESSAGES, api_key="sk"
            )
        self.assertEqual(completion.usage.cached_input_tokens, 400)

    def test_reasoning_models_get_max_completion_tokens_and_no_temperature(self):
        captured = {}

        def fake(url, **kwargs):
            captured.update(kwargs["payload"])
            return result(200, {"choices": [{"message": {"content": "ok"}}], "usage": {}})

        with mock.patch("hive.providers.openai_compat.request_json", side_effect=fake):
            OpenAICompatProvider("openai", "https://api.openai.com/v1").complete(
                model="gpt-5", system=SYSTEM, messages=MESSAGES, api_key="sk", max_tokens=99
            )
        self.assertEqual(captured["max_completion_tokens"], 99)
        self.assertNotIn("temperature", captured)

    def test_insufficient_quota_is_classified(self):
        body = {"error": {"code": "insufficient_quota", "message": "You exceeded your current quota"}}
        with mock.patch("hive.providers.openai_compat.request_json", return_value=result(429, body)):
            with self.assertRaises(QuotaError):
                OpenAICompatProvider("openai", "https://x/v1").complete(
                    model="gpt-5", system=SYSTEM, messages=MESSAGES, api_key="sk"
                )


class GeminiTest(unittest.TestCase):
    def test_usage_metadata(self):
        body = {
            "candidates": [{"content": {"parts": [{"text": "hello"}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 300, "candidatesTokenCount": 20, "cachedContentTokenCount": 100},
        }
        with mock.patch("hive.providers.gemini.request_json", return_value=result(200, body)):
            completion = GeminiProvider("gemini", "https://g/v1beta").complete(
                model="gemini-2.5-flash", system=SYSTEM, messages=MESSAGES, api_key="k"
            )
        self.assertEqual(completion.text, "hello")
        self.assertEqual(completion.usage.input_tokens, 300)
        self.assertEqual(completion.usage.cached_input_tokens, 100)


class ClassifyTest(unittest.TestCase):
    def test_status_mapping(self):
        self.assertIsInstance(classify(401, "invalid api key"), AuthError)
        self.assertIsInstance(classify(403, "forbidden"), AuthError)
        self.assertIsInstance(classify(402, "payment required"), QuotaError)
        self.assertIsInstance(classify(429, "rate limit exceeded, slow down"), RateLimitError)
        self.assertIsInstance(classify(429, "insufficient_quota"), QuotaError)
        self.assertIsInstance(classify(400, "unknown model"), BadRequestError)
        self.assertIsInstance(classify(503, "upstream unavailable"), TransientError)
        self.assertIsInstance(classify(500, "boom"), TransientError)

    def test_quota_wording_wins_over_status(self):
        self.assertIsInstance(classify(400, "Your credit balance is too low to run this"), QuotaError)
        self.assertIsInstance(classify(403, "billing hard limit reached"), QuotaError)

    def test_retryable_flags(self):
        self.assertTrue(classify(429, "slow down").retryable)
        self.assertFalse(classify(401, "nope").retryable)


if __name__ == "__main__":
    unittest.main()
