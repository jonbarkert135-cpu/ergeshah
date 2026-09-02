"""Engine behaviour: rotation, retries, fallbacks, accounting, spend cap."""

from __future__ import annotations

import unittest
from unittest import mock

from hive.engine import BudgetExceeded, Engine, NoModelAvailable
from hive.providers.base import AuthError, Block, Message, QuotaError, RateLimitError, TransientError
from hive.tests.helpers import ScriptedProvider, TempProject

SYSTEM = [Block("rules", cache=True)]
MESSAGES = [Message("user", "go")]


class EngineTest(TempProject):
    env_lines = [
        "ANTHROPIC_API_KEY=sk-one",
        "ANTHROPIC_API_KEY_2=sk-two",
        "OPENAI_API_KEY=sk-openai",
        "HIVE_KEY_BUDGET=100000",
    ]

    def build(self, providers: dict[str, ScriptedProvider]) -> Engine:
        pool = self.make_pool()
        engine = Engine(self.cfg, self.store, pool, self.notifier)
        engine.router.available = sorted(providers)
        self.patcher = mock.patch(
            "hive.engine.build_provider", side_effect=lambda name, cfg: providers[name]
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        return engine

    def test_happy_path_records_usage_against_the_key(self):
        provider = ScriptedProvider("anthropic", ["### NOTES\nfine\n"])
        engine = self.build({"anthropic": provider})
        completion = engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t1", phase="build")
        self.assertEqual(completion.provider, "anthropic")
        self.assertAlmostEqual(engine.spend_usd, 0.01, places=6)
        rows = self.store.attempts("t1")
        self.assertEqual(rows[0]["outcome"], "ok:build")
        self.assertEqual(rows[0]["input_tokens"], 1000)
        key_row = [k for k in engine.pool.summary() if k["id"] == rows[0]["key_id"]][0]
        self.assertAlmostEqual(key_row["spent"], 10.0, places=3)  # $0.01 = 10 credits

    def test_quota_error_retires_the_key_and_uses_the_next_one(self):
        provider = ScriptedProvider("anthropic", [QuotaError("credit balance is too low", 400), "ok"])
        engine = self.build({"anthropic": provider})
        completion = engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t2")
        self.assertEqual(completion.text, "ok")
        statuses = {k["id"]: k["status"] for k in engine.pool.summary()}
        self.assertEqual(sum(1 for s in statuses.values() if s == "exhausted"), 1)
        self.assertIn("key_exhausted", [e["kind"] for e in self.store.events()])

    def test_invalid_key_is_marked_invalid(self):
        provider = ScriptedProvider("anthropic", [AuthError("invalid api key", 401), "ok"])
        engine = self.build({"anthropic": provider})
        engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t3")
        self.assertIn("invalid", [k["status"] for k in engine.pool.summary()])

    def test_rate_limit_is_retried_on_the_same_key(self):
        provider = ScriptedProvider("anthropic", [RateLimitError("slow down", 429), "recovered"])
        engine = self.build({"anthropic": provider})
        with mock.patch("hive.engine.time.sleep"):
            completion = engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t4")
        self.assertEqual(completion.text, "recovered")
        self.assertEqual([k["status"] for k in engine.pool.summary()].count("live"), 3)

    def test_falls_back_to_another_provider_when_one_is_hopeless(self):
        dead = ScriptedProvider("anthropic", [TransientError("500")] * 6)
        alive = ScriptedProvider("openai", ["from openai"])
        engine = self.build({"anthropic": dead, "openai": alive})
        with mock.patch("hive.engine.time.sleep"):
            completion = engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t5")
        self.assertEqual(completion.provider, "openai")

    def test_spend_cap_stops_the_run(self):
        self.cfg.max_spend_usd = 0.005
        provider = ScriptedProvider("anthropic", ["one", "two"])
        engine = self.build({"anthropic": provider})
        with self.assertRaises(BudgetExceeded):
            engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t6")
        self.assertIn("budget_exhausted", [e["kind"] for e in self.store.events()])

    def test_reviewer_avoids_the_authors_provider(self):
        anthropic = ScriptedProvider("anthropic", ["a"])
        openai = ScriptedProvider("openai", ["b"])
        engine = self.build({"anthropic": anthropic, "openai": openai})
        completion = engine.call(
            "reviewer_security", system=SYSTEM, messages=MESSAGES, task_id="t7", avoid_provider="anthropic"
        )
        self.assertEqual(completion.provider, "openai")

    def test_a_provider_outage_is_not_waited_out_forever(self):
        """Only missing keys justify pausing; broken candidates must fail fast."""
        engine = self.build(
            {
                "anthropic": ScriptedProvider("anthropic", [TransientError("500")] * 8),
                "openai": ScriptedProvider("openai", [TransientError("500")] * 8),
            }
        )
        with mock.patch("hive.engine.time.sleep"):
            with self.assertRaises(NoModelAvailable):
                engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t9")

    def test_no_provider_at_all_raises_instead_of_hanging(self):
        self.write_env(["HIVE_KEY_WAIT_TIMEOUT=1"])
        cfg_pool = self.make_pool()
        engine = Engine(self.cfg, self.store, cfg_pool, self.notifier)
        engine.router.available = []
        self.cfg.key_wait_timeout = 1
        with mock.patch("hive.keys.KeyPool.load", return_value=0), mock.patch("time.sleep"):
            with self.assertRaises(NoModelAvailable):
                engine.call("backend", system=SYSTEM, messages=MESSAGES)

    def test_empty_replies_are_retried_then_abandoned(self):
        engine = self.build(
            {
                "anthropic": ScriptedProvider("anthropic", [""] * 6),
                "openai": ScriptedProvider("openai", [""] * 6),
            }
        )
        with mock.patch("hive.engine.time.sleep"):
            with self.assertRaises(NoModelAvailable):
                engine.call("backend", system=SYSTEM, messages=MESSAGES, task_id="t8")
        self.assertTrue(any(a["outcome"] == "empty" for a in self.store.attempts("t8")))


if __name__ == "__main__":
    unittest.main()
