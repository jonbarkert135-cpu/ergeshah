"""Key discovery, budgets, rotation and the pause/refill cycle."""

from __future__ import annotations

import threading
import time
import unittest

from hive import pricing
from hive.keys import KeyPool, NoKeysAvailable
from hive.tests.helpers import TempProject


class DiscoveryTest(TempProject):
    def test_all_env_shapes_are_discovered(self):
        self.write_env(
            [
                "ANTHROPIC_API_KEY=sk-ant-one",
                "ANTHROPIC_API_KEY_2=sk-ant-two",
                "OPENAI_API_KEYS=sk-a,sk-b",
                "GEMINI_API_KEY=goog-1",
                "HIVE_KEY_BUDGET=1000",
            ]
        )
        pool = KeyPool(self.cfg, self.store, self.notifier)
        ids = sorted(k.id for k in pool.keys.values())
        self.assertEqual(ids, ["anthropic#1", "anthropic#2", "gemini#1", "openai#1", "openai#2"])
        self.assertEqual(sorted(pool.live_providers()), ["anthropic", "gemini", "openai"])
        self.assertEqual(pool.keys["anthropic#1"].budget_credits, 1000)

    def test_placeholders_are_ignored(self):
        self.write_env(["ANTHROPIC_API_KEY=", "OPENAI_API_KEY=your-key-here", "GROQ_API_KEY=<paste here>"])
        pool = KeyPool(self.cfg, self.store, self.notifier)
        self.assertEqual(pool.keys, {})

    def test_per_provider_budget_override(self):
        self.write_env(["HIVE_KEY_BUDGET=100", "OPENAI_API_KEY=sk-x", "OPENAI_KEY_BUDGET=45000"])
        pool = KeyPool(self.cfg, self.store, self.notifier)
        self.assertEqual(pool.keys["openai#1"].budget_credits, 45000)

    def test_aliases(self):
        self.write_env(["GOOGLE_API_KEY=goog", "CLAUDE_API_KEY=sk-ant"])
        pool = KeyPool(self.cfg, self.store, self.notifier)
        self.assertEqual(sorted(pool.live_providers()), ["anthropic", "gemini"])


class RotationTest(TempProject):
    env_lines = ["ANTHROPIC_API_KEY=sk-one", "ANTHROPIC_API_KEY_2=sk-two", "HIVE_KEY_BUDGET=1000"]

    def test_picks_the_key_with_most_headroom(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        first = pool.acquire("anthropic")
        pool.record_usage(first, usage_cost_usd=0.5, input_tokens=100, output_tokens=100)  # 500 credits
        second = pool.acquire("anthropic")
        self.assertNotEqual(first.id, second.id)

    def test_budget_exhaustion_retires_the_key_and_raises_an_alert(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        key = pool.acquire("anthropic")
        pool.record_usage(key, usage_cost_usd=1.0, input_tokens=10, output_tokens=10)  # 1000 credits
        self.assertEqual(key.status, "exhausted")
        kinds = [e["kind"] for e in self.store.events()]
        self.assertIn("key_exhausted", kinds)
        # the alert also lands in a file the operator cannot miss
        self.assertTrue((self.tmp / "NEEDS_ATTENTION.md").exists())
        # and the pool keeps serving the other key
        self.assertEqual(pool.acquire("anthropic").id, "anthropic#2")

    def test_warning_at_eighty_percent(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        key = pool.acquire("anthropic")
        pool.record_usage(key, usage_cost_usd=0.85, input_tokens=10, output_tokens=10)
        self.assertEqual(key.status, "live")
        self.assertIn("key_warning", [e["kind"] for e in self.store.events()])

    def test_no_live_keys_raises(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        for key in list(pool.keys.values()):
            pool.retire(key, "budget", "test")
        with self.assertRaises(NoKeysAvailable):
            pool.acquire("anthropic")

    def test_spend_survives_a_restart(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        key = pool.acquire("anthropic")
        pool.record_usage(key, usage_cost_usd=0.2, input_tokens=10, output_tokens=10)
        reloaded = KeyPool(self.cfg, self.store, self.notifier)
        self.assertAlmostEqual(reloaded.keys[key.id].spent_credits, 200.0, places=3)

    def test_replacing_the_secret_resets_the_budget(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        key = pool.acquire("anthropic")
        pool.record_usage(key, usage_cost_usd=1.0, input_tokens=10, output_tokens=10)
        self.assertEqual(key.status, "exhausted")
        self.write_env(["ANTHROPIC_API_KEY=sk-fresh", "ANTHROPIC_API_KEY_2=sk-two", "HIVE_KEY_BUDGET=1000"])
        pool.load()
        self.assertEqual(pool.keys["anthropic#1"].status, "live")
        self.assertEqual(pool.keys["anthropic#1"].spent_credits, 0.0)


class WaitForKeyTest(TempProject):
    env_lines = ["ANTHROPIC_API_KEY=sk-one", "HIVE_KEY_BUDGET=10", "HIVE_KEY_WAIT_SECONDS=2"]

    def test_run_resumes_when_a_new_key_is_dropped_into_env(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        key = pool.acquire("anthropic")
        pool.record_usage(key, usage_cost_usd=1.0, input_tokens=10, output_tokens=10)
        self.assertEqual(key.status, "exhausted")

        def refill():
            time.sleep(0.05)
            self.write_env(["ANTHROPIC_API_KEY=sk-one", "ANTHROPIC_API_KEY_2=sk-rescue", "HIVE_KEY_BUDGET=10"])

        threading.Thread(target=refill, daemon=True).start()
        fresh = pool.wait_for_key("anthropic", sleep=0.02, timeout=10)
        self.assertEqual(fresh.id, "anthropic#2")
        self.assertIn("blocked", [e["kind"] for e in self.store.events()])

    def test_wait_times_out_when_nobody_refills(self):
        pool = KeyPool(self.cfg, self.store, self.notifier)
        for key in list(pool.keys.values()):
            pool.retire(key, "budget", "test")
        with self.assertRaises(NoKeysAvailable):
            pool.wait_for_key("anthropic", sleep=0.01, timeout=1)


class CreditUnitTest(unittest.TestCase):
    def test_units(self):
        self.assertAlmostEqual(pricing.to_credits("usd_milli", cost=0.05, input_tokens=1, output_tokens=1), 50.0)
        self.assertAlmostEqual(pricing.to_credits("usd", cost=0.05, input_tokens=1, output_tokens=1), 0.05)
        self.assertAlmostEqual(pricing.to_credits("tokens", cost=9.0, input_tokens=10, output_tokens=5), 15.0)
        self.assertAlmostEqual(pricing.to_credits("ktokens", cost=9.0, input_tokens=1500, output_tokens=500), 2.0)
        self.assertAlmostEqual(pricing.to_credits("requests", cost=9.0, input_tokens=1, output_tokens=1), 1.0)


if __name__ == "__main__":
    unittest.main()
