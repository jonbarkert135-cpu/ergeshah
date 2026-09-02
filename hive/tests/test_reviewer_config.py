"""Review verdict handling, config loading and roster routing."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from hive.config import Config, parse_env_file
from hive.reviewer import Finding, ReviewBoard, Verdict, blocking_feedback, review_summary
from hive.roster import ROLES, Router
from hive.tests.helpers import ScriptedProvider, TempProject


class VerdictTest(unittest.TestCase):
    def parse(self, text: str) -> Verdict:
        return ReviewBoard._parse("reviewer_code", "openai", "gpt-5", text)

    def test_approve(self):
        verdict = self.parse(json.dumps({"verdict": "approve", "summary": "fine", "findings": []}))
        self.assertTrue(verdict.approved)
        self.assertEqual(verdict.blocking(("critical", "high")), [])

    def test_request_changes_with_high_finding_blocks(self):
        verdict = self.parse(
            json.dumps(
                {
                    "verdict": "request_changes",
                    "summary": "authz missing",
                    "findings": [{"severity": "high", "file": "api.py", "issue": "no ownership check", "fix": "check user id"}],
                }
            )
        )
        self.assertFalse(verdict.approved)
        feedback = blocking_feedback([verdict], ("critical", "high"))
        self.assertIn("no ownership check", feedback)
        self.assertIn("api.py", feedback)

    def test_low_severity_nitpicks_do_not_block(self):
        verdict = self.parse(
            json.dumps(
                {
                    "verdict": "request_changes",
                    "summary": "naming",
                    "findings": [{"severity": "low", "file": "", "issue": "rename x to count"}],
                }
            )
        )
        self.assertEqual(blocking_feedback([verdict], ("critical", "high")), "")

    def test_unparseable_review_does_not_block(self):
        verdict = self.parse("Looks good to me, ship it.")
        self.assertTrue(verdict.approved)
        self.assertTrue(verdict.parse_error)
        self.assertEqual(blocking_feedback([verdict], ("critical", "high")), "")

    def test_summary_rendering(self):
        verdicts = [
            Verdict("reviewer_code", "openai", "gpt-5", True, "ok"),
            Verdict("reviewer_security", "anthropic", "opus", False, "leak", [Finding("critical", "a.py", "logs token")]),
        ]
        text = review_summary(verdicts)
        self.assertIn("reviewer_code (openai): approve", text)
        self.assertIn("request_changes", text)


class ReviewBoardTest(TempProject):
    env_lines = ["ANTHROPIC_API_KEY=sk-one", "OPENAI_API_KEY=sk-two", "HIVE_KEY_BUDGET=100000"]

    def test_two_reviewers_run_and_avoid_the_author(self):
        pool = self.make_pool()
        engine = self.make_engine(pool)
        engine.router.available = ["anthropic", "openai"]
        providers = {
            "anthropic": ScriptedProvider("anthropic", [json.dumps({"verdict": "approve", "findings": []})] * 2),
            "openai": ScriptedProvider("openai", [json.dumps({"verdict": "approve", "findings": []})] * 2),
        }
        with mock.patch("hive.engine.build_provider", side_effect=lambda n, c: providers[n]):
            board = ReviewBoard(self.cfg, engine, self.store, goal_text="goal", repo_map="map")
            verdicts = board.review(
                {"id": "t", "title": "T", "spec": "s", "files": ["a.py"], "acceptance": []},
                diff="--- a/a.py\n+++ b/a.py\n+x = 1\n",
                gate_summary="[PASS] tests",
                notes="",
                author_provider="anthropic",
            )
        self.assertEqual(len(verdicts), 2)
        self.assertTrue(all(v.provider == "openai" for v in verdicts))

    def test_review_disabled(self):
        self.cfg.review_count = 0
        board = ReviewBoard(self.cfg, self.make_engine(), self.store, goal_text="g", repo_map="m")
        self.assertEqual(board.review({"id": "t", "title": "T"}, "diff", "", "", "anthropic"), [])


class ConfigTest(TempProject):
    def test_env_parsing_quirks(self):
        self.env_path.write_text(
            "# comment\n"
            "export QUOTED=\"a b\"\n"
            "PLAIN=value  # trailing comment\n"
            "EMPTY=\n"
            "SINGLE='x=y'\n"
            "not_a_line\n",
            encoding="utf-8",
        )
        parsed = parse_env_file(self.env_path)
        self.assertEqual(parsed["QUOTED"], "a b")
        self.assertEqual(parsed["PLAIN"], "value")
        self.assertEqual(parsed["EMPTY"], "")
        self.assertEqual(parsed["SINGLE"], "x=y")
        self.assertNotIn("not_a_line", parsed)

    def test_defaults_and_overrides(self):
        self.env_path.write_text(
            "HIVE_MAX_PARALLEL=7\nHIVE_KEY_BUDGET=1234\nHIVE_GIT_PUSH=yes\nHIVE_BLOCKING_SEVERITIES=critical\n",
            encoding="utf-8",
        )
        cfg = Config.load(self.env_path)
        self.assertEqual(cfg.max_parallel, 7)
        self.assertEqual(cfg.default_key_budget, 1234)
        self.assertTrue(cfg.git_push)
        self.assertEqual(cfg.blocking_severities, ("critical",))
        self.assertEqual(cfg.credit_unit, "usd_milli")

    def test_garbage_numbers_fall_back_to_defaults(self):
        self.env_path.write_text("HIVE_MAX_PARALLEL=lots\n", encoding="utf-8")
        self.assertEqual(Config.load(self.env_path).max_parallel, 3)

    def test_role_and_model_overrides_are_collected(self):
        self.env_path.write_text(
            "HIVE_ROLE_ARCHITECT=openai:gpt-5\nHIVE_MODEL_ANTHROPIC_SMART=claude-x\n", encoding="utf-8"
        )
        cfg = Config.load(self.env_path)
        self.assertEqual(cfg.role_overrides["architect"], "openai:gpt-5")
        router = Router(cfg, ["anthropic", "openai"])
        self.assertEqual(router.model_for("anthropic", "smart"), "claude-x")
        self.assertEqual(router.candidates("architect")[0].provider, "openai")


class RouterTest(unittest.TestCase):
    def test_tiers_and_fallbacks(self):
        cfg = Config()
        cfg.raw_env = {}
        router = Router(cfg, ["anthropic", "deepseek"])
        cheap = router.candidates("docs")[0]
        expensive = router.candidates("architect")[0]
        self.assertEqual(ROLES["docs"].tier, "cheap")
        self.assertIn(cheap.provider, {"anthropic", "deepseek"})
        self.assertEqual(expensive.provider, "anthropic")
        self.assertGreater(len(router.candidates("backend")), 1)

    def test_no_providers_means_no_candidates(self):
        cfg = Config()
        cfg.raw_env = {}
        self.assertEqual(Router(cfg, []).candidates("backend"), [])

    def test_avoid_provider_pushes_it_last(self):
        cfg = Config()
        cfg.raw_env = {}
        router = Router(cfg, ["anthropic", "openai"])
        first = router.candidates("reviewer_code", avoid_provider="openai")[0]
        self.assertEqual(first.provider, "anthropic")

    def test_every_role_has_a_persona_and_tier(self):
        for name, role in ROLES.items():
            self.assertTrue(role.persona.strip(), name)
            self.assertIn(role.tier, ("ultra", "smart", "cheap"))


if __name__ == "__main__":
    unittest.main()
