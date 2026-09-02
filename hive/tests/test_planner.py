"""Plan validation: the invariants that make parallel agents safe."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from hive.planner import Planner, summarize_state
from hive.tests.helpers import ScriptedProvider, TempProject
from hive.util import extract_json


class NormalizeTest(TempProject):
    env_lines = ["ANTHROPIC_API_KEY=sk-one", "HIVE_KEY_BUDGET=100000"]

    def planner_with(self, replies: list[object]) -> Planner:
        pool = self.make_pool()
        engine = self.make_engine(pool)
        engine.router.available = ["anthropic"]
        provider = ScriptedProvider("anthropic", replies)
        patcher = mock.patch("hive.engine.build_provider", return_value=provider)
        patcher.start()
        self.addCleanup(patcher.stop)
        return Planner(self.cfg, engine, self.store)

    @staticmethod
    def plan_json(tasks: list[dict]) -> str:
        return json.dumps({"tasks": tasks})

    def test_overlapping_files_become_a_dependency(self):
        planner = self.planner_with(
            [
                self.plan_json(
                    [
                        {"id": "a", "title": "A", "spec": "do a", "files": ["src/app.py"]},
                        {"id": "b", "title": "B", "spec": "do b", "files": ["src/app.py", "src/b.py"]},
                    ]
                )
            ]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual([t["id"] for t in result.tasks], ["a", "b"])
        self.assertEqual(result.tasks[1]["depends_on"], ["a"])
        self.assertTrue(any("shares src/app.py" in e for e in result.errors))

    def test_duplicate_ids_are_made_unique(self):
        planner = self.planner_with(
            [
                self.plan_json(
                    [
                        {"id": "same", "title": "A", "spec": "a", "files": ["a.py"]},
                        {"id": "same", "title": "B", "spec": "b", "files": ["b.py"]},
                    ]
                )
            ]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual([t["id"] for t in result.tasks], ["same", "same-2"])

    def test_tasks_without_files_or_spec_are_dropped(self):
        planner = self.planner_with(
            [
                self.plan_json(
                    [
                        {"id": "ok", "title": "Fine", "spec": "yes", "files": ["a.py"]},
                        {"id": "nofiles", "title": "Bad", "spec": "yes", "files": []},
                        {"id": "nospec", "title": "Bad", "files": ["b.py"]},
                    ]
                )
            ]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual([t["id"] for t in result.tasks], ["ok"])
        self.assertEqual(len(result.errors), 2)

    def test_protected_paths_are_stripped(self):
        planner = self.planner_with(
            [self.plan_json([{"id": "x", "title": "X", "spec": "s", "files": [".env", "src/x.py"]}])]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual(result.tasks[0]["files"], ["src/x.py"])

    def test_unknown_dependencies_and_cycles_are_removed(self):
        planner = self.planner_with(
            [
                self.plan_json(
                    [
                        {"id": "a", "title": "A", "spec": "a", "files": ["a.py"], "depends_on": ["b", "ghost"]},
                        {"id": "b", "title": "B", "spec": "b", "files": ["b.py"], "depends_on": ["a"]},
                    ]
                )
            ]
        )
        result = planner.plan("goal", "map", "state", 1)
        by_id = {t["id"]: t for t in result.tasks}
        self.assertNotIn("ghost", by_id["a"]["depends_on"])
        self.assertFalse(set(by_id["a"]["depends_on"]) & {"b"} and set(by_id["b"]["depends_on"]) & {"a"})

    def test_unknown_role_falls_back_to_backend(self):
        planner = self.planner_with(
            [self.plan_json([{"id": "x", "title": "X", "spec": "s", "files": ["x.py"], "role": "wizard"}])]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual(result.tasks[0]["role"], "backend")

    def test_task_cap_is_respected(self):
        self.cfg.max_tasks_per_iteration = 2
        planner = self.planner_with(
            [
                self.plan_json(
                    [{"id": f"t{i}", "title": f"T{i}", "spec": "s", "files": [f"f{i}.py"]} for i in range(6)]
                )
            ]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual(len(result.tasks), 2)

    def test_invalid_json_is_retried_with_feedback(self):
        planner = self.planner_with(
            ["I think we should start with the database.", self.plan_json([{"id": "a", "title": "A", "spec": "s", "files": ["a.py"]}])]
        )
        result = planner.plan("goal", "map", "state", 1)
        self.assertEqual([t["id"] for t in result.tasks], ["a"])

    def test_verify_parses_gaps(self):
        planner = self.planner_with(
            [json.dumps({"done": False, "summary": "half done", "gaps": ["auth missing"], "risks": ["no rate limit"]})]
        )
        verify = planner.verify("goal", "map", "state", 1)
        self.assertFalse(verify.done)
        self.assertEqual(verify.gaps, ["auth missing"])
        self.assertEqual(verify.risks, ["no rate limit"])

    def test_verify_unparseable_is_not_treated_as_done(self):
        planner = self.planner_with(["definitely finished!"])
        verify = planner.verify("goal", "map", "state", 1)
        self.assertFalse(verify.done)


class StateSummaryTest(TempProject):
    def test_summary_lists_done_failed_and_open(self):
        self.store.upsert_task({"id": "a", "title": "A", "files": ["a.py"], "status": "merged"})
        self.store.upsert_task({"id": "b", "title": "B", "files": ["b.py"], "status": "failed", "last_error": "gates"})
        self.store.upsert_task({"id": "c", "title": "C", "files": ["c.py"], "status": "pending"})
        text = summarize_state(self.store, "gates: PASS", ["needs docs"])
        self.assertIn("COMPLETED TASKS (1)", text)
        self.assertIn("FAILED TASKS (1)", text)
        self.assertIn("STILL OPEN (1)", text)
        self.assertIn("needs docs", text)
        self.assertIn("gates: PASS", text)


class ExtractJsonTest(unittest.TestCase):
    def test_json_in_prose_and_fences(self):
        self.assertEqual(extract_json('{"a": 1}'), {"a": 1})
        self.assertEqual(extract_json('Sure:\n```json\n{"a": 2}\n```\nhope that helps'), {"a": 2})
        self.assertEqual(extract_json('prefix {"a": {"b": [1,2]}} suffix')["a"]["b"], [1, 2])
        with self.assertRaises(ValueError):
            extract_json("no json here")


if __name__ == "__main__":
    unittest.main()
