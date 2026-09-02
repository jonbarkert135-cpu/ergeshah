"""End-to-end: the whole loop against the built-in mock provider, in a real git repo.

This is the test that proves the machinery works: planning, parallel builds in worktrees,
gates, review, serial merges, goal verification, resumability — and that a dead key pauses the
run instead of losing work.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from hive import git_ops
from hive.engine import Engine
from hive.gates import GATES_FILE
from hive.keys import KeyPool
from hive.orchestrator import Orchestrator
from hive.providers import mock as mock_provider
from hive.tests.helpers import HAS_GIT, TempProject

DEMO_GATES = {
    "gates": [
        {"name": "compile", "cmd": "python -m compileall -q .", "required": True, "timeout": 120},
        {
            "name": "tests",
            "cmd": (
                "python -c \"import os,subprocess,sys;"
                "sys.exit(subprocess.call([sys.executable,'-m','unittest','discover','-s','tests','-t','tests'])"
                " if os.path.isdir('tests') else 0)\""
            ),
            "required": True,
            "timeout": 300,
        },
    ]
}


@unittest.skipUnless(HAS_GIT, "git is required for the end-to-end test")
class EndToEndTest(TempProject):
    env_lines = ["HIVE_ENABLE_MOCK=1", "HIVE_MAX_PARALLEL=2", "HIVE_MAX_ATTEMPTS=2"]

    def setUp(self):
        super().setUp()
        mock_provider.reset()
        self.init_git()
        (self.tmp / "GOAL.md").write_text("Build a tiny calculator package with tests.\n", encoding="utf-8")
        (self.tmp / GATES_FILE).write_text(json.dumps(DEMO_GATES, indent=2), encoding="utf-8")
        self.pool = KeyPool(self.cfg, self.store, self.notifier)
        self.engine = Engine(self.cfg, self.store, self.pool, self.notifier)

    def orchestrator(self) -> Orchestrator:
        return Orchestrator(self.cfg, self.store, self.pool, self.notifier, self.engine)

    def test_full_cycle_builds_reviews_merges_and_verifies(self):
        summary = self.orchestrator().run(max_iterations=1)

        self.assertEqual(sorted(summary.merged), ["core-calc", "core-tests", "docs"])
        self.assertEqual(summary.failed, [])
        self.assertTrue(summary.goal_done)

        # the code really exists on the integration branch
        self.assertTrue((self.tmp / "calc/core.py").exists())
        self.assertTrue((self.tmp / "tests/test_core.py").exists())
        tracked = self.git("ls-files").stdout.split()
        self.assertIn("calc/core.py", tracked)
        self.assertIn("USAGE.md", tracked)

        # the tests the agents wrote actually pass
        proc = self.git("log", "--oneline")
        self.assertIn("core-calc", proc.stdout)
        run = __import__("subprocess").run(
            ["python", "-m", "unittest", "discover", "-s", "tests", "-t", "tests"],
            cwd=str(self.tmp),
            capture_output=True,
            text=True,
            env={**__import__("os").environ, "PYTHONPATH": str(self.tmp)},
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)

        # bookkeeping: every task has attempts recorded, reviews ran, nothing is left open
        for task_id in summary.merged:
            task = self.store.task(task_id)
            self.assertEqual(task["status"], "merged")
            self.assertTrue(task["commit_sha"])
            self.assertTrue(self.store.attempts(task_id))
        review_calls = [c for c in mock_provider.calls() if "HIVE_PHASE: review" in c["prompt"]]
        self.assertGreaterEqual(len(review_calls), 2 * len(summary.merged))

        # worktrees are cleaned up
        self.assertFalse(list((self.tmp / ".worktrees").glob("*")) if (self.tmp / ".worktrees").exists() else [])

        # report artifacts exist
        self.assertTrue((self.cfg.state_dir / "REPORT.md").exists())
        report = json.loads((self.cfg.state_dir / "report.json").read_text())
        self.assertEqual(len(report["tasks"]), 3)

    def test_cached_prefix_is_identical_across_agents(self):
        """The savings claim: within one iteration every agent sends the same cacheable prefix.

        The final verification call is the one deliberate exception — it re-reads the repo after
        the merges, so its repo-map block differs.
        """
        self.orchestrator().run(max_iterations=1)
        prefixes = {
            c["prompt"].split("YOUR ROLE")[0]
            for c in mock_provider.calls()
            if "HIVE_PHASE: verify" not in c["prompt"]
        }
        self.assertEqual(len(prefixes), 1, "core rules + goal + repo map must be byte-identical for all agents")
        self.assertGreaterEqual(len(mock_provider.calls()), 8)

    def test_secrets_never_reach_a_commit(self):
        self.orchestrator().run(max_iterations=1)
        tracked = self.git("ls-files").stdout.split()
        self.assertNotIn(".env", tracked)
        self.assertNotIn(".hive", tracked)

    def test_ownership_violation_is_rejected_and_task_fails_cleanly(self):
        """An agent that writes outside its contract gets nothing merged."""

        def handler(prompt: str) -> str:
            if "HIVE_PHASE: plan" in prompt:
                return json.dumps(
                    {
                        "tasks": [
                            {
                                "id": "greedy",
                                "title": "Greedy task",
                                "role": "backend",
                                "spec": "only touch allowed.py",
                                "files": ["allowed.py"],
                                "acceptance": ["file exists"],
                            }
                        ]
                    }
                )
            if "HIVE_PHASE: verify" in prompt:
                return json.dumps({"done": False, "summary": "nope", "gaps": ["everything"]})
            if "HIVE_PHASE: review" in prompt:
                return json.dumps({"verdict": "approve", "findings": []})
            return "### FILE not_allowed.py\n```python\nx = 1\n```\n"

        from hive.providers import build_provider

        provider = build_provider("mock", self.cfg)
        provider.handler = handler
        self.addCleanup(setattr, provider, "handler", None)

        summary = self.orchestrator().run(max_iterations=1)
        self.assertEqual(summary.merged, [])
        self.assertEqual(summary.failed, ["greedy"])
        self.assertFalse((self.tmp / "not_allowed.py").exists())
        self.assertIn("file ownership", self.store.task("greedy")["last_error"])

    def test_blocking_review_forces_rework_then_merges(self):
        state = {"reviews": 0, "builds": 0}

        def handler(prompt: str) -> str:
            if "HIVE_PHASE: plan" in prompt:
                return json.dumps(
                    {
                        "tasks": [
                            {
                                "id": "hardening",
                                "title": "Add input validation",
                                "role": "backend",
                                "spec": "create app.py",
                                "files": ["app.py"],
                                "acceptance": ["validates input"],
                            }
                        ]
                    }
                )
            if "HIVE_PHASE: verify" in prompt:
                return json.dumps({"done": True, "summary": "done", "gaps": []})
            if "HIVE_PHASE: review" in prompt:
                state["reviews"] += 1
                if state["reviews"] <= 1:  # first reviewer of the first round blocks
                    return json.dumps(
                        {
                            "verdict": "request_changes",
                            "summary": "missing validation",
                            "findings": [
                                {"severity": "high", "file": "app.py", "issue": "no validation", "fix": "validate"}
                            ],
                        }
                    )
                return json.dumps({"verdict": "approve", "findings": []})
            state["builds"] += 1
            if state["builds"] == 1:
                return "### FILE app.py\n```python\ndef run(x):\n    return x\n```\n"
            return (
                "### EDIT app.py\n<<<<<<< SEARCH\ndef run(x):\n    return x\n=======\n"
                "def run(x):\n    if not isinstance(x, int):\n        raise TypeError('int required')\n"
                "    return x\n>>>>>>> REPLACE\n"
            )

        from hive.providers import build_provider

        provider = build_provider("mock", self.cfg)
        provider.handler = handler
        self.addCleanup(setattr, provider, "handler", None)

        summary = self.orchestrator().run(max_iterations=1)
        self.assertEqual(summary.merged, ["hardening"])
        self.assertIn("TypeError", (self.tmp / "app.py").read_text())
        self.assertGreaterEqual(state["builds"], 2, "review feedback must trigger a rework build")

    def test_run_resumes_open_tasks_without_replanning(self):
        self.store.upsert_task(
            {
                "id": "docs",
                "iteration": 1,
                "title": "Document usage",
                "role": "docs",
                "spec": "Create USAGE.md",
                "files": ["USAGE.md"],
                "acceptance": ["exists"],
                "status": "pending",
            }
        )
        summary = self.orchestrator().run(max_iterations=1)
        self.assertEqual(summary.merged, ["docs"])
        plan_calls = [c for c in mock_provider.calls() if "HIVE_PHASE: plan" in c["prompt"]]
        self.assertEqual(plan_calls, [], "a resumed run must not re-plan while tasks are open")

    def test_dead_key_pauses_and_resumes_when_refilled(self):
        """The operator-facing promise: run out of credits, add a key, work continues."""
        self.cfg.key_wait_seconds = 1
        key = self.pool.acquire("mock")
        self.pool.retire(key, "budget", "simulated exhaustion")
        self.assertFalse(self.pool.live_keys())
        self.assertTrue((self.tmp / "NEEDS_ATTENTION.md").exists())

        import threading

        def refill():
            import time

            time.sleep(0.2)
            self.write_env(["HIVE_ENABLE_MOCK=1", "MOCK_API_KEY=rescue-key"])

        threading.Thread(target=refill, daemon=True).start()
        fresh = self.pool.wait_for_key("mock", sleep=0.05, timeout=15)
        self.assertEqual(fresh.status, "live")
        summary = self.orchestrator().run(max_iterations=1)
        self.assertTrue(summary.merged)

    def test_git_history_is_linear_and_attributed(self):
        self.orchestrator().run(max_iterations=1)
        log = self.git("log", "--pretty=%an|%s").stdout.strip().splitlines()
        self.assertTrue(any("Hive Agent" in line for line in log))
        self.assertTrue(all("|" in line for line in log))
        self.assertEqual(git_ops.current_branch(Path(self.tmp)), "main")


if __name__ == "__main__":
    unittest.main()
