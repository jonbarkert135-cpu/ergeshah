"""The cycle. Plan → build in parallel → gate → review → merge → push → verify → repeat.

    ┌──────────────────────────────────────────────────────────────────────┐
    │  read GOAL.md + repo map                                             │
    │  architect plans ≤N tasks with disjoint file ownership                │
    │  workers build them in parallel, each in its own worktree             │
    │      → gates must pass inside the worktree                           │
    │      → two reviewers from other model families must not object        │
    │      → one rework cycle is allowed before a task is abandoned         │
    │  orchestrator merges serially into the integration branch             │
    │      → gates run again on the integrated tree; a failure is reverted  │
    │      → push (optional)                                               │
    │  architect verifies the goal; unmet → next iteration with the gaps    │
    └──────────────────────────────────────────────────────────────────────┘

Everything is checkpointed in SQLite, so Ctrl-C, a dead key or a reboot costs you at most the
task that was in flight: ``python -m hive run`` resumes from the same task graph.
"""

from __future__ import annotations

import concurrent.futures as futures
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import git_ops, repomap
from .config import Config
from .engine import BudgetExceeded, Engine, NoModelAvailable
from .gates import GateReport, load_gates, run_gates
from .keys import KeyPool
from .notify import Notifier
from .planner import Planner, VerifyResult, summarize_state
from .reviewer import ReviewBoard, blocking_feedback, review_summary
from .store import Store
from .util import LOG, human_usd, trim, utc_stamp
from .worker import TaskOutcome, Worker

GOAL_TEMPLATE = """# Final goal

Describe, in prose, the finished state you want. Be concrete about what must exist and how you
will know it works — the architect turns this into tasks and later checks the result against it.

## Acceptance criteria

- [ ] ...
- [ ] ...

## Constraints

- ...
"""


@dataclass
class RunSummary:
    iterations: int = 0
    merged: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    goal_done: bool = False
    verdict: str = ""
    gaps: list[str] = field(default_factory=list)
    spend_usd: float = 0.0
    stopped_reason: str = ""

    def as_text(self) -> str:
        lines = [
            f"iterations: {self.iterations}",
            f"merged tasks: {len(self.merged)}" + (f" ({', '.join(self.merged)})" if self.merged else ""),
            f"failed tasks: {len(self.failed)}" + (f" ({', '.join(self.failed)})" if self.failed else ""),
            f"goal reached: {'yes' if self.goal_done else 'no'}",
            f"spend: {human_usd(self.spend_usd)}",
        ]
        if self.verdict:
            lines.append(f"architect verdict: {self.verdict}")
        if self.gaps:
            lines.append("remaining gaps:\n" + "\n".join(f"  - {g}" for g in self.gaps))
        if self.stopped_reason:
            lines.append(f"stopped because: {self.stopped_reason}")
        return "\n".join(lines)


class Orchestrator:
    def __init__(self, cfg: Config, store: Store, pool: KeyPool, notifier: Notifier, engine: Engine):
        self.cfg = cfg
        self.store = store
        self.pool = pool
        self.notifier = notifier
        self.engine = engine
        self.planner = Planner(cfg, engine, store)
        self.gates = load_gates(cfg.project_dir)
        self.goal_text = self._read_goal()
        self.gate_summary = ""

    # ------------------------------------------------------------------ setup
    def _read_goal(self) -> str:
        path = Path(self.cfg.goal_file)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(GOAL_TEMPLATE, encoding="utf-8")
            LOG.warning("created %s — fill in the final goal before running", path)
        text = path.read_text(encoding="utf-8").strip()
        return text or GOAL_TEMPLATE

    def prepare(self) -> None:
        self.cfg.ensure_dirs()
        repo = Path(self.cfg.project_dir)
        if self.cfg.git_enabled:
            git_ops.ensure_repo(repo, self.cfg.git_branch)
            self._ensure_gitignore(repo)
            branch = git_ops.current_branch(repo)
            if branch != self.cfg.git_branch and git_ops.has_commits(repo):
                result = git_ops.git(["checkout", self.cfg.git_branch], repo)
                if not result.ok:
                    git_ops.git(["checkout", "-b", self.cfg.git_branch], repo)
            if git_ops.is_dirty(repo):
                sha = git_ops.commit_all(repo, f"{self.cfg.commit_prefix}: snapshot before run")
                if sha:
                    LOG.info("committed pre-existing changes as %s", sha[:8])
            if not git_ops.has_commits(repo):
                git_ops.commit_all(repo, f"{self.cfg.commit_prefix}: initial commit")
        self.store.set_meta("goal_hash", hash(self.goal_text))
        self.store.set_meta("started_at", utc_stamp())

    @staticmethod
    def _ensure_gitignore(repo: Path) -> None:
        """Hive's own state, worktrees and secrets must never end up in a commit."""
        path = repo / ".gitignore"
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        needed = [".hive/", ".worktrees/", "NEEDS_ATTENTION.md", ".env", "__pycache__/", "*.pyc"]
        missing = [line for line in needed if line not in existing.splitlines()]
        if not missing:
            return
        with path.open("a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write("\n".join(missing) + "\n")

    def baseline_gates(self) -> GateReport:
        report = run_gates(self.cfg.project_dir, self.gates, changed=[], only_required=True)
        self.gate_summary = report.summary()
        if not report.ok:
            LOG.warning("baseline gates are already failing:\n%s", report.summary())
        return report

    # ------------------------------------------------------------------ the cycle
    def run(self, max_iterations: int | None = None) -> RunSummary:
        summary = RunSummary()
        self.prepare()
        self.baseline_gates()
        limit = max_iterations or self.cfg.max_iterations
        gaps: list[str] = []
        start_iteration = int(self.store.get_meta("iteration", 0) or 0)

        try:
            for step in range(1, limit + 1):
                iteration = start_iteration + step
                self.store.set_meta("iteration", iteration)
                summary.iterations = step
                LOG.info("=" * 72)
                LOG.info("ITERATION %d", iteration)
                LOG.info("=" * 72)

                repo_map = repomap.build(self.cfg.project_dir, self.cfg.repomap_char_limit)
                open_tasks = self._open_tasks()

                # Nothing queued: ask whether the goal is already met before paying for a plan.
                if not open_tasks:
                    if self.store.tasks():
                        verify = self._verify(repo_map, gaps, iteration)
                        summary.verdict, summary.gaps, gaps = verify.summary, verify.gaps, verify.gaps
                        if verify.done:
                            summary.goal_done = True
                            self.notifier.event("goal_reached", "final goal reached", verify.summary)
                            break
                    state = summarize_state(self.store, self.gate_summary, gaps)
                    plan = self.planner.plan(self.goal_text, repo_map, state, iteration)
                    if plan.errors and not plan.tasks:
                        self.notifier.event("blocked", "the architect produced no usable plan", "; ".join(plan.errors))
                    for task in plan.tasks:
                        self.store.upsert_task(task)
                    open_tasks = self._open_tasks()
                    LOG.info("planned %d task(s): %s", len(open_tasks), ", ".join(t["id"] for t in open_tasks))

                if not open_tasks:
                    summary.stopped_reason = "the architect planned no further tasks"
                    break

                merged, failed = self._execute(open_tasks, repo_map)
                summary.merged += merged
                summary.failed += failed

                if step == limit:  # last lap: report where the project actually stands
                    verify = self._verify(repo_map, gaps, iteration)
                    summary.verdict, summary.gaps, gaps = verify.summary, verify.gaps, verify.gaps
                    summary.goal_done = verify.done
                    if verify.done:
                        self.notifier.event("goal_reached", "final goal reached", verify.summary)
                if not merged and failed:
                    LOG.warning("iteration %d merged nothing — %d task(s) failed", iteration, len(failed))
        except KeyboardInterrupt:
            summary.stopped_reason = "interrupted by the operator (state saved, rerun to resume)"
            self._release_building_tasks()
        except BudgetExceeded as exc:
            summary.stopped_reason = str(exc)
        except NoModelAvailable as exc:
            summary.stopped_reason = str(exc)
            self.notifier.event("run_failed", "no usable model/key", str(exc))
        finally:
            summary.spend_usd = self.engine.spend_usd
            self._write_report(summary)
        return summary

    # ------------------------------------------------------------------ execution
    def _open_tasks(self) -> list[dict]:
        return [t for t in self.store.tasks() if t["status"] in {"pending", "building", "changes_requested"}]

    def _execute(self, tasks: list[dict], repo_map: str) -> tuple[list[str], list[str]]:
        merged: list[str] = []
        failed: list[str] = []
        worker = Worker(
            self.cfg,
            self.engine,
            self.store,
            self.notifier,
            goal_text=self.goal_text,
            repo_map=repo_map,
            gates=self.gates,
        )
        board = ReviewBoard(self.cfg, self.engine, self.store, goal_text=self.goal_text, repo_map=repo_map)
        remaining = {t["id"]: t for t in tasks}

        while remaining:
            ready = [t for t in remaining.values() if self._deps_ready(t)]
            if not ready:
                for task in remaining.values():
                    reason = "blocked: a dependency failed"
                    self.store.update_task(task["id"], status="abandoned", last_error=reason)
                    failed.append(task["id"])
                    LOG.warning("task %s abandoned — %s", task["id"], reason)
                break

            wave = ready[: self.cfg.max_parallel]
            LOG.info("building wave of %d: %s", len(wave), ", ".join(t["id"] for t in wave))
            outcomes: dict[str, TaskOutcome] = {}
            if len(wave) == 1:
                outcomes[wave[0]["id"]] = worker.run(wave[0])
            else:
                with futures.ThreadPoolExecutor(max_workers=len(wave)) as pool:
                    future_map = {pool.submit(worker.run, task): task for task in wave}
                    for future in futures.as_completed(future_map):
                        task = future_map[future]
                        try:
                            outcomes[task["id"]] = future.result()
                        except Exception as exc:  # a crashed worker must not kill the wave
                            LOG.exception("worker for %s crashed", task["id"])
                            outcomes[task["id"]] = TaskOutcome(task["id"], "failed", error=f"worker crashed: {exc}")

            # merges are serial: one integration branch, one gate run at a time
            for task in wave:
                remaining.pop(task["id"], None)
                outcome = outcomes[task["id"]]
                if self._finalize(task, outcome, worker, board):
                    merged.append(task["id"])
                else:
                    failed.append(task["id"])
        return merged, failed

    def _deps_ready(self, task: dict) -> bool:
        for dep in task.get("depends_on", []):
            row = self.store.task(dep)
            if row is None:
                continue
            if row["status"] != "merged":
                return False
        return True

    def _finalize(self, task: dict, outcome: TaskOutcome, worker: Worker, board: ReviewBoard) -> bool:
        if not outcome.ok:
            self.store.update_task(task["id"], status="failed", last_error=outcome.error, branch=outcome.branch)
            LOG.warning("task %s failed: %s", task["id"], trim(outcome.error, 300))
            worker.cleanup(outcome)
            return False

        gate_summary = outcome.gate_report.summary() if outcome.gate_report else ""
        verdicts = board.review(task, outcome.diff, gate_summary, outcome.notes, outcome.provider)
        feedback = blocking_feedback(verdicts, self.cfg.blocking_severities)
        if feedback:
            LOG.info("task %s: review requested changes\n%s", task["id"], review_summary(verdicts))
            self.store.update_task(task["id"], status="changes_requested", last_error=trim(feedback, 900))
            outcome = worker.run(task, reuse=outcome, feedback=feedback)
            if not outcome.ok:
                self.store.update_task(task["id"], status="failed", last_error=trim(outcome.error, 900))
                worker.cleanup(outcome)
                return False
            verdicts = board.review(
                task,
                outcome.diff,
                outcome.gate_report.summary() if outcome.gate_report else "",
                outcome.notes,
                outcome.provider,
            )
            feedback = blocking_feedback(verdicts, self.cfg.blocking_severities)
            if feedback:
                self.store.update_task(
                    task["id"], status="failed", last_error="review still blocking: " + trim(feedback, 800)
                )
                LOG.warning("task %s abandoned after rework — reviewers still blocking", task["id"])
                worker.cleanup(outcome)
                return False

        ok, detail = self._merge(task, outcome)
        if not ok:
            self.store.update_task(task["id"], status="failed", last_error=trim(detail, 900))
            worker.cleanup(outcome)
            return False

        self.store.update_task(
            task["id"],
            status="merged",
            commit_sha=detail,
            branch=outcome.branch,
            last_error="",
        )
        LOG.info("task %s merged as %s", task["id"], detail[:8])
        worker.cleanup(outcome)
        return True

    def _merge(self, task: dict, outcome: TaskOutcome) -> tuple[bool, str]:
        repo = Path(self.cfg.project_dir)
        if not self.cfg.git_enabled:
            return True, "no-git"
        before = git_ops.head_sha(repo)
        message = f"{self.cfg.commit_prefix}: {task['title']} ({task['id']})"
        ok, detail = git_ops.merge_branch(repo, outcome.branch, message)
        if not ok:
            return False, f"could not merge {outcome.branch}: {detail}"

        report = run_gates(repo, self.gates, changed=outcome.changed_files, only_required=True)
        self.gate_summary = report.summary()
        if not report.ok:
            git_ops.git(["reset", "--hard", before], repo)
            return False, (
                "gates failed on the integrated branch, merge reverted:\n" + trim(report.failure_text(), 2500)
            )

        sha = git_ops.head_sha(repo)
        if self.cfg.git_push:
            pushed, push_detail = git_ops.push(repo, self.cfg.git_remote, self.cfg.git_branch)
            if pushed:
                LOG.info("pushed %s to %s/%s", sha[:8], self.cfg.git_remote, self.cfg.git_branch)
            else:
                self.notifier.event(
                    "push_failed",
                    f"could not push to {self.cfg.git_remote}/{self.cfg.git_branch}",
                    trim(push_detail, 800),
                )
        return True, sha

    # ------------------------------------------------------------------ verify + report
    def _verify(self, repo_map: str, gaps: list[str], iteration: int) -> VerifyResult:
        fresh_map = repomap.build(self.cfg.project_dir, self.cfg.repomap_char_limit)
        state = summarize_state(self.store, self.gate_summary, gaps)
        verify = self.planner.verify(self.goal_text, fresh_map, state, iteration)
        LOG.info("architect verdict: done=%s — %s", verify.done, verify.summary)
        for gap in verify.gaps[:8]:
            LOG.info("  gap: %s", gap)
        self.store.set_meta("last_verify", {"done": verify.done, "summary": verify.summary, "gaps": verify.gaps})
        return verify

    def _release_building_tasks(self) -> None:
        for task in self.store.tasks("building"):
            self.store.update_task(task["id"], status="pending")

    def _write_report(self, summary: RunSummary) -> None:
        totals = self.store.totals()
        keys = self.pool.summary()
        lines = [
            "# Hive run report",
            "",
            f"- generated: {utc_stamp()}",
            f"- project: `{self.cfg.project_dir}`",
            f"- branch: `{self.cfg.git_branch}`",
            "",
            "## Outcome",
            "",
            "```",
            summary.as_text(),
            "```",
            "",
            "## Spend",
            "",
            f"- calls: {totals['calls']}",
            f"- tokens: {totals['tokens']} (cached: {totals['cached_tokens']})",
            f"- cost: {human_usd(totals['cost_usd'])}",
            "",
            "| key | provider | status | spent/budget credits | usd | calls |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for key in keys:
            budget = f"{key['spent']:.0f}/{key['budget']:.0f}" if key["budget"] else f"{key['spent']:.0f}/∞"
            lines.append(
                f"| {key['id']} | {key['provider']} | {key['status']} | {budget} | ${key['usd']:.4f} | {key['calls']} |"
            )
        lines += ["", "## Tasks", "", "| task | status | role | files | cost |", "| --- | --- | --- | --- | --- |"]
        for task in self.store.tasks():
            lines.append(
                f"| {task['id']} | {task['status']} | {task['role']} | "
                f"{', '.join(task['files'][:4])} | ${task['cost_usd']:.4f} |"
            )
        lines += ["", "## Latest gate results", "", "```", self.gate_summary or "(none)", "```", ""]
        try:
            self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
            (self.cfg.state_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (self.cfg.state_dir / "report.json").write_text(
                json.dumps(
                    {
                        "summary": summary.__dict__,
                        "totals": totals,
                        "keys": keys,
                        "tasks": self.store.tasks(),
                    },
                    indent=2,
                    default=str,
                )
                + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            LOG.debug("could not write report: %s", exc)
