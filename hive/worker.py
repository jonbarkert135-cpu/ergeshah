"""The build phase: one task, one isolated worktree, up to N attempts.

The loop per task is deliberately boring:

1. create a fresh worktree + branch off the integration branch,
2. ask the role's model for edits (owned files only),
3. apply them; protocol/ownership failures go straight back to the model as feedback,
4. commit and run the project's gates inside the worktree,
5. failures go back to the model with the actual command output — never a summary,
6. after ``HIVE_MAX_ATTEMPTS`` failed attempts the task is marked failed and the next
   iteration's planner sees why.

Feedback carries the real error text because that is what turns a second attempt into a fix
rather than a re-roll.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import git_ops, patch, repomap
from .config import Config
from .engine import Engine
from .gates import GateReport, run_gates
from .notify import Notifier
from .prompts import build_messages, core_blocks, patch_feedback, role_block
from .store import Store
from .util import LOG, trim


@dataclass
class TaskOutcome:
    task_id: str
    status: str  # built | failed
    branch: str = ""
    commit: str = ""
    base: str = ""
    diff: str = ""
    notes: str = ""
    error: str = ""
    provider: str = ""
    model: str = ""
    attempts: int = 0
    changed_files: list[str] = field(default_factory=list)
    gate_report: GateReport | None = None
    worktree: Path | None = None

    @property
    def ok(self) -> bool:
        return self.status == "built"


class Worker:
    def __init__(
        self,
        cfg: Config,
        engine: Engine,
        store: Store,
        notifier: Notifier,
        *,
        goal_text: str,
        repo_map: str,
        gates: list[dict],
    ):
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.notifier = notifier
        self.goal_text = goal_text
        self.repo_map = repo_map
        self.gates = gates

    # ------------------------------------------------------------------ main
    def run(self, task: dict, *, reuse: TaskOutcome | None = None, feedback: str = "") -> TaskOutcome:
        """Build a task. With ``reuse`` the existing worktree is kept (used for rework after review)."""
        repo = Path(self.cfg.project_dir)
        if reuse is not None and reuse.worktree and Path(reuse.worktree).exists():
            branch, base, worktree = reuse.branch, reuse.base, Path(reuse.worktree)
            outcome = TaskOutcome(
                task_id=task["id"], status="failed", branch=branch, base=base, worktree=worktree
            )
        else:
            branch = git_ops.branch_name(self.cfg.commit_prefix, task["id"])
            rel_dir = f".worktrees/{branch.split('/', 1)[-1]}"
            base = git_ops.head_sha(repo) if git_ops.has_commits(repo) else ""
            outcome = TaskOutcome(task_id=task["id"], status="failed", branch=branch, base=base)
            try:
                worktree = git_ops.add_worktree(repo, rel_dir, branch)
            except git_ops.GitError as exc:
                outcome.error = f"could not create worktree: {exc}"
                return outcome
            outcome.worktree = worktree
            self._link_shared_dirs(repo, worktree)

        system = core_blocks(self.goal_text, self.repo_map) + [
            role_block(task.get("role", "backend"), "build", task["id"])
        ]
        for attempt in range(1, self.cfg.max_attempts + 1):
            outcome.attempts = attempt
            self.store.update_task(task["id"], status="building", attempts=attempt)
            file_context = repomap.read_files(worktree, task.get("files", []))
            completion = self.engine.call(
                task.get("role", "backend"),
                system=system,
                messages=build_messages(task, file_context, feedback),
                task_id=task["id"],
                phase="build",
                attempt=attempt,
            )
            outcome.provider, outcome.model = completion.provider, completion.model

            parsed = patch.parse(completion.text)
            result = patch.apply(
                parsed,
                worktree,
                allowed=task.get("files", []),
                forbidden=self.cfg.forbidden_paths,
            )
            outcome.notes = parsed.notes.strip()
            if not result.ok:
                feedback = patch_feedback(parsed, result.errors)
                LOG.warning("task %s attempt %d: patch rejected — %s", task["id"], attempt, patch.summarize(result))
                continue

            outcome.changed_files = result.changed + result.deleted
            commit_msg = f"{self.cfg.commit_prefix}({task.get('role', 'dev')}): {task['title']}"
            try:
                sha = git_ops.commit_all(worktree, commit_msg)
            except git_ops.GitError as exc:
                feedback = f"git refused the commit: {exc}"
                continue
            outcome.commit = sha

            report = run_gates(worktree, self.gates, changed=outcome.changed_files)
            outcome.gate_report = report
            if report.ok:
                outcome.status = "built"
                outcome.diff = (
                    git_ops.diff_text(worktree, base, "HEAD") if base else git_ops.git(["show", "--stat"], worktree).stdout
                )
                LOG.info(
                    "task %s built on attempt %d (%s)", task["id"], attempt, ", ".join(outcome.changed_files[:6])
                )
                return outcome

            failure = report.failure_text()
            LOG.warning("task %s attempt %d: gates failed\n%s", task["id"], attempt, report.summary())
            feedback = (
                "The gates that must pass before your work can be merged failed. Fix the cause, "
                "do not weaken or delete the checks:\n\n" + trim(failure, 8000)
            )

        outcome.error = trim(feedback or "no usable patch produced", 1500)
        return outcome

    # ------------------------------------------------------------------ helpers
    def _link_shared_dirs(self, repo: Path, worktree: Path) -> None:
        """Symlink heavy shared dirs (node_modules, .venv) so gates can run in a fresh worktree."""
        for name in self.cfg.shared_dirs:
            source = repo / name
            target = worktree / name
            if not source.exists() or target.exists():
                continue
            try:
                os.symlink(source, target, target_is_directory=source.is_dir())
                LOG.debug("linked %s into %s", name, worktree.name)
            except OSError as exc:
                LOG.debug("could not link %s: %s", name, exc)

    def cleanup(self, outcome: TaskOutcome, keep: bool = False, task_id: str = "") -> None:
        """Remove the task's worktree. Safe to call for a crashed attempt with no outcome data."""
        if keep:
            return
        branch = outcome.branch or git_ops.branch_name(self.cfg.commit_prefix, task_id or outcome.task_id)
        rel = f".worktrees/{branch.split('/', 1)[-1]}"
        try:
            git_ops.remove_worktree(Path(self.cfg.project_dir), rel)
        except git_ops.GitError as exc:
            LOG.debug("worktree cleanup failed: %s", exc)
