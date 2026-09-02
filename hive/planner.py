"""The architect: goal → task graph, and goal ← reality check.

Two responsibilities, both cheap relative to the build phase and both worth the strongest
model available:

* :meth:`Planner.plan` turns the remaining distance to the final goal into a small set of
  independently buildable tasks with **disjoint file ownership** — the invariant that makes
  parallel agents safe. Overlaps the model leaves behind are repaired here, not discovered at
  merge time.
* :meth:`Planner.verify` decides whether the goal is actually met, using only the repo map,
  the completed task list and real gate results. This is the loop's termination condition.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .config import Config
from .engine import Engine
from .prompts import core_blocks, plan_messages, role_block, verify_messages
from .roster import WORKER_ROLES
from .store import Store
from .util import LOG, extract_json, slug

MAX_PLAN_RETRIES = 2


@dataclass
class PlanResult:
    tasks: list[dict] = field(default_factory=list)
    raw: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass
class VerifyResult:
    done: bool = False
    summary: str = ""
    gaps: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    raw: str = ""


class Planner:
    def __init__(self, cfg: Config, engine: Engine, store: Store):
        self.cfg = cfg
        self.engine = engine
        self.store = store

    # ------------------------------------------------------------------ planning
    def plan(self, goal: str, repo_map: str, state_summary: str, iteration: int) -> PlanResult:
        feedback = ""
        for attempt in range(1, MAX_PLAN_RETRIES + 2):
            completion = self.engine.call(
                "architect",
                system=core_blocks(goal, repo_map) + [role_block("architect", "plan")],
                messages=plan_messages(state_summary, self.cfg.max_tasks_per_iteration, feedback),
                task_id=f"plan-{iteration}",
                phase="plan",
                attempt=attempt,
                temperature=0.15,
            )
            try:
                data = extract_json(completion.text)
            except ValueError as exc:
                feedback = f"Your answer was not valid JSON ({exc})."
                LOG.warning("planner returned invalid JSON (attempt %d)", attempt)
                continue
            tasks_raw = data.get("tasks") if isinstance(data, dict) else data
            if not isinstance(tasks_raw, list):
                feedback = "Expected an object with a 'tasks' array."
                continue
            tasks, errors = self._normalize(tasks_raw, iteration)
            if errors and not tasks:
                feedback = "Problems with your plan:\n" + "\n".join(f"- {e}" for e in errors)
                continue
            for err in errors:
                LOG.info("plan repaired: %s", err)
            return PlanResult(tasks=tasks, raw=completion.text, errors=errors)
        return PlanResult(tasks=[], raw="", errors=[f"planner failed after {MAX_PLAN_RETRIES + 1} attempts"])

    def _normalize(self, raw_tasks: list, iteration: int) -> tuple[list[dict], list[str]]:
        """Validate, de-duplicate, and enforce disjoint file ownership."""
        errors: list[str] = []
        existing_ids = {t["id"] for t in self.store.tasks()}
        tasks: list[dict] = []
        seen_ids: set[str] = set()

        for item in raw_tasks[: self.cfg.max_tasks_per_iteration]:
            if not isinstance(item, dict):
                errors.append("skipped a task that was not an object")
                continue
            title = str(item.get("title") or item.get("id") or "").strip()
            spec = str(item.get("spec") or "").strip()
            if not title or not spec:
                errors.append(f"skipped task without title/spec: {str(item)[:80]}")
                continue
            task_id = slug(str(item.get("id") or title), 48)
            base_id = task_id
            n = 2
            while task_id in seen_ids or task_id in existing_ids:
                task_id = f"{base_id}-{n}"
                n += 1
            seen_ids.add(task_id)

            role = str(item.get("role") or "backend").strip().lower()
            if role not in WORKER_ROLES:
                role = "backend"

            files = [
                str(f).strip().replace("\\", "/")
                for f in (item.get("files") or [])
                if str(f).strip()
            ]
            files = [f for f in files if not f.startswith(("/", "..")) and not self._protected(f)]
            if not files:
                errors.append(f"task '{task_id}' declared no files it may touch — skipped")
                continue

            acceptance = [str(a).strip() for a in (item.get("acceptance") or []) if str(a).strip()]
            depends = [
                slug(str(d), 48)
                for d in (item.get("depends_on") or [])
                if str(d).strip()
            ]
            tasks.append(
                {
                    "id": task_id,
                    "iteration": iteration,
                    "title": title[:200],
                    "role": role,
                    "spec": spec,
                    "files": files,
                    "depends_on": depends,
                    "acceptance": acceptance,
                    "status": "pending",
                }
            )

        # dependencies must point at real tasks (this plan or an earlier one)
        valid = {t["id"] for t in tasks} | existing_ids
        for task in tasks:
            dropped = [d for d in task["depends_on"] if d not in valid]
            if dropped:
                task["depends_on"] = [d for d in task["depends_on"] if d in valid]
                errors.append(f"task '{task['id']}': dropped unknown dependencies {dropped}")

        self._deconflict(tasks, errors)
        self._break_cycles(tasks, errors)
        return tasks, errors

    def _protected(self, path: str) -> bool:
        for rule in self.cfg.forbidden_paths:
            if rule.endswith("/") and path.startswith(rule):
                return True
            if path == rule:
                return True
        return False

    def _deconflict(self, tasks: list[dict], errors: list[str]) -> None:
        """If two tasks claim the same file, serialize them instead of letting them collide."""
        owner: dict[str, str] = {}
        by_id = {t["id"]: t for t in tasks}
        for task in tasks:
            for path in list(task["files"]):
                first = owner.get(path)
                if first is None:
                    owner[path] = task["id"]
                    continue
                if first == task["id"]:
                    continue
                if first not in task["depends_on"] and not self._depends_on(by_id, first, task["id"]):
                    task["depends_on"].append(first)
                    errors.append(
                        f"task '{task['id']}' shares {path} with '{first}' → made it depend on '{first}'"
                    )

    @staticmethod
    def _depends_on(by_id: dict[str, dict], task_id: str, target: str, depth: int = 0) -> bool:
        if depth > 20 or task_id not in by_id:
            return False
        for dep in by_id[task_id].get("depends_on", []):
            if dep == target or Planner._depends_on(by_id, dep, target, depth + 1):
                return True
        return False

    def _break_cycles(self, tasks: list[dict], errors: list[str]) -> None:
        by_id = {t["id"]: t for t in tasks}
        for task in tasks:
            for dep in list(task["depends_on"]):
                if dep == task["id"] or (
                    dep in by_id and self._depends_on(by_id, dep, task["id"])
                ):
                    task["depends_on"].remove(dep)
                    errors.append(f"task '{task['id']}': removed circular dependency on '{dep}'")

    # ------------------------------------------------------------------ verification
    def verify(self, goal: str, repo_map: str, state_summary: str, iteration: int) -> VerifyResult:
        completion = self.engine.call(
            "architect",
            system=core_blocks(goal, repo_map) + [role_block("architect", "verify")],
            messages=verify_messages(state_summary),
            task_id=f"verify-{iteration}",
            phase="verify",
            temperature=0.0,
        )
        try:
            data = extract_json(completion.text)
        except ValueError:
            return VerifyResult(False, "verification response was unparseable", [], [], completion.text)
        if not isinstance(data, dict):
            return VerifyResult(False, "verification response was not an object", [], [], completion.text)
        return VerifyResult(
            done=bool(data.get("done")),
            summary=str(data.get("summary") or "").strip(),
            gaps=[str(g) for g in (data.get("gaps") or [])][:20],
            risks=[str(r) for r in (data.get("risks") or [])][:20],
            raw=completion.text,
        )


def summarize_state(store: Store, gate_summary: str = "", goal_gaps: list[str] | None = None) -> str:
    """Compact, deterministic state description for planner/verifier prompts."""
    tasks = store.tasks()
    done = [t for t in tasks if t["status"] == "merged"]
    failed = [t for t in tasks if t["status"] in {"failed", "abandoned"}]
    open_tasks = [t for t in tasks if t["status"] not in {"merged", "failed", "abandoned"}]
    lines: list[str] = []
    lines.append(f"COMPLETED TASKS ({len(done)}):")
    lines += [f"- {t['id']}: {t['title']} → {', '.join(t['files'][:6])}" for t in done] or ["- (none yet)"]
    if failed:
        lines.append(f"\nFAILED TASKS ({len(failed)}) — do not simply repeat them, change the approach:")
        lines += [f"- {t['id']}: {t['title']} — {t['last_error'][:200]}" for t in failed]
    if open_tasks:
        lines.append(f"\nSTILL OPEN ({len(open_tasks)}):")
        lines += [f"- {t['id']}: {t['title']} [{t['status']}]" for t in open_tasks]
    if gate_summary:
        lines.append("\nLATEST GATE RESULTS:\n" + gate_summary)
    if goal_gaps:
        lines.append("\nGAPS IDENTIFIED IN THE PREVIOUS ITERATION:")
        lines += [f"- {g}" for g in goal_gaps]
    totals = store.totals()
    lines.append(
        f"\nSPEND SO FAR: {totals['calls']} calls, {totals['tokens']} tokens "
        f"({totals['cached_tokens']} cached), ${totals['cost_usd']:.4f}"
    )
    return "\n".join(lines)


def tasks_to_json(tasks: list[dict]) -> str:
    return json.dumps(tasks, indent=2, ensure_ascii=False)
