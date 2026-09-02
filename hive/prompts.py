"""Prompt construction — where the token bill is won or lost.

Every call is assembled as::

    [ core rules ]      identical for every agent, every call      → cached
    [ final goal ]      identical for the whole run                → cached
    [ repo map ]        identical within an iteration              → cached
    [ role + phase ]    small, varies per agent
    [ task payload ]    the only genuinely new tokens

The first three blocks are byte-identical across all ten agents, so after the first call of an
iteration every other agent hits the provider's prompt cache for that prefix (~10% of the
input price on Anthropic/OpenAI/DeepSeek). That is the difference between a hive being
affordable and being a bonfire.

The ``HIVE_PHASE`` / ``HIVE_ROLE`` / ``HIVE_TASK`` markers are part of the contract: they let
tests and the mock provider react to the same prompts the real models see.
"""

from __future__ import annotations

import json

from .patch import ParsedPatch
from .providers import Block, Message
from .roster import ROLES
from .util import trim

CORE_RULES = """\
You are one agent in a multi-agent engineering team called Hive. Several specialists work on
the same repository in parallel, each in an isolated git worktree, coordinated by an
orchestrator. Obey these rules exactly — they are what makes parallel work safe.

FILE OWNERSHIP
- You may only create, edit or delete the files listed in your task's "files" contract.
- If the task cannot be completed without touching another file, do not touch it: explain the
  conflict in a `### NOTES` block and implement everything you legitimately can.

EDIT PROTOCOL — your reply must consist only of these blocks:

### FILE relative/path.ext
```
<complete new content of the file>
```

### EDIT relative/path.ext
<<<<<<< SEARCH
<text that currently exists in the file, quoted exactly, with enough context to be unique>
=======
<replacement text>
>>>>>>> REPLACE

### DELETE relative/path.ext

### NOTES
<short remarks for the reviewer: decisions, trade-offs, residual risks>

Rules for edits:
- Prefer `### EDIT` over `### FILE` for existing files: it is cheaper and safer. Use `### FILE`
  for new files or a deliberate full rewrite.
- SEARCH text must match the current file byte-for-byte (whitespace included) and must appear
  exactly once. Multiple EDIT blocks per file are allowed.
- Never write placeholders, `TODO`, `...`, "rest of the file unchanged", or stub bodies that
  pretend to work. Ship complete, working code.
- No prose outside the blocks. No explanation of what you are about to do.

ENGINEERING RULES
- Correctness over volume. Handle errors and edge cases; validate all external input.
- No secrets, keys or tokens in code. No new third-party dependency unless the task asks for
  it; prefer the standard library.
- Do not invent cryptography. Use vetted libraries and standard constructions.
- Do not add telemetry, analytics or third-party trackers.
- Keep the public interfaces named in the task contract stable; other agents depend on them.
- Make the acceptance criteria of your task literally true, and nothing beyond your task.
"""

PLAN_INSTRUCTIONS = """\
Decompose the remaining work toward the FINAL GOAL into independent tasks.

Return ONLY a JSON object:

{
  "tasks": [
    {
      "id": "kebab-case-unique-id",
      "title": "one line",
      "role": "backend|frontend|database|crypto|tests|devops|docs",
      "spec": "what to implement, precisely enough that an engineer who cannot ask questions can do it; name the interfaces to expose",
      "files": ["exact/paths.ext", "the/agent/may/touch.ext"],
      "depends_on": ["ids of tasks that must be merged first"],
      "acceptance": ["objectively checkable statements"]
    }
  ]
}

Hard constraints:
- At most %(max_tasks)d tasks. Fewer, well-specified tasks beat many vague ones.
- Two tasks that can run in parallel MUST NOT list the same file. If they need the same file,
  give one task the file and make the other depend on it.
- Every task must be completable by one engineer in one sitting (roughly < 400 lines of change).
- Do not re-plan work that is already listed as completed. Build on it.
- Order matters: foundations (schema, interfaces, config) before features that use them.
- If the goal is already fully met, return {"tasks": []}.
"""

VERIFY_INSTRUCTIONS = """\
Decide whether the FINAL GOAL is met by the current state of the repository.

Return ONLY JSON:

{
  "done": true|false,
  "summary": "two sentences on where the project stands",
  "gaps": ["concrete missing pieces, most important first"],
  "risks": ["known weaknesses worth telling the operator about"]
}

Judge only what the repo map, the completed task list and the gate results support. Do not
assume unwritten code exists. Being wrong in the optimistic direction is the worst outcome.
"""

REVIEW_INSTRUCTIONS = """\
Review the diff below against the task contract.

Return ONLY JSON:

{
  "verdict": "approve" | "request_changes",
  "summary": "one or two sentences",
  "findings": [
    {"severity": "critical|high|medium|low", "file": "path or ''", "issue": "what is wrong", "fix": "what to do instead"}
  ]
}

Guidance:
- "request_changes" only for defects you can point at: wrong behaviour, unmet acceptance
  criteria, missing error handling, security or privacy regressions, broken contracts,
  placeholders pretending to be implementations, files touched outside the contract.
- Style preferences, naming taste and hypothetical future refactors are `low` at most and must
  not block a merge.
- Be specific and short. No praise, no restating the diff.
"""


def core_blocks(goal_text: str, repo_map: str) -> list[Block]:
    """The three cached blocks, identical for every agent in the iteration."""
    return [
        Block(CORE_RULES, cache=True),
        Block("FINAL GOAL OF THE PROJECT\n" + goal_text.strip(), cache=True),
        Block("CURRENT REPOSITORY\n" + repo_map, cache=True),
    ]


def role_block(role: str, phase: str, task_id: str = "") -> Block:
    persona = (ROLES.get(role) or ROLES["backend"]).persona
    marker = f"HIVE_ROLE: {role}\nHIVE_PHASE: {phase}"
    if task_id:
        marker += f"\nHIVE_TASK: {task_id}"
    return Block(f"YOUR ROLE\n{persona}\n\n{marker}")


# --------------------------------------------------------------------------- phases
def plan_messages(state_summary: str, max_tasks: int, feedback: str = "") -> list[Message]:
    body = (PLAN_INSTRUCTIONS % {"max_tasks": max_tasks}) + "\n\nPROJECT STATE\n" + state_summary
    if feedback:
        body += f"\n\nYOUR PREVIOUS ANSWER WAS REJECTED\n{feedback}\nReturn corrected JSON only."
    return [Message("user", body)]


def build_messages(task: dict, file_context: str, feedback: str = "") -> list[Message]:
    contract = {
        "id": task["id"],
        "title": task["title"],
        "role": task.get("role", "backend"),
        "files": task.get("files", []),
        "acceptance": task.get("acceptance", []),
    }
    body = (
        "YOUR TASK\n"
        + json.dumps(contract, indent=2, ensure_ascii=False)
        + "\n\nSPEC\n"
        + str(task.get("spec", "")).strip()
        + "\n\nFILES YOU OWN (current content)\n"
        + (file_context or "(none of them exist yet)")
        + "\n\nReply with edit blocks only, following the EDIT PROTOCOL."
    )
    if feedback:
        body += (
            "\n\nPREVIOUS ATTEMPT FAILED — fix exactly this, keep everything that already works:\n"
            + trim(feedback, 8000)
        )
    return [Message("user", body)]


def review_messages(task: dict, diff: str, gate_summary: str, notes: str = "") -> list[Message]:
    body = (
        REVIEW_INSTRUCTIONS
        + "\n\nTASK CONTRACT\n"
        + json.dumps(
            {
                "id": task["id"],
                "title": task["title"],
                "spec": task.get("spec", ""),
                "files": task.get("files", []),
                "acceptance": task.get("acceptance", []),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n\nGATE RESULTS\n"
        + (gate_summary or "(none)")
        + (f"\n\nAUTHOR NOTES\n{trim(notes, 2000)}" if notes else "")
        + "\n\nDIFF\n```diff\n"
        + trim(diff, 30_000)
        + "\n```"
    )
    return [Message("user", body)]


def verify_messages(state_summary: str) -> list[Message]:
    return [Message("user", VERIFY_INSTRUCTIONS + "\n\nPROJECT STATE\n" + state_summary)]


def patch_feedback(parsed: ParsedPatch, apply_errors: list[str]) -> str:
    """Human-readable, model-actionable explanation of why a patch did not stick."""
    lines: list[str] = []
    if parsed.errors:
        lines.append("Protocol errors:")
        lines += [f"- {e}" for e in parsed.errors]
    if apply_errors:
        lines.append("Could not apply your edits:")
        lines += [f"- {e}" for e in apply_errors]
    if not lines:
        lines.append("Your reply contained no usable edits.")
    lines.append(
        "Re-send the complete set of edits for this task using the EDIT PROTOCOL. "
        "Quote existing content exactly, or use '### FILE' with the full new content."
    )
    return "\n".join(lines)
