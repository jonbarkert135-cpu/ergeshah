"""Review phase: two independent reviewers, deliberately from different model families.

Rules that keep this useful instead of ceremonial:

* **No self-review.** A reviewer never runs on the provider that wrote the code; the author's
  provider is pushed to the back of the candidate list.
* **Only pointed defects block.** A merge is blocked by findings at the severities in
  ``HIVE_BLOCKING_SEVERITIES`` (default critical/high). Taste is advisory and gets logged.
* **Reviews cannot fabricate a pass.** Gates already ran; review adds judgement about intent,
  contracts and security that a test suite cannot express.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config
from .engine import Engine
from .prompts import core_blocks, review_messages, role_block
from .roster import REVIEW_ROLES
from .store import Store
from .util import LOG, extract_json


@dataclass
class Finding:
    severity: str
    file: str
    issue: str
    fix: str = ""

    def line(self) -> str:
        where = f" [{self.file}]" if self.file else ""
        return f"({self.severity}){where} {self.issue}" + (f" → {self.fix}" if self.fix else "")


@dataclass
class Verdict:
    role: str
    provider: str
    model: str
    approved: bool
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    parse_error: str = ""

    def blocking(self, severities: tuple[str, ...]) -> list[Finding]:
        if self.approved:
            return []
        return [f for f in self.findings if f.severity.lower() in severities]


class ReviewBoard:
    def __init__(self, cfg: Config, engine: Engine, store: Store, *, goal_text: str, repo_map: str):
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.goal_text = goal_text
        self.repo_map = repo_map

    def review(self, task: dict, diff: str, gate_summary: str, notes: str, author_provider: str) -> list[Verdict]:
        if self.cfg.review_count <= 0 or not diff.strip():
            return []
        verdicts: list[Verdict] = []
        for role in REVIEW_ROLES[: self.cfg.review_count]:
            completion = self.engine.call(
                role,
                system=core_blocks(self.goal_text, self.repo_map) + [role_block(role, "review", task["id"])],
                messages=review_messages(task, diff, gate_summary, notes),
                task_id=task["id"],
                phase="review",
                temperature=0.0,
                avoid_provider=author_provider,
            )
            verdicts.append(self._parse(role, completion.provider, completion.model, completion.text))
        return verdicts

    @staticmethod
    def _parse(role: str, provider: str, model: str, text: str) -> Verdict:
        try:
            data = extract_json(text)
        except ValueError as exc:
            # An unparseable review must not silently block or silently approve: log and pass,
            # because the gates already proved the change works.
            LOG.warning("review from %s was unparseable (%s)", role, exc)
            return Verdict(role, provider, model, True, "review unparseable — treated as no objection", [], str(exc))
        if not isinstance(data, dict):
            return Verdict(role, provider, model, True, "review not an object — treated as no objection")
        verdict = str(data.get("verdict") or "").strip().lower()
        findings = []
        for item in data.get("findings") or []:
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    severity=str(item.get("severity") or "medium").strip().lower(),
                    file=str(item.get("file") or "").strip(),
                    issue=str(item.get("issue") or "").strip(),
                    fix=str(item.get("fix") or "").strip(),
                )
            )
        approved = verdict not in {"request_changes", "reject", "changes_requested"}
        return Verdict(role, provider, model, approved, str(data.get("summary") or "").strip(), findings)


def blocking_feedback(verdicts: list[Verdict], severities: tuple[str, ...]) -> str:
    """Return the text to send back to the author, or '' when the change may be merged."""
    blocking: list[tuple[str, Finding]] = []
    for verdict in verdicts:
        for finding in verdict.blocking(severities):
            blocking.append((verdict.role, finding))
    if not blocking:
        return ""
    lines = ["Reviewers blocked this change. Fix these findings, keep everything that works:"]
    for role, finding in blocking:
        lines.append(f"- [{role}] {finding.line()}")
    return "\n".join(lines)


def review_summary(verdicts: list[Verdict]) -> str:
    if not verdicts:
        return "(no review)"
    parts = []
    for verdict in verdicts:
        state = "approve" if verdict.approved else "request_changes"
        detail = f" — {verdict.summary}" if verdict.summary else ""
        extra = f" [{len(verdict.findings)} finding(s)]" if verdict.findings else ""
        parts.append(f"{verdict.role} ({verdict.provider}): {state}{extra}{detail}")
    return "\n".join(parts)
