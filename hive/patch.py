"""The edit protocol: how agents are allowed to change the repo.

Models are bad at inventing correct unified-diff line numbers and good at quoting text, so
Hive uses a quote-based protocol instead of ``diff``:

    ### FILE path/to/new_or_rewritten.py
    ```python
    <full file content>
    ```

    ### EDIT path/to/existing.py
    <<<<<<< SEARCH
    exact text that is in the file right now
    =======
    text that replaces it
    >>>>>>> REPLACE

    ### DELETE path/to/obsolete.py

    ### NOTES
    free-form remarks for the reviewer (never written to disk)

Why this shape:

* ``EDIT`` blocks cost a fraction of the tokens of a whole-file rewrite — the single biggest
  cost sink in agentic coding — and they fail loudly instead of silently dropping code.
* Every write is checked against the task's declared file ownership, so two agents working in
  parallel cannot quietly fight over the same file.
* Path traversal, absolute paths and protected files are rejected before touching the disk.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

HEADER_RE = re.compile(r"^###\s+(FILE|EDIT|DELETE|NOTES)\b[ \t]*(.*)$", re.MULTILINE)
FENCE_RE = re.compile(r"^\s*```")
SR_RE = re.compile(
    r"<{5,}\s*SEARCH\s*\n(?P<search>.*?)\n={5,}\s*\n(?P<replace>.*?)\n>{5,}\s*REPLACE",
    re.DOTALL,
)


@dataclass
class Edit:
    kind: str  # file | edit | delete
    path: str
    content: str = ""
    replacements: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ParsedPatch:
    edits: list[Edit] = field(default_factory=list)
    notes: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.edits


@dataclass
class ApplyResult:
    changed: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and bool(self.changed or self.deleted)


def parse(text: str) -> ParsedPatch:
    """Parse an agent reply into edits. Unknown prose outside blocks is ignored."""
    out = ParsedPatch()
    if not text:
        out.errors.append("empty reply")
        return out
    matches = list(HEADER_RE.finditer(text))
    if not matches:
        out.errors.append(
            "no '### FILE', '### EDIT' or '### DELETE' block found — the reply did not follow the edit protocol"
        )
        return out
    for i, match in enumerate(matches):
        kind = match.group(1).upper()
        arg = match.group(2).strip().strip("`")
        body_start = match.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[body_start:body_end]
        if kind == "NOTES":
            out.notes += body.strip() + "\n"
            continue
        if not arg:
            out.errors.append(f"'### {kind}' block without a path")
            continue
        path = _normalize(arg)
        if path is None:
            out.errors.append(f"unsafe path rejected: {arg}")
            continue
        if kind == "FILE":
            out.edits.append(Edit("file", path, content=_strip_fence(body)))
        elif kind == "DELETE":
            out.edits.append(Edit("delete", path))
        else:
            pairs = [(m.group("search"), m.group("replace")) for m in SR_RE.finditer(body)]
            if not pairs:
                out.errors.append(
                    f"'### EDIT {path}' has no SEARCH/REPLACE block (expected <<<<<<< SEARCH … ======= … >>>>>>> REPLACE)"
                )
                continue
            out.edits.append(Edit("edit", path, replacements=pairs))
    return out


def apply(
    patch: ParsedPatch,
    root: Path,
    *,
    allowed: list[str] | None = None,
    forbidden: tuple[str, ...] = (),
) -> ApplyResult:
    """Apply edits inside ``root``. ``allowed`` may contain exact paths or glob patterns."""
    result = ApplyResult(errors=list(patch.errors))
    root = Path(root)
    for edit in patch.edits:
        target = root / edit.path
        if not _within(root, target):
            result.errors.append(f"{edit.path}: escapes the project directory")
            continue
        if _is_forbidden(edit.path, forbidden):
            result.errors.append(f"{edit.path}: protected path, agents may not modify it")
            continue
        if allowed is not None and not _is_allowed(edit.path, allowed):
            result.errors.append(
                f"{edit.path}: not in this task's file ownership list ({', '.join(allowed) or 'none'})"
            )
            continue
        try:
            if edit.kind == "file":
                target.parent.mkdir(parents=True, exist_ok=True)
                body = edit.content
                if body and not body.endswith("\n"):
                    body += "\n"
                target.write_text(body, encoding="utf-8")
                result.changed.append(edit.path)
            elif edit.kind == "delete":
                if target.exists():
                    target.unlink()
                    result.deleted.append(edit.path)
                else:
                    result.errors.append(f"{edit.path}: cannot delete, file does not exist")
            else:
                if not target.exists():
                    result.errors.append(
                        f"{edit.path}: cannot EDIT a file that does not exist — use '### FILE' to create it"
                    )
                    continue
                original = target.read_text(encoding="utf-8")
                updated = original
                for search, replace in edit.replacements:
                    updated, error = _replace_once(updated, search, replace, edit.path)
                    if error:
                        result.errors.append(error)
                        updated = None
                        break
                if updated is None:
                    continue
                if updated == original:
                    result.errors.append(f"{edit.path}: edit produced no change")
                    continue
                target.write_text(updated, encoding="utf-8")
                result.changed.append(edit.path)
        except OSError as exc:
            result.errors.append(f"{edit.path}: {exc}")
    return result


# --------------------------------------------------------------------------- helpers
def _strip_fence(body: str) -> str:
    """Remove the code fence wrapping a ``### FILE`` body, keeping nested fences intact."""
    lines = body.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and FENCE_RE.match(lines[0]):
        lines.pop(0)
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip().startswith("```"):
                del lines[i]
                break
    return ("\n".join(lines) + "\n") if lines else ""


def _replace_once(text: str, search: str, replace: str, path: str) -> tuple[str | None, str]:
    if not search.strip():
        return None, f"{path}: empty SEARCH block"
    count = text.count(search)
    if count == 1:
        return text.replace(search, replace, 1), ""
    if count > 1:
        return None, (
            f"{path}: SEARCH block matches {count} times — include more surrounding context to make it unique"
        )
    # tolerate trailing-whitespace and indentation drift before giving up
    loose = _loose_find(text, search)
    if loose is not None:
        start, end = loose
        return text[:start] + replace + text[end:], ""
    preview = search.strip().splitlines()[0][:80] if search.strip() else ""
    return None, (
        f"{path}: SEARCH block not found (first line: {preview!r}). "
        "Quote the current file content exactly."
    )


def _loose_find(text: str, search: str) -> tuple[int, int] | None:
    def norm(line: str) -> str:
        return line.strip()

    hay = text.splitlines(keepends=True)
    needle = [norm(x) for x in search.splitlines() if norm(x)]
    if not needle:
        return None
    for i in range(len(hay)):
        j, k = i, 0
        while j < len(hay) and k < len(needle):
            if not norm(hay[j]):
                j += 1
                continue
            if norm(hay[j]) != needle[k]:
                break
            j += 1
            k += 1
        if k == len(needle):
            start = sum(len(x) for x in hay[:i])
            end = sum(len(x) for x in hay[:j])
            return start, end
    return None


def _normalize(raw: str) -> str | None:
    candidate = raw.strip().strip('"').strip("'").replace("\\", "/")
    if candidate.startswith(("a/", "b/")) and len(candidate) > 2:
        candidate = candidate[2:]
    if not candidate or candidate.startswith("/") or ":" in candidate.split("/")[0][1:2]:
        return None
    pure = PurePosixPath(candidate)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        return None
    return str(pure)


def _within(root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _is_forbidden(path: str, forbidden: tuple[str, ...]) -> bool:
    for rule in forbidden:
        rule = rule.strip()
        if not rule:
            continue
        if rule.endswith("/"):
            if path == rule.rstrip("/") or path.startswith(rule):
                return True
        elif fnmatch.fnmatch(path, rule) or path == rule:
            return True
    return False


def _is_allowed(path: str, allowed: list[str]) -> bool:
    for rule in allowed:
        rule = rule.strip().replace("\\", "/")
        if not rule:
            continue
        if rule.endswith("/"):
            if path.startswith(rule):
                return True
        elif path == rule or fnmatch.fnmatch(path, rule):
            return True
    return False


def summarize(result: ApplyResult) -> str:
    parts = []
    if result.changed:
        parts.append("changed: " + ", ".join(result.changed))
    if result.deleted:
        parts.append("deleted: " + ", ".join(result.deleted))
    if result.errors:
        parts.append("errors: " + "; ".join(result.errors))
    return " | ".join(parts) or "no changes"
