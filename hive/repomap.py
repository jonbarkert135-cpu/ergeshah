"""Repo map: a compact, cache-friendly picture of the codebase.

Sending whole files to every agent on every call is what makes naive multi-agent setups
ruinously expensive. Instead each agent gets:

* a directory tree with file sizes,
* extracted signatures (defs/classes/exports/interfaces) for source files,
* the *full* text of only the files its task owns (added by the worker, not here).

The map is deterministic and byte-stable within an iteration, which is exactly what prompt
caching needs to give the ~90% discount on the repeated prefix.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hive",
    ".worktrees",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".cache",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
}
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wasm", ".so", ".dylib", ".dll", ".class", ".jar",
    ".sqlite3", ".db", ".lock",
}
SIGNATURE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs", ".java", ".rb", ".php", ".sql"}

TS_SIGNATURE_RE = re.compile(
    r"^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?"
    r"(?:function\s+\w+\s*\([^)]*\)|class\s+\w+[^{]*|interface\s+\w+[^{]*|type\s+\w+\s*=[^;]*"
    r"|const\s+\w+\s*[:=][^=]*=>|enum\s+\w+)",
    re.MULTILINE,
)
GENERIC_SIGNATURE_RE = re.compile(
    r"^\s*(?:pub\s+)?(?:async\s+)?(?:func|fn|class|struct|interface|type|def|module|CREATE\s+TABLE)\b.*$",
    re.MULTILINE | re.IGNORECASE,
)


def list_files(root: Path) -> list[Path]:
    """Prefer ``git ls-files`` (respects .gitignore); fall back to a filtered walk."""
    root = Path(root)
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            paths = []
            for line in proc.stdout.splitlines():
                rel = line.strip()
                if not rel or any(part in SKIP_DIRS for part in Path(rel).parts):
                    continue
                path = root / rel
                if path.is_file():
                    paths.append(path)
            return sorted(paths)
    except (OSError, subprocess.SubprocessError):
        pass
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        out.append(path)
    return out


def signatures(path: Path, text: str) -> list[str]:
    suffix = path.suffix.lower()
    lines: list[str] = []
    if suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines.append(f"def {node.name}({_args(node)})")
            elif isinstance(node, ast.ClassDef):
                methods = [
                    n.name
                    for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_")
                ]
                lines.append(f"class {node.name}" + (f" [{', '.join(methods[:8])}]" if methods else ""))
        return lines
    if suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs"}:
        for match in TS_SIGNATURE_RE.finditer(text):
            lines.append(" ".join(match.group(0).split())[:120])
        return lines[:40]
    if suffix in SIGNATURE_SUFFIXES:
        for match in GENERIC_SIGNATURE_RE.finditer(text):
            lines.append(" ".join(match.group(0).split())[:120])
        return lines[:40]
    return []


def _args(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    parts = [a.arg for a in node.args.args]
    if node.args.vararg:
        parts.append("*" + node.args.vararg.arg)
    if node.args.kwarg:
        parts.append("**" + node.args.kwarg.arg)
    return ", ".join(parts)


def build(root: Path, char_limit: int = 18_000, focus: list[str] | None = None) -> str:
    """Render the map. ``focus`` paths keep their signatures when the budget gets tight."""
    root = Path(root)
    files = list_files(root)
    if not files:
        return "(empty repository)"
    focus_set = {f.strip().replace("\\", "/") for f in (focus or [])}

    entries: list[tuple[str, int, list[str], bool]] = []
    for path in files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            size = path.stat().st_size
        except OSError:
            continue
        sigs: list[str] = []
        if path.suffix.lower() in SIGNATURE_SUFFIXES and size < 400_000:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                sigs = signatures(path, text)
            except OSError:
                sigs = []
        is_focus = rel in focus_set or any(rel.startswith(f.rstrip("*")) for f in focus_set if f.endswith("*"))
        entries.append((rel, size, sigs, is_focus))

    header = f"REPO MAP — {len(entries)} files\n"
    body_lines: list[str] = []
    for rel, size, sigs, is_focus in entries:
        mark = " *" if is_focus else ""
        body_lines.append(f"{rel} ({_kb(size)}){mark}")
        for sig in sigs[:12]:
            body_lines.append(f"    · {sig}")
    text = header + "\n".join(body_lines)
    if len(text) <= char_limit:
        return text

    # Too big: drop signatures for non-focus files, then truncate the tail.
    body_lines = []
    for rel, size, sigs, is_focus in entries:
        body_lines.append(f"{rel} ({_kb(size)})" + (" *" if is_focus else ""))
        if is_focus:
            for sig in sigs[:12]:
                body_lines.append(f"    · {sig}")
    text = header + "\n".join(body_lines)
    if len(text) <= char_limit:
        return text
    return text[:char_limit] + f"\n... [map truncated at {char_limit} chars — {len(entries)} files total]"


def _kb(size: int) -> str:
    if size < 1024:
        return f"{size}B"
    return f"{size / 1024:.1f}KB"


def read_files(root: Path, rel_paths: list[str], per_file_limit: int = 24_000) -> str:
    """Full text of specific files, for the agent that owns them."""
    root = Path(root)
    chunks: list[str] = []
    for rel in rel_paths:
        path = root / rel
        if not path.exists():
            chunks.append(f"### CURRENT {rel}\n(file does not exist yet — create it)\n")
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            chunks.append(f"### CURRENT {rel}\n(binary file, {_kb(path.stat().st_size)})\n")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            chunks.append(f"### CURRENT {rel}\n(unreadable: {exc})\n")
            continue
        if len(text) > per_file_limit:
            text = text[:per_file_limit] + f"\n... [truncated at {per_file_limit} chars]"
        chunks.append(f"### CURRENT {rel}\n```\n{text}\n```\n")
    return "\n".join(chunks)
