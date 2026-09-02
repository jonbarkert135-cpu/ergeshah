"""Small shared helpers: logging, time, text trimming, JSON extraction."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path

LOG = logging.getLogger("hive")


def setup_logging(log_dir: Path | None = None, verbose: bool = False) -> None:
    """Console + optional file logging. Idempotent."""
    root = logging.getLogger("hive")
    if root.handlers:
        root.setLevel(logging.DEBUG if verbose else logging.INFO)
        return
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    stream.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(stream)
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "hive.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s"))
        fh.setLevel(logging.DEBUG)
        root.addHandler(fh)


def now() -> float:
    return time.time()


def utc_stamp(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def trim(text: str, limit: int, marker: str = "\n... [trimmed] ...\n") -> str:
    """Keep the head and the tail of long text — errors are usually at both ends."""
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    if limit <= len(marker) + 20:
        return text[:limit]
    head = int(limit * 0.6)
    tail = limit - head - len(marker)
    return text[:head] + marker + text[-tail:]


def slug(text: str, max_len: int = 40) -> str:
    out = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return (out[:max_len].strip("-") or "task")


_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def extract_json(text: str) -> object:
    """Pull the first JSON object/array out of a model reply.

    Models wrap JSON in prose or fences no matter how loudly the prompt forbids it, so we
    try: whole string → fenced block → first balanced {...}/[...] span.
    """
    if text is None:
        raise ValueError("empty response")
    candidates: list[str] = []
    stripped = text.strip()
    if stripped:
        candidates.append(stripped)
    for m in _FENCE_RE.finditer(text):
        candidates.append(m.group(1))
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(text)):
                ch = text[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[start : i + 1])
                        break
            break
    for cand in candidates:
        try:
            return json.loads(cand)
        except Exception:
            continue
    raise ValueError("no valid JSON found in response")


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def human_usd(value: float) -> str:
    if value >= 1:
        return f"${value:,.2f}"
    return f"${value:.4f}"


def read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return default
