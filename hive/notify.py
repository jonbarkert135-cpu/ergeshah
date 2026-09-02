"""Notifications: console, event log, ``NEEDS_ATTENTION.md``, Slack webhook, shell hook.

The only alert that really matters is "a key is dead, give me a new one" — so it is made
impossible to miss: it lands in the log, in the state DB, in a file at the project root, in
Slack (if a webhook is configured) and in whatever command you put in ``HIVE_NOTIFY_CMD``.
"""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from .config import Config
from .http import post_text
from .store import Store
from .util import LOG, utc_stamp

ALERT_KINDS = {"key_exhausted", "key_invalid", "blocked", "run_failed", "budget_exhausted"}
ATTENTION_FILE = "NEEDS_ATTENTION.md"


class Notifier:
    def __init__(self, cfg: Config, store: Store | None = None):
        self.cfg = cfg
        self.store = store

    def event(self, kind: str, title: str, body: str = "") -> None:
        alert = kind in ALERT_KINDS
        (LOG.warning if alert else LOG.info)("[%s] %s%s", kind, title, f" — {body}" if body else "")
        if self.store is not None:
            try:
                self.store.add_event(kind, title, body)
            except Exception as exc:  # never let bookkeeping kill a run
                LOG.debug("event store failed: %s", exc)
        self._append_journal(kind, title, body)
        if alert:
            self._write_attention(kind, title, body)
            self._slack(kind, title, body)
            self._shell(kind, title, body)

    # ------------------------------------------------------------------ sinks
    def _append_journal(self, kind: str, title: str, body: str) -> None:
        try:
            self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
            with (self.cfg.state_dir / "EVENTS.md").open("a", encoding="utf-8") as fh:
                fh.write(f"- `{utc_stamp()}` **{kind}** — {title}{(': ' + body) if body else ''}\n")
        except OSError as exc:
            LOG.debug("journal write failed: %s", exc)

    def _write_attention(self, kind: str, title: str, body: str) -> None:
        try:
            path = Path(self.cfg.project_dir) / ATTENTION_FILE
            path.write_text(
                f"# Hive needs you\n\n"
                f"- **when:** {utc_stamp()}\n"
                f"- **what:** {kind}\n"
                f"- **detail:** {title}\n\n"
                f"{body}\n\n"
                f"## What to do\n\n"
                f"1. Put a working key in `{self.cfg.env_file}` (any free slot, e.g. "
                f"`ANTHROPIC_API_KEY_2=...`).\n"
                f"2. Hive re-reads `{self.cfg.env_file}` every "
                f"{self.cfg.key_wait_seconds}s while it waits — no restart needed.\n"
                f"3. If you stopped the run, `python -m hive run` picks up exactly where it left off.\n",
                encoding="utf-8",
            )
        except OSError as exc:
            LOG.debug("attention file write failed: %s", exc)

    def clear_attention(self) -> None:
        try:
            (Path(self.cfg.project_dir) / ATTENTION_FILE).unlink(missing_ok=True)
        except OSError:
            pass

    def _slack(self, kind: str, title: str, body: str) -> None:
        if not self.cfg.slack_webhook:
            return
        text = f":rotating_light: *Hive: {kind}*\n{title}"
        if body:
            text += f"\n```{body[:1500]}```"
        status = post_text(self.cfg.slack_webhook, {"text": text})
        if status not in (200, 0):
            LOG.debug("slack webhook returned %s", status)

    def _shell(self, kind: str, title: str, body: str) -> None:
        if not self.cfg.notify_cmd:
            return
        message = f"Hive {kind}: {title} {body}".strip()
        try:
            cmd = self.cfg.notify_cmd
            if "{message}" in cmd:
                cmd = cmd.replace("{message}", shlex.quote(message))
            else:
                cmd = f"{cmd} {shlex.quote(message)}"
            subprocess.run(cmd, shell=True, timeout=30, check=False)  # noqa: S602 - operator supplied
        except Exception as exc:
            LOG.debug("notify_cmd failed: %s", exc)
