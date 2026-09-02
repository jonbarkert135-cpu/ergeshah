"""Shared test fixtures: a temp project, a store, a pool, and a fake provider."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hive.config import Config
from hive.engine import Engine
from hive.keys import KeyPool
from hive.notify import Notifier
from hive.providers.base import Block, Completion, Message, Provider, Usage
from hive.store import Store

HAS_GIT = shutil.which("git") is not None


class TempProject(unittest.TestCase):
    """Base class giving each test an isolated project dir + config + store."""

    env_lines: list[str] = ["HIVE_ENABLE_MOCK=1"]

    def setUp(self) -> None:
        logging.getLogger("hive").setLevel(logging.CRITICAL)  # keep test output readable
        self.tmp = Path(tempfile.mkdtemp(prefix="hive-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.env_path = self.tmp / ".env"
        self.write_env(self.env_lines)
        self.cfg = Config.load(self.env_path)
        self.cfg.project_dir = self.tmp
        self.cfg.state_dir = self.tmp / ".hive"
        self.cfg.goal_file = self.tmp / "GOAL.md"
        self.cfg.ensure_dirs()
        self.store = Store(self.cfg.db_path)
        self.addCleanup(self.store.close)
        self.notifier = Notifier(self.cfg, self.store)

    def write_env(self, lines: list[str]) -> None:
        self.env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        # Config.load merges os.environ on top; tests must not leak real keys into the pool.

    def make_pool(self) -> KeyPool:
        return KeyPool(self.cfg, self.store, self.notifier)

    def make_engine(self, pool: KeyPool | None = None) -> Engine:
        return Engine(self.cfg, self.store, pool or self.make_pool(), self.notifier)

    def git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args], cwd=str(cwd or self.tmp), capture_output=True, text=True, check=False
        )

    def init_git(self) -> None:
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")


class ScriptedProvider(Provider):
    """Fake provider that replays queued behaviours: strings or exceptions."""

    kind = "scripted"

    def __init__(self, name: str = "anthropic", script: list[object] | None = None):
        super().__init__(name, "https://example.invalid", 5)
        self.script: list[object] = list(script or [])
        self.calls: list[dict] = []

    def complete(
        self,
        *,
        model: str,
        system: list[Block],
        messages: list[Message],
        api_key: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> Completion:
        self.calls.append({"model": model, "api_key": api_key, "messages": messages})
        item = self.script.pop(0) if self.script else "### NOTES\nnothing\n"
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            item = item()
        return Completion(
            text=str(item),
            model=model,
            provider=self.name,
            usage=Usage(input_tokens=1000, output_tokens=100, cost_usd=0.01),
        )
