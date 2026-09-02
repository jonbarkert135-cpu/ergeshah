"""SQLite state — the reason a run survives Ctrl-C, a dead key or a reboot.

Everything durable lives here: the task graph, every attempt with its cost, per-key spend,
and an event log. Threads share one connection guarded by a lock (writes are short).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .util import now, utc_stamp

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    iteration INTEGER NOT NULL DEFAULT 1,
    title TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'backend',
    spec TEXT NOT NULL DEFAULT '',
    files TEXT NOT NULL DEFAULT '[]',
    depends_on TEXT NOT NULL DEFAULT '[]',
    acceptance TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    branch TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    cost_usd REAL NOT NULL DEFAULT 0,
    tokens INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    n INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    key_id TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    budget_credits REAL NOT NULL DEFAULT 0,
    spent_credits REAL NOT NULL DEFAULT 0,
    spent_usd REAL NOT NULL DEFAULT 0,
    tokens INTEGER NOT NULL DEFAULT 0,
    calls INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'live',
    last_error TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_task ON attempts(task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
"""

TERMINAL_OK = ("merged",)
TERMINAL_BAD = ("failed", "abandoned")


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # ------------------------------------------------------------------ low level
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(sql, tuple(params)).fetchall())

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ------------------------------------------------------------------ meta
    def set_meta(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    def get_meta(self, key: str, default: Any = None) -> Any:
        rows = self.query("SELECT value FROM meta WHERE key=?", (key,))
        if not rows:
            return default
        try:
            return json.loads(rows[0]["value"])
        except Exception:
            return default

    # ------------------------------------------------------------------ tasks
    def upsert_task(self, task: dict) -> None:
        ts = now()
        existing = self.query("SELECT id FROM tasks WHERE id=?", (task["id"],))
        payload = (
            task["id"],
            int(task.get("iteration", 1)),
            task.get("title", task["id"]),
            task.get("role", "backend"),
            task.get("spec", ""),
            json.dumps(task.get("files", [])),
            json.dumps(task.get("depends_on", [])),
            json.dumps(task.get("acceptance", [])),
            task.get("status", "pending"),
            int(task.get("attempts", 0)),
            task.get("branch", ""),
            task.get("commit_sha", ""),
            task.get("last_error", ""),
            float(task.get("cost_usd", 0.0)),
            int(task.get("tokens", 0)),
            ts,
            ts,
        )
        if existing:
            self.execute(
                """UPDATE tasks SET iteration=?, title=?, role=?, spec=?, files=?, depends_on=?,
                       acceptance=?, status=?, attempts=?, branch=?, commit_sha=?, last_error=?,
                       cost_usd=?, tokens=?, updated_at=? WHERE id=?""",
                payload[1:15] + (ts, task["id"]),
            )
        else:
            self.execute(
                """INSERT INTO tasks(id, iteration, title, role, spec, files, depends_on, acceptance,
                       status, attempts, branch, commit_sha, last_error, cost_usd, tokens,
                       created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                payload,
            )

    def update_task(self, task_id: str, **fields: Any) -> None:
        if not fields:
            return
        json_fields = {"files", "depends_on", "acceptance"}
        sets, params = [], []
        for key, value in fields.items():
            sets.append(f"{key}=?")
            params.append(json.dumps(value) if key in json_fields else value)
        sets.append("updated_at=?")
        params.extend([now(), task_id])
        self.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id=?", params)

    def bump_task_cost(self, task_id: str, cost_usd: float, tokens: int) -> None:
        self.execute(
            "UPDATE tasks SET cost_usd=cost_usd+?, tokens=tokens+?, updated_at=? WHERE id=?",
            (cost_usd, tokens, now(), task_id),
        )

    def tasks(self, status: str | None = None) -> list[dict]:
        rows = (
            self.query("SELECT * FROM tasks WHERE status=? ORDER BY iteration, rowid", (status,))
            if status
            else self.query("SELECT * FROM tasks ORDER BY iteration, rowid")
        )
        return [self._row_to_task(r) for r in rows]

    def task(self, task_id: str) -> dict | None:
        rows = self.query("SELECT * FROM tasks WHERE id=?", (task_id,))
        return self._row_to_task(rows[0]) if rows else None

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> dict:
        task = dict(row)
        for field in ("files", "depends_on", "acceptance"):
            try:
                task[field] = json.loads(task.get(field) or "[]")
            except Exception:
                task[field] = []
        return task

    # ------------------------------------------------------------------ attempts
    def add_attempt(self, **fields: Any) -> None:
        cols = (
            "task_id",
            "n",
            "role",
            "provider",
            "model",
            "key_id",
            "outcome",
            "detail",
            "input_tokens",
            "output_tokens",
            "cached_tokens",
            "cost_usd",
        )
        values = [fields.get(c, 0 if c.endswith("tokens") or c == "n" else "") for c in cols]
        values.append(now())
        self.execute(
            f"INSERT INTO attempts({','.join(cols)}, created_at) VALUES({','.join('?' * (len(cols) + 1))})",
            values,
        )

    def attempts(self, task_id: str) -> list[dict]:
        return [dict(r) for r in self.query("SELECT * FROM attempts WHERE task_id=? ORDER BY n", (task_id,))]

    # ------------------------------------------------------------------ keys
    def sync_key(self, key_id: str, provider: str, fingerprint: str, budget: float) -> dict:
        rows = self.query("SELECT * FROM keys WHERE id=?", (key_id,))
        if rows:
            row = dict(rows[0])
            if row["fingerprint"] != fingerprint:
                # Same slot, new secret → the operator swapped the key: reset the budget.
                self.execute(
                    "UPDATE keys SET fingerprint=?, budget_credits=?, spent_credits=0, spent_usd=0,"
                    " tokens=0, calls=0, status='live', last_error='', updated_at=? WHERE id=?",
                    (fingerprint, budget, now(), key_id),
                )
                row.update(
                    fingerprint=fingerprint,
                    budget_credits=budget,
                    spent_credits=0.0,
                    spent_usd=0.0,
                    status="live",
                    last_error="",
                )
            elif abs(float(row["budget_credits"]) - budget) > 1e-9:
                self.execute(
                    "UPDATE keys SET budget_credits=?, updated_at=? WHERE id=?", (budget, now(), key_id)
                )
                row["budget_credits"] = budget
            return row
        self.execute(
            "INSERT INTO keys(id, provider, fingerprint, budget_credits, updated_at) VALUES(?,?,?,?,?)",
            (key_id, provider, fingerprint, budget, now()),
        )
        return dict(self.query("SELECT * FROM keys WHERE id=?", (key_id,))[0])

    def record_key_usage(self, key_id: str, credits: float, usd: float, tokens: int) -> None:
        self.execute(
            "UPDATE keys SET spent_credits=spent_credits+?, spent_usd=spent_usd+?, tokens=tokens+?,"
            " calls=calls+1, updated_at=? WHERE id=?",
            (credits, usd, tokens, now(), key_id),
        )

    def set_key_status(self, key_id: str, status: str, error: str = "") -> None:
        self.execute(
            "UPDATE keys SET status=?, last_error=?, updated_at=? WHERE id=?",
            (status, error[:500], now(), key_id),
        )

    def keys(self) -> list[dict]:
        return [dict(r) for r in self.query("SELECT * FROM keys ORDER BY provider, id")]

    # ------------------------------------------------------------------ events
    def add_event(self, kind: str, title: str, body: str = "") -> None:
        self.execute(
            "INSERT INTO events(kind, title, body, created_at) VALUES(?,?,?,?)",
            (kind, title, body, now()),
        )

    def events(self, limit: int = 50) -> list[dict]:
        rows = self.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) | {"stamp": utc_stamp(r["created_at"])} for r in rows]

    # ------------------------------------------------------------------ aggregates
    def totals(self) -> dict:
        row = self.query(
            "SELECT COALESCE(SUM(cost_usd),0) AS usd, COALESCE(SUM(input_tokens+output_tokens),0) AS tokens,"
            " COALESCE(SUM(cached_tokens),0) AS cached, COUNT(*) AS calls FROM attempts"
        )[0]
        return {
            "cost_usd": float(row["usd"]),
            "tokens": int(row["tokens"]),
            "cached_tokens": int(row["cached"]),
            "calls": int(row["calls"]),
        }
