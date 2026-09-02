/**
 * Sessions are opaque random tokens. The database stores only their SHA-256 hash, so a
 * database leak does not hand the attacker a set of live sessions. Tokens are bound to
 * nothing else: no IP pinning, because pinning requires storing addresses.
 */
import type { Db } from "../db/index.ts";
import { newId, randomToken, sha256 } from "./ids.ts";
import { today } from "./time.ts";

export interface SessionUser {
  id: string;
  username: string;
  role: "user" | "moderator" | "admin";
  status: "active" | "suspended";
  sessionId: string;
}

export async function createSession(
  db: Db,
  userId: string,
  ttlMs: number,
  label: string | null,
): Promise<{ token: string; expiresAt: number }> {
  const token = randomToken(32);
  const now = Date.now();
  const expiresAt = now + ttlMs;
  await db.run(
    `INSERT INTO sessions (id, user_id, token_hash, label, created_at, expires_at, last_seen_day)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [newId(), userId, sha256(token), label, now, expiresAt, today(now)],
  );
  return { token, expiresAt };
}

export async function resolveSession(db: Db, token: string): Promise<SessionUser | null> {
  const row = await db.get<{
    session_id: string;
    user_id: string;
    username: string;
    role: SessionUser["role"];
    status: SessionUser["status"];
    expires_at: number;
    last_seen_day: number;
  }>(
    `SELECT s.id AS session_id, s.expires_at, s.last_seen_day,
            u.id AS user_id, u.username, u.role, u.status
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`,
    [sha256(token)],
  );
  if (!row) return null;
  if (row.expires_at <= Date.now()) {
    await db.run("DELETE FROM sessions WHERE id = ?", [row.session_id]);
    return null;
  }
  // Day granularity: enough to expire idle sessions, useless as an activity timeline.
  if (row.last_seen_day !== today()) {
    await db.run("UPDATE sessions SET last_seen_day = ? WHERE id = ?", [today(), row.session_id]);
  }
  return {
    id: row.user_id,
    username: row.username,
    role: row.role,
    status: row.status,
    sessionId: row.session_id,
  };
}

export async function destroySession(db: Db, sessionId: string): Promise<void> {
  await db.run("DELETE FROM sessions WHERE id = ?", [sessionId]);
}

export async function destroyAllSessions(db: Db, userId: string): Promise<void> {
  await db.run("DELETE FROM sessions WHERE user_id = ?", [userId]);
}

export async function pruneSessions(db: Db, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM sessions WHERE expires_at < ?", [now]);
}
