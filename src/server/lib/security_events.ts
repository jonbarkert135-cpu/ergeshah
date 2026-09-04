/**
 * The account's own security history (ADR-0090).
 *
 * Distinct from `lib/audit.ts`, which records what *staff* did to other people. This
 * records what happened to one account, is readable only by its owner, and is written for
 * the events a person could recognise as not theirs: a sign-in, a failed sign-in, a
 * password change, a key change, a recovery, a session ending.
 *
 * Three rules keep it from becoming an activity log:
 *
 * 1. **Kinds are a closed list.** No free text, no subject, no counterparty.
 * 2. **The clock is a day.** Two sign-ins on the same day are one row with a count of two;
 *    the order they happened in is not recorded, because that is a timeline.
 * 3. **It expires.** `pruneSecurityEvents` deletes rows past the retention window, which is
 *    90 days by default — long enough to notice a stranger, short enough not to be a file.
 *
 * Nothing here is ever written for another account: the subject of an event is always the
 * account it belongs to, so this table cannot answer "who tried to reach whom".
 */
import type { Db } from "../db/index.ts";
import { today } from "./time.ts";

export type SecurityEventKind =
  /** A session was created with a password (and nothing else was required). */
  | "login.password"
  /** A session was created after a PGP signature verified. */
  | "login.pgp"
  /** A password was offered for this account and refused. */
  | "login.failed"
  /** A session was created by redeeming a device-link code. */
  | "login.device"
  /** The account password changed, which also ends every other session. */
  | "password.changed"
  /** A PGP key was enrolled on an account that had none. */
  | "pgp.enrolled"
  /** A PGP key was replaced, proven by the key being replaced. */
  | "pgp.rotated"
  /** The PGP factor was turned off, proven by the key being removed. */
  | "pgp.removed"
  /** A recovery phrase was attached or replaced. */
  | "recovery.key_set"
  /** A recovery phrase was used: password rotated, PGP cleared, every session ended. */
  | "recovery.completed"
  /** One session was revoked from the security centre. */
  | "session.revoked"
  /** Every session was ended at once. */
  | "sessions.revoked_all"
  /** A device was revoked from the key directory. */
  | "device.revoked";

/**
 * Record one event. Best-effort by construction: the caller is in the middle of an
 * authentication flow, and a full disk must not turn a valid sign-in into a 500. A failure
 * to write history is logged by the database layer and swallowed here.
 */
export async function recordSecurityEvent(
  db: Db,
  userId: string,
  kind: SecurityEventKind,
  now = Date.now(),
): Promise<void> {
  try {
    await db.run(
      `INSERT INTO security_events (user_id, kind, day, count) VALUES (?, ?, ?, 1)
       ON CONFLICT (user_id, kind, day) DO UPDATE SET count = security_events.count + 1`,
      [userId, kind, today(now)],
    );
  } catch {
    // Deliberately silent: see above. The event is worth less than the flow it is part of.
  }
}

export interface SecurityEventRow {
  kind: string;
  day: number;
  count: number;
}

/** Newest first, bounded, and only ever for the caller's own account. */
export async function listSecurityEvents(
  db: Db,
  userId: string,
  limit = 100,
): Promise<SecurityEventRow[]> {
  return db.all<SecurityEventRow>(
    `SELECT kind, day, count FROM security_events WHERE user_id = ?
      ORDER BY day DESC, kind ASC LIMIT ?`,
    [userId, limit],
  );
}

/** Retention, run from housekeeping beside the audit and notification sweeps. */
export async function pruneSecurityEvents(
  db: Db,
  retentionDays: number,
  now = Date.now(),
): Promise<void> {
  await db.run("DELETE FROM security_events WHERE day < ?", [today(now) - retentionDays]);
}
