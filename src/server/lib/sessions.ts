/**
 * Sessions are opaque random tokens. The database stores only their SHA-256 hash, so a
 * database leak does not hand the attacker a set of live sessions. Tokens are bound to
 * nothing else: no IP pinning, because pinning requires storing addresses.
 *
 * A session ends in three ways, and all three are enforced here rather than promised in
 * a document:
 *
 *   * **absolute** — `expires_at`, set once at creation and never extended. Thirty days
 *     after you signed in you sign in again, however busy you were;
 *   * **idle** — `last_seen_day`. A session nobody has used for `idleDays` is deleted the
 *     next time its cookie shows up. The column was already written and displayed before
 *     this change, but nothing read it, so an abandoned session lived its full TTL;
 *   * **explicit** — logout, "sign out everywhere", a password change, a recovery, or the
 *     operator's break-glass tool.
 *
 * The token also rotates once a day (ADR-0038), which is the same write that already
 * updated `last_seen_day`.
 */
import type { Db } from "../db/index.ts";
import { newId, randomToken, sha256 } from "./ids.ts";
import { today } from "./time.ts";

/**
 * How long the previous token stays acceptable after a rotation. It covers requests that
 * were already in flight when the cookie changed, and nothing else: a minute is far more
 * than a page load and far less than useful to someone replaying a captured cookie.
 */
const ROTATION_GRACE_MS = 60_000;

export interface SessionUser {
  id: string;
  username: string;
  role: "user" | "moderator" | "admin";
  status: "active" | "suspended";
  sessionId: string;
  /**
   * Set only on the request that rotated the token: the caller must send it back as a
   * cookie, or the browser keeps a value that is about to stop working.
   */
  rotatedToken?: string;
  /** Seconds left of the absolute lifetime, for the rotated cookie's `Max-Age`. */
  rotatedMaxAgeSeconds?: number;
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
    `INSERT INTO sessions (id, user_id, token_hash, label, created_at, expires_at,
                           last_seen_day, rotated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [newId(), userId, sha256(token), label, now, expiresAt, today(now), now],
  );
  return { token, expiresAt };
}

export async function resolveSession(
  db: Db,
  token: string,
  idleDays: number,
  now = Date.now(),
): Promise<SessionUser | null> {
  const hash = sha256(token);
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
      WHERE s.token_hash = ?
         OR (s.previous_token_hash = ? AND s.rotated_at > ?)`,
    [hash, hash, now - ROTATION_GRACE_MS],
  );
  if (!row) return null;
  if (row.expires_at <= now) {
    await db.run("DELETE FROM sessions WHERE id = ?", [row.session_id]);
    return null;
  }
  // Idle expiry. Day granularity: enough to end an abandoned session, useless as an
  // activity timeline — which is why the column is a day and not a timestamp.
  if (today(now) - row.last_seen_day > idleDays) {
    await db.run("DELETE FROM sessions WHERE id = ?", [row.session_id]);
    return null;
  }

  const user: SessionUser = {
    id: row.user_id,
    username: row.username,
    role: row.role,
    status: row.status,
    sessionId: row.session_id,
  };

  if (row.last_seen_day !== today(now)) {
    // One write a day per session, and it now carries a new token as well as the date.
    // The old hash is kept for the grace window so that a request already on the wire
    // does not come back 401.
    // Compare-and-swap on the hash that was presented. A page load fires several requests
    // at once, and the first one after midnight found them all rotating: each wrote its own
    // new token, the last writer won, and whichever cookie the browser kept was — more often
    // than not — a token no row held, so the session died after the grace window
    // (SEC-2026-017). Now only the request that still matches the row's current hash
    // rotates; the others keep using the token they have, which the grace clause above
    // continues to accept.
    const rotated = randomToken(32);
    const won = await db.get<{ id: string }>(
      `UPDATE sessions
          SET token_hash = ?, previous_token_hash = ?, rotated_at = ?, last_seen_day = ?
        WHERE id = ? AND token_hash = ? AND last_seen_day = ?
        RETURNING id`,
      [sha256(rotated), hash, now, today(now), row.session_id, hash, row.last_seen_day],
    );
    if (won) {
      user.rotatedToken = rotated;
      user.rotatedMaxAgeSeconds = Math.floor((row.expires_at - now) / 1000);
    }
  }
  return user;
}

export async function destroySession(db: Db, sessionId: string): Promise<void> {
  await db.run("DELETE FROM sessions WHERE id = ?", [sessionId]);
}

export async function destroyAllSessions(db: Db, userId: string): Promise<void> {
  await db.run("DELETE FROM sessions WHERE user_id = ?", [userId]);
}

/**
 * Everything that could still let somebody in, gone in one transaction (ADR-0089).
 *
 * "Sign out everywhere" ends sessions. It does not end the two other credentials that mint
 * one: an authentication challenge already issued and waiting for a signature, and a
 * device-link code parked for the next browser to redeem. After a recovery or a password
 * change those are exactly the leftovers an attacker would be holding, so a credential
 * rotation revokes all three or it does not mean what it says.
 *
 * What this cannot revoke, stated rather than implied: unspent **send tokens**. They carry
 * no owner by design (ADR-0084) — the table has no column that could be joined to an
 * account — so the price of sealed sender is that a stolen token can still post an envelope
 * until it expires. It cannot read anything, and it cannot become a session.
 */
export async function revokeAllCredentials(db: Db, userId: string): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.run("DELETE FROM sessions WHERE user_id = ?", [userId]);
    await tx.run("DELETE FROM auth_challenges WHERE user_id = ?", [userId]);
    await tx.run("DELETE FROM device_links WHERE user_id = ?", [userId]);
  });
}

/**
 * The same revocation, with one exception: the session that asked for it (ADR-0102).
 *
 * A change to the second factor — enrolling a PGP key, rotating it, removing it, replacing
 * the recovery key — is a credential rotation, so the sessions minted under the old one have
 * to end (point 131). What it is not is a reason to sign the user out of the browser they
 * are sitting in front of: that caller has just proved the password *and* a signature from
 * the key being replaced, which is the strongest proof this system accepts, and a rotation
 * that logs you out is a rotation people postpone.
 *
 * Challenges and device-link codes are taken whatever session they belong to: neither is a
 * session, and both were minted under the credential that just changed.
 */
export async function revokeOtherCredentials(
  db: Db,
  userId: string,
  keepSessionId: string,
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.run("DELETE FROM sessions WHERE user_id = ? AND id <> ?", [userId, keepSessionId]);
    await tx.run("DELETE FROM auth_challenges WHERE user_id = ?", [userId]);
    await tx.run("DELETE FROM device_links WHERE user_id = ?", [userId]);
  });
}

/** Housekeeping: absolute expiry and idle expiry, without waiting for a cookie to arrive. */
export async function pruneSessions(db: Db, idleDays: number, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM sessions WHERE expires_at < ? OR last_seen_day < ?", [
    now,
    today(now) - idleDays,
  ]);
}
