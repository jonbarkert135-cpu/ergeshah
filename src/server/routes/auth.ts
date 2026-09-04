/**
 * Account identity: registration, login, logout, session management.
 *
 * The server never sees a password — only `authSecret`, the half of the client-side
 * Argon2id output that is meant to be shown to it (see `src/shared/crypto/vault.ts`).
 * The other ways into an account — a second device, a recovery phrase, a PGP key — are
 * their own domain and live in `routes/recovery.ts`.
 */
import type { FastifyInstance } from "fastify";
import { csrfCookie, sessionCookie } from "../app.ts";
import { badRequest, conflict, unauthorized } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { hashAuthSecret, verifyAuthSecret } from "../lib/password.ts";
import {
  createSession,
  destroyAllSessions,
  destroySession,
  pruneSessions,
  revokeAllCredentials,
} from "../lib/sessions.ts";
import {
  listSecurityEvents,
  recordSecurityEvent,
} from "../lib/security_events.ts";
import { today, dayToIsoDate } from "../lib/time.ts";
import {
  asBase64Url,
  asOptionalString,
  asSealedVault,
  asUsername,
} from "../lib/validate.ts";
import { readableFingerprint } from "../lib/pgp.ts";
import { issueChallenge, limitByAccountName, replyWithSession } from "../lib/auth_flow.ts";

interface Credentials {
  username: unknown;
  authSecret: unknown;
  label?: unknown;
  sealedVault?: unknown;
  recoveryPublicKey?: unknown;
}

export async function registerAuthRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  app.post("/api/auth/register", async (request, reply) => {
    // Validate before spending a rate-limit token: a malformed request costs the server
    // nothing, and burning the budget on typos would only punish honest clients.
    const body = (request.body ?? {}) as Credentials;
    const username = asUsername(body.username);
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const label = asOptionalString(body.label, "label", 40) || null;
    const sealedVault = body.sealedVault === undefined ? null : asSealedVault(body.sealedVault);
    const recoveryPublicKey =
      body.recoveryPublicKey === undefined || body.recoveryPublicKey === null
        ? null
        : asBase64Url(body.recoveryPublicKey, "recoveryPublicKey", 32);
    // Work first, then the allowance: an unsolved request has cost the server a hash and
    // must not be able to spend the bucket that protects everybody else (point 71).
    await app.requireWork(request);
    await app.limit(request, "register");

    const existing = await db.get("SELECT id FROM users WHERE username = ?", [username]);
    if (existing) {
      // Usernames are public identifiers on this platform (you message and buy from a
      // name), so registration necessarily reveals that one is taken. Login does not.
      throw conflict("that username is taken", "username_taken");
    }

    const userId = newId();
    const passwordHash = await hashAuthSecret(authSecret);

    // The first account of a fresh deployment is its administrator, and *which* account that
    // is has to be decided by one statement rather than by a read followed by a write.
    // "Is the users table empty?" and then `INSERT` is two statements with no lock between
    // them: on PostgreSQL two registrations arriving in the same instant both saw an empty
    // table and both became administrators (finding SEC-2026-002). The claim is now a row in
    // `bootstrap_claims` whose primary key does the arbitration — the same pattern as the
    // one-time prekey (ADR-0060) — and it is inserted inside the transaction that writes the
    // account, so a registration that fails afterwards releases the claim with it.
    let isFirstUser = false;

    await db.transaction(async (tx) => {
      const claim = await tx.get<{ id: string }>(
        `INSERT INTO bootstrap_claims (id, claimed_at) VALUES ('admin', ?)
         ON CONFLICT (id) DO NOTHING RETURNING id`,
        [Date.now()],
      );
      isFirstUser = Boolean(claim);
      await tx.run(
        `INSERT INTO users (id, username, password_hash, role, status, created_day,
                            recovery_public_key)
         VALUES (?, ?, ?, ?, 'active', ?, ?)`,
        [
          userId,
          username,
          passwordHash,
          isFirstUser ? "admin" : "user",
          today(),
          recoveryPublicKey,
        ],
      );
      if (sealedVault !== null) {
        await tx.run("INSERT INTO vaults (user_id, sealed, updated_day) VALUES (?, ?, ?)", [
          userId,
          sealedVault,
          today(),
        ]);
      }
    });

    const session = await createSession(db, userId, config.sessionTtlMs, label);
    return replyWithSession(reply, request, config, {
      id: userId,
      username,
      role: isFirstUser ? "admin" : "user",
      token: session.token,
      expiresAt: session.expiresAt,
    });
  });

  app.post("/api/auth/login", async (request, reply) => {
    const body = (request.body ?? {}) as Credentials;
    const username = asUsername(body.username);
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const label = asOptionalString(body.label, "label", 40) || null;
    await app.requireWork(request);
    await app.limit(request, "login");
    await limitByAccountName(db, config, username);

    const user = await db.get<{
      id: string;
      username: string;
      password_hash: string;
      role: "user" | "moderator" | "admin";
      status: "active" | "suspended";
      status_reason: string | null;
      pgp_fingerprint: string | null;
    }>(
      `SELECT id, username, password_hash, role, status, status_reason, pgp_fingerprint
       FROM users WHERE username = ?`,
      [username],
    );

    // Constant work whether or not the account exists: no enumeration through timing.
    const ok = await verifyAuthSecret(user?.password_hash ?? null, authSecret);
    if (!user || !ok) {
      // Recorded against the account that was targeted, never against the name that was
      // guessed: an account that does not exist gets no row, so this cannot become a list
      // of usernames strangers tried.
      if (user) await recordSecurityEvent(db, user.id, "login.failed");
      throw unauthorized("invalid username or password");
    }
    if (user.status !== "active") {
      throw unauthorized(`account suspended: ${user.status_reason ?? "contact moderation"}`);
    }

    // Second factor: the password was right, but the account asks for a PGP signature
    // too, so no session is created yet. The challenge row records that the password step
    // already passed — it is the only thing that lets the next request mint a session.
    if (user.pgp_fingerprint) {
      const issued = await issueChallenge(db, config, "pgp-login", user.id);
      return {
        pgpRequired: true,
        ...issued,
        fingerprint: readableFingerprint(user.pgp_fingerprint),
      };
    }

    const session = await createSession(db, user.id, config.sessionTtlMs, label);
    await recordSecurityEvent(db, user.id, "login.password");
    await pruneSessions(db, config.sessionIdleDays);
    const vault = await db.get<{ sealed: string }>(
      "SELECT sealed FROM vaults WHERE user_id = ?",
      [user.id],
    );
    return replyWithSession(reply, request, config, {
      id: user.id,
      username: user.username,
      role: user.role,
      token: session.token,
      expiresAt: session.expiresAt,
      sealedVault: vault ? JSON.parse(vault.sealed) : null,
    });
  });

  app.post("/api/auth/logout", async (request, reply) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    await destroySession(db, user.sessionId);
    reply.header("set-cookie", [
      sessionCookie(config, request, "", 0),
      csrfCookie(config, request, "", 0),
    ]);
    return { ok: true };
  });

  app.post("/api/auth/logout-everywhere", async (request, reply) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    await destroyAllSessions(db, user.id);
    await recordSecurityEvent(db, user.id, "sessions.revoked_all");
    reply.header("set-cookie", [sessionCookie(config, request, "", 0), csrfCookie(config, request, "", 0)]);
    return { ok: true };
  });

  /**
   * Change the password.
   *
   * The password does two jobs: it authenticates to the server and it seals the vault
   * that holds the user's private keys. Moving one without the other would lock the user
   * out of their own conversations, so the new hash and the re-sealed vault are written
   * in one transaction, and every other session is dropped: they were authorised under
   * a password that no longer exists.
   */
  app.post("/api/auth/password", async (request, reply) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as {
      currentAuthSecret?: unknown;
      newAuthSecret?: unknown;
      sealedVault?: unknown;
    };
    const currentAuthSecret = asBase64Url(body.currentAuthSecret, "currentAuthSecret", 64);
    const newAuthSecret = asBase64Url(body.newAuthSecret, "newAuthSecret", 64);
    await app.limit(request, "login");

    const row = await db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = ?",
      [user.id],
    );
    if (!(await verifyAuthSecret(row?.password_hash ?? null, currentAuthSecret))) {
      throw unauthorized("current password is wrong");
    }

    const hasVault = await db.get("SELECT user_id FROM vaults WHERE user_id = ?", [user.id]);
    if (hasVault && body.sealedVault === undefined) {
      throw badRequest(
        "sealedVault is required: the vault must be re-sealed with the new password",
        "vault_required",
      );
    }
    const sealedVault = body.sealedVault === undefined ? null : asSealedVault(body.sealedVault);
    const passwordHash = await hashAuthSecret(newAuthSecret);

    await db.transaction(async (tx) => {
      await tx.run("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, user.id]);
      if (sealedVault !== null) {
        await tx.run(
          hasVault
            ? "UPDATE vaults SET sealed = ?, updated_day = ? WHERE user_id = ?"
            : "INSERT INTO vaults (sealed, updated_day, user_id) VALUES (?, ?, ?)",
          [sealedVault, today(), user.id],
        );
      }
    });

    // Not just the sessions: a challenge already issued and a parked device-link code are
    // both credentials minted under the old password (ADR-0089).
    await revokeAllCredentials(db, user.id);
    await recordSecurityEvent(db, user.id, "password.changed");
    const session = await createSession(db, user.id, config.sessionTtlMs, null);
    return replyWithSession(reply, request, config, {
      id: user.id,
      username: user.username,
      role: user.role,
      token: session.token,
      expiresAt: session.expiresAt,
    });
  });

  /**
   * Delete the account, for real.
   *
   * Everything that belongs to the account goes: sessions, the sealed vault, devices and
   * their prekeys, undelivered envelopes, listings, orders, reviews and reports all
   * cascade from the `users` row. Three kinds of reference do not belong to the account
   * and are unlinked instead of deleted — moderation decisions, resolved reports and
   * audit entries stay, minus the identity of who made them, so a deletion cannot erase
   * the record that a moderator acted.
   *
   * The username becomes available again. That is a deliberate reading of "delete": we
   * keep no tombstone. The cost is that a later account can take the name, which is why
   * identity is verified by key and not by name — see docs/THREAT_MODEL.md.
   */
  app.post("/api/auth/delete", async (request, reply) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as { authSecret?: unknown };
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    await app.limit(request, "sensitive");

    const row = await db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = ?",
      [user.id],
    );
    if (!(await verifyAuthSecret(row?.password_hash ?? null, authSecret))) {
      throw unauthorized("password is wrong");
    }

    // Money first. Deleting an account is allowed to destroy data — that is the point — but
    // it must not destroy value: the balance rows cascade from `users`, so a deletion with a
    // balance on it would quietly keep the money. The owner is told to empty the account,
    // which is the one thing this server cannot do on their behalf (it has no spend key, and
    // no address to send to).
    const balance = await db.get<{ available_pico: number; held_pico: number }>(
      "SELECT available_pico, held_pico FROM balances WHERE account_id = ?",
      [user.id],
    );
    if ((balance?.available_pico ?? 0) > 0 || (balance?.held_pico ?? 0) > 0) {
      throw conflict(
        "withdraw your balance and let your open orders finish before deleting the account",
        "balance_not_empty",
      );
    }
    // Other people's money next. The balance above is the deleter's own; on an open order
    // the escrow is held on the *buyer's* account, so a seller with open orders has nothing
    // held and would pass the check — and `orders` cascades from `users`, so the buyers'
    // hold would be left with no order to settle or release it against (SEC-2026-009).
    // Either side of an order that has not finished stays until it has.
    const open = await db.get<{ count: number }>(
      `SELECT COUNT(*) AS count FROM orders
        WHERE (buyer_user_id = ? OR seller_user_id = ?)
          AND status IN ('placed', 'accepted', 'delivered', 'disputed')`,
      [user.id, user.id],
    );
    if (Number(open?.count ?? 0) > 0) {
      throw conflict(
        "let your open orders finish (or cancel them) before deleting the account",
        "orders_open",
      );
    }

    await db.transaction(async (tx) => {
      await tx.run("UPDATE audit_log SET actor_user_id = NULL WHERE actor_user_id = ?", [user.id]);
      await tx.run("UPDATE reports SET resolved_by = NULL WHERE resolved_by = ?", [user.id]);
      await tx.run("UPDATE seller_applications SET decided_by = NULL WHERE decided_by = ?", [
        user.id,
      ]);
      // Order events name the actor and cannot be null; the order keeps its status.
      await tx.run("DELETE FROM order_events WHERE actor_user_id = ?", [user.id]);
      await tx.run("DELETE FROM users WHERE id = ?", [user.id]);
    });

    reply.header("set-cookie", [sessionCookie(config, request, "", 0), csrfCookie(config, request, "", 0)]);
    return { ok: true };
  });

  /**
   * Authorise a new device (called by a device that is already signed in).
   *
   * The new device shows a code containing its public bundle and a secret. This device
   * publishes the bundle through /api/keys/device, then parks a one-time authorisation
   * here under SHA-256 of the secret. No session token is stored: the session is minted
   * when the new device redeems the row, and the row is deleted in the same transaction.
   */
  app.get("/api/auth/me", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const row = await db.get<{
      created_day: number;
      recovery_public_key: string | null;
      pgp_fingerprint: string | null;
    }>(
      "SELECT created_day, recovery_public_key, pgp_fingerprint FROM users WHERE id = ?",
      [user.id],
    );
    const seller = await db.get<{ display_name: string; status: string }>(
      "SELECT display_name, status FROM sellers WHERE user_id = ?",
      [user.id],
    );
    return {
      id: user.id,
      username: user.username,
      role: user.role,
      recoveryConfigured: Boolean(row?.recovery_public_key),
      pgpFingerprint: row?.pgp_fingerprint ? readableFingerprint(row.pgp_fingerprint) : null,
      memberSince: row ? dayToIsoDate(row.created_day) : null,
      seller: seller ? { displayName: seller.display_name, status: seller.status } : null,
    };
  });

  /**
   * The account's own security history (ADR-0090). Day-granular counts of a fixed list of
   * events, for the owner and nobody else: there is no staff route that reads this table,
   * because "let a moderator see when you signed in" is the surveillance feature this log
   * was designed not to be.
   */
  app.get("/api/auth/security-events", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const rows = await listSecurityEvents(db, user.id);
    return {
      retentionDays: config.securityEventRetentionDays,
      events: rows.map((row) => ({
        kind: row.kind,
        on: dayToIsoDate(row.day),
        count: row.count,
      })),
    };
  });

  app.get("/api/auth/sessions", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const rows = await db.all<{
      id: string;
      label: string | null;
      created_at: number;
      expires_at: number;
      last_seen_day: number;
    }>(
      "SELECT id, label, created_at, expires_at, last_seen_day FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
      [user.id],
    );
    return {
      sessions: rows.map((row) => ({
        id: row.id,
        label: row.label,
        current: row.id === user.sessionId,
        createdOn: dayToIsoDate(Math.floor(row.created_at / 86_400_000)),
        lastSeenOn: dayToIsoDate(row.last_seen_day),
        expiresOn: dayToIsoDate(Math.floor(row.expires_at / 86_400_000)),
      })),
    };
  });

  app.delete("/api/auth/sessions/:id", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const { id } = request.params as { id: string };
    const row = await db.get<{ id: string }>(
      "SELECT id FROM sessions WHERE id = ? AND user_id = ?",
      [id, user.id],
    );
    if (!row) throw badRequest("no such session", "not_found");
    await destroySession(db, id);
    await recordSecurityEvent(db, user.id, "session.revoked");
    return { ok: true };
  });
}
