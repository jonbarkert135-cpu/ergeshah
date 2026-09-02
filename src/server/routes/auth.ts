/**
 * Account identity: registration, login, logout, session management.
 *
 * The server never sees a password — only `authSecret`, the half of the client-side
 * Argon2id output that is meant to be shown to it (see `src/shared/crypto/vault.ts`).
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { csrfCookie, sessionCookie } from "../app.ts";
import { badRequest, conflict, unauthorized } from "../lib/errors.ts";
import { newId, randomToken, sha256 } from "../lib/ids.ts";
import { hashAuthSecret, verifyAuthSecret } from "../lib/password.ts";
import {
  createSession,
  destroyAllSessions,
  destroySession,
  pruneSessions,
} from "../lib/sessions.ts";
import { today, dayToIsoDate } from "../lib/time.ts";
import {
  asBase64Url,
  asId,
  asOptionalString,
  asOptionalText,
  asSealedVault,
  asUsername,
} from "../lib/validate.ts";
import { verifyEd25519 } from "../lib/signatures.ts";
import {
  inspectPublicKey,
  PgpError,
  readableFingerprint,
  verifyDetachedSignature,
} from "../lib/pgp.ts";

/** Long enough to walk to the other device, short enough that a photographed screen ages out. */
const LINK_TTL_MS = 5 * 60 * 1000;
/** Long enough to paste a phrase and sign, short enough to be useless if intercepted. */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

interface Credentials {
  username: unknown;
  authSecret: unknown;
  label?: unknown;
  sealedVault?: unknown;
  recoveryPublicKey?: unknown;
}

export async function registerAuthRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  /**
   * Take a challenge out of the table, once. Expired rows go with it. The row is deleted
   * whether or not the signature that follows turns out to be valid, so a challenge
   * cannot be ground against offline guesses, and a valid signature cannot be replayed.
   */
  async function consumeChallenge(
    id: string,
    kind: "recovery" | "pgp-enroll" | "pgp-login",
  ): Promise<{ user_id: string; challenge: string } | null> {
    return db.transaction(async (tx) => {
      await tx.run("DELETE FROM auth_challenges WHERE expires_at < ?", [Date.now()]);
      const row = await tx.get<{ user_id: string; challenge: string }>(
        "SELECT user_id, challenge FROM auth_challenges WHERE id = ? AND kind = ?",
        [id, kind],
      );
      if (!row) return null;
      await tx.run("DELETE FROM auth_challenges WHERE id = ?", [id]);
      return row;
    });
  }

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
    await app.limit(request, "register");

    const existing = await db.get("SELECT id FROM users WHERE username = ?", [username]);
    if (existing) {
      // Usernames are public identifiers on this platform (you message and buy from a
      // name), so registration necessarily reveals that one is taken. Login does not.
      throw conflict("that username is taken", "username_taken");
    }

    const userId = newId();
    const passwordHash = await hashAuthSecret(authSecret);
    const isFirstUser = !(await db.get("SELECT id FROM users LIMIT 1"));

    await db.transaction(async (tx) => {
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
    await app.limit(request, "login");

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
    if (!user || !ok) throw unauthorized("invalid username or password");
    if (user.status !== "active") {
      throw unauthorized(`account suspended: ${user.status_reason ?? "contact moderation"}`);
    }

    // Second factor: the password was right, but the account asks for a PGP signature
    // too, so no session is created yet. The challenge row records that the password step
    // already passed — it is the only thing that lets the next request mint a session.
    if (user.pgp_fingerprint) {
      const challenge = randomToken(32);
      const id = newId();
      await db.run(
        `INSERT INTO auth_challenges (id, user_id, kind, challenge, expires_at)
         VALUES (?, ?, 'pgp-login', ?, ?)`,
        [id, user.id, challenge, Date.now() + CHALLENGE_TTL_MS],
      );
      return {
        pgpRequired: true,
        challengeId: id,
        challenge,
        fingerprint: readableFingerprint(user.pgp_fingerprint),
        expiresInSeconds: CHALLENGE_TTL_MS / 1000,
      };
    }

    const session = await createSession(db, user.id, config.sessionTtlMs, label);
    await pruneSessions(db);
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
    await destroySession(db, user.sessionId);
    reply.header("set-cookie", [
      sessionCookie(config, request, "", 0),
      csrfCookie(config, request, "", 0),
    ]);
    return { ok: true };
  });

  app.post("/api/auth/logout-everywhere", async (request, reply) => {
    const user = await app.authenticate(request);
    await destroyAllSessions(db, user.id);
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

    await destroyAllSessions(db, user.id);
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
  app.post("/api/auth/link", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const body = (request.body ?? {}) as { linkHash?: unknown; label?: unknown };
    const linkHash = asBase64Url(body.linkHash, "linkHash", 32);
    const label = asOptionalString(body.label, "label", 40) || null;

    await db.run(
      `INSERT INTO device_links (link_hash, user_id, label, expires_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (link_hash) DO UPDATE SET expires_at = excluded.expires_at`,
      [linkHash, user.id, label, Date.now() + LINK_TTL_MS],
    );
    return { expiresInSeconds: LINK_TTL_MS / 1000 };
  });

  /**
   * Redeem the authorisation. Unauthenticated by necessity — the secret *is* the
   * credential — so it is rate-limited, single-use and short-lived.
   */
  app.post("/api/auth/link/claim", async (request, reply) => {
    const body = (request.body ?? {}) as { linkSecret?: unknown };
    const linkSecret = asBase64Url(body.linkSecret, "linkSecret", 32);
    await app.limit(request, "sensitive");

    const claimed = await db.transaction(async (tx) => {
      await tx.run("DELETE FROM device_links WHERE expires_at < ?", [Date.now()]);
      const row = await tx.get<{ link_hash: string; user_id: string; label: string | null }>(
        "SELECT link_hash, user_id, label FROM device_links WHERE link_hash = ?",
        [sha256(Buffer.from(linkSecret, "base64url"))],
      );
      if (!row) return null;
      // Deleted before the session exists: a replay of the same code finds nothing.
      await tx.run("DELETE FROM device_links WHERE link_hash = ?", [row.link_hash]);
      return row;
    });
    if (!claimed) throw unauthorized("this link code is unknown, expired or already used");

    const user = await db.get<{ id: string; username: string; role: string; status: string }>(
      "SELECT id, username, role, status FROM users WHERE id = ?",
      [claimed.user_id],
    );
    if (!user || user.status !== "active") throw unauthorized("account is not active");

    const session = await createSession(db, user.id, config.sessionTtlMs, claimed.label);
    return replyWithSession(reply, request, config, {
      id: user.id,
      username: user.username,
      role: user.role,
      token: session.token,
      expiresAt: session.expiresAt,
    });
  });

  /**
   * Recovery, step one: hand out a challenge to sign.
   *
   * A challenge is returned for *every* username, whether or not the account exists or
   * has a recovery key. Otherwise this endpoint would answer "does this account exist?"
   * to anyone who asks, and no rate limit fixes an oracle.
   */
  app.post("/api/auth/recovery/challenge", async (request) => {
    const body = (request.body ?? {}) as { username?: unknown };
    const username = asUsername(body.username);
    await app.limit(request, "recovery");

    const user = await db.get<{ id: string; recovery_public_key: string | null }>(
      "SELECT id, recovery_public_key FROM users WHERE username = ? AND status = 'active'",
      [username],
    );
    const challenge = randomToken(32);
    const id = newId();
    // A row is only written for accounts that can actually answer; unknown usernames get
    // a well-formed challenge that will never verify.
    if (user?.recovery_public_key) {
      await db.run(
        `INSERT INTO auth_challenges (id, user_id, kind, challenge, expires_at)
         VALUES (?, ?, 'recovery', ?, ?)`,
        [id, user.id, challenge, Date.now() + CHALLENGE_TTL_MS],
      );
    }
    return { challengeId: id, challenge, expiresInSeconds: CHALLENGE_TTL_MS / 1000 };
  });

  /**
   * Recovery, step two: prove the phrase, set a new password, keep the vault.
   *
   * The signature is over the challenge bytes, made by the Ed25519 key the client derives
   * from the recovery phrase; the server holds only the public half. On success the
   * password hash and the vault backup are replaced in one transaction and *every* session
   * is destroyed — a recovery is exactly the moment to assume the old ones are hostile.
   */
  app.post("/api/auth/recovery/complete", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const challengeId = asId(body.challengeId, "challengeId");
    const signature = asBase64Url(body.signature, "signature", 64);
    const newAuthSecret = asBase64Url(body.newAuthSecret, "newAuthSecret", 64);
    await app.limit(request, "recovery");

    const claimed = await consumeChallenge(challengeId, "recovery");
    if (!claimed) throw unauthorized("that recovery challenge is unknown or expired");

    const user = await db.get<{
      id: string;
      username: string;
      role: string;
      status: string;
      recovery_public_key: string | null;
    }>(
      "SELECT id, username, role, status, recovery_public_key FROM users WHERE id = ?",
      [claimed.user_id],
    );
    if (!user?.recovery_public_key || user.status !== "active") {
      throw unauthorized("recovery is not available for this account");
    }
    const valid = verifyEd25519(
      Buffer.from(user.recovery_public_key, "base64url"),
      Buffer.from(claimed.challenge, "utf8"),
      Buffer.from(signature, "base64url"),
    );
    if (!valid) throw unauthorized("that signature does not match this account");

    // The password moves now; the vault backup is handed back untouched so the client can
    // unwrap the master key with the phrase and rewrap it under the new password. If that
    // second step fails the account is still reachable and recovery still works, which is
    // why the rewrap is not attempted here with material the server must never hold.
    // The phrase also clears a PGP factor: someone recovering an account has lost their
    // password, and there is no reason to assume they still hold the signing key. Leaving
    // the factor in place would turn a recoverable account into an unreachable one. Stated
    // as a consequence, not hidden: a recovery phrase outranks the second factor.
    const passwordHash = await hashAuthSecret(newAuthSecret);
    await db.run(
      "UPDATE users SET password_hash = ?, pgp_public_key = NULL, pgp_fingerprint = NULL WHERE id = ?",
      [passwordHash, user.id],
    );
    await destroyAllSessions(db, user.id);
    const vault = await db.get<{ sealed: string }>("SELECT sealed FROM vaults WHERE user_id = ?", [
      user.id,
    ]);

    const session = await createSession(db, user.id, config.sessionTtlMs, "recovered");
    return replyWithSession(reply, request, config, {
      id: user.id,
      username: user.username,
      role: user.role,
      token: session.token,
      expiresAt: session.expiresAt,
      sealedVault: vault ? JSON.parse(vault.sealed) : null,
    });
  });

  /**
   * PGP, step one of enrolment: a challenge to sign with the key being added.
   *
   * Requires a session, because this is an account setting rather than a way in. The
   * point is proof of possession: a key whose private half the user cannot actually use
   * would turn the second factor into a locked door with no key behind it.
   */
  app.post("/api/auth/pgp/challenge", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const challenge = randomToken(32);
    const id = newId();
    await db.run(
      `INSERT INTO auth_challenges (id, user_id, kind, challenge, expires_at)
       VALUES (?, ?, 'pgp-enroll', ?, ?)`,
      [id, user.id, challenge, Date.now() + CHALLENGE_TTL_MS],
    );
    return { challengeId: id, challenge, expiresInSeconds: CHALLENGE_TTL_MS / 1000 };
  });

  /**
   * PGP, step two of enrolment: the public key, the current password, and a signature
   * over the challenge from step one. All three, because adding a second factor is worth
   * as much as the weakest check that lets you add it.
   */
  app.post("/api/auth/pgp/key", async (request) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const publicKey = asOptionalText(body.publicKey, "publicKey", 64 * 1024);
    const challengeId = asId(body.challengeId, "challengeId");
    const signature = asOptionalText(body.signature, "signature", 64 * 1024);
    if (!publicKey || !signature) throw badRequest("publicKey and signature are required");
    await app.limit(request, "sensitive");

    const row = await db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = ?",
      [user.id],
    );
    if (!(await verifyAuthSecret(row?.password_hash ?? null, authSecret))) {
      throw unauthorized("password is wrong");
    }

    const claimed = await consumeChallenge(challengeId, "pgp-enroll");
    if (!claimed || claimed.user_id !== user.id) {
      throw unauthorized("that challenge is unknown or expired");
    }

    let facts;
    try {
      facts = await inspectPublicKey(publicKey);
    } catch (error) {
      if (error instanceof PgpError) throw badRequest(error.message);
      throw error;
    }
    if (!(await verifyDetachedSignature(publicKey, claimed.challenge, signature))) {
      throw badRequest("that signature does not match the challenge and this key");
    }

    await db.run("UPDATE users SET pgp_public_key = ?, pgp_fingerprint = ? WHERE id = ?", [
      publicKey.trim(),
      facts.fingerprint,
      user.id,
    ]);
    return { fingerprint: facts.readable, algorithm: facts.algorithm, identities: facts.identities };
  });

  /**
   * PGP, step two of login: the signature that the password alone no longer replaces.
   *
   * The challenge row is the proof that the password step passed; consuming it is what
   * mints the session. It is deleted whether or not the signature verifies.
   */
  app.post("/api/auth/pgp/complete", async (request, reply) => {
    const body = (request.body ?? {}) as Record<string, unknown>;
    const challengeId = asId(body.challengeId, "challengeId");
    const signature = asOptionalText(body.signature, "signature", 64 * 1024);
    const label = asOptionalString(body.label, "label", 40) || null;
    if (!signature) throw badRequest("signature is required");
    await app.limit(request, "sensitive");

    const claimed = await consumeChallenge(challengeId, "pgp-login");
    if (!claimed) throw unauthorized("that challenge is unknown or expired");

    const user = await db.get<{
      id: string;
      username: string;
      role: string;
      status: string;
      pgp_public_key: string | null;
    }>(
      "SELECT id, username, role, status, pgp_public_key FROM users WHERE id = ?",
      [claimed.user_id],
    );
    if (!user?.pgp_public_key || user.status !== "active") {
      throw unauthorized("that challenge is unknown or expired");
    }
    if (!(await verifyDetachedSignature(user.pgp_public_key, claimed.challenge, signature))) {
      throw unauthorized("that signature does not match this account's key");
    }

    const session = await createSession(db, user.id, config.sessionTtlMs, label);
    await pruneSessions(db);
    const vault = await db.get<{ sealed: string }>("SELECT sealed FROM vaults WHERE user_id = ?", [
      user.id,
    ]);
    return replyWithSession(reply, request, config, {
      id: user.id,
      username: user.username,
      role: user.role,
      token: session.token,
      expiresAt: session.expiresAt,
      sealedVault: vault ? JSON.parse(vault.sealed) : null,
    });
  });

  /**
   * Turn the second factor off. The current password is required, and every other session
   * is left alone: this removes a factor from future logins, it does not touch the vault.
   */
  app.post("/api/auth/pgp/remove", async (request) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    await app.limit(request, "sensitive");
    const row = await db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = ?",
      [user.id],
    );
    if (!(await verifyAuthSecret(row?.password_hash ?? null, authSecret))) {
      throw unauthorized("password is wrong");
    }
    await db.run(
      "UPDATE users SET pgp_public_key = NULL, pgp_fingerprint = NULL WHERE id = ?",
      [user.id],
    );
    return { ok: true };
  });

  /** Set or replace the recovery public key. Requires the current password, not a session alone. */
  app.post("/api/auth/recovery/key", async (request) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const recoveryPublicKey = asBase64Url(body.recoveryPublicKey, "recoveryPublicKey", 32);
    const sealedVault = body.sealedVault === undefined ? null : asSealedVault(body.sealedVault);
    await app.limit(request, "sensitive");

    const row = await db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = ?",
      [user.id],
    );
    if (!(await verifyAuthSecret(row?.password_hash ?? null, authSecret))) {
      throw unauthorized("password is wrong");
    }

    await db.transaction(async (tx) => {
      await tx.run("UPDATE users SET recovery_public_key = ? WHERE id = ?", [
        recoveryPublicKey,
        user.id,
      ]);
      if (sealedVault !== null) {
        const existing = await tx.get("SELECT user_id FROM vaults WHERE user_id = ?", [user.id]);
        await tx.run(
          existing
            ? "UPDATE vaults SET sealed = ?, updated_day = ? WHERE user_id = ?"
            : "INSERT INTO vaults (sealed, updated_day, user_id) VALUES (?, ?, ?)",
          [sealedVault, today(), user.id],
        );
      }
    });
    return { ok: true };
  });

  app.get("/api/auth/me", async (request) => {
    const user = await app.authenticate(request);
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

  app.get("/api/auth/sessions", async (request) => {
    const user = await app.authenticate(request);
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
    const { id } = request.params as { id: string };
    const row = await db.get<{ id: string }>(
      "SELECT id FROM sessions WHERE id = ? AND user_id = ?",
      [id, user.id],
    );
    if (!row) throw badRequest("no such session", "not_found");
    await destroySession(db, id);
    return { ok: true };
  });
}

function replyWithSession(
  reply: FastifyReply,
  request: FastifyRequest,
  config: FastifyInstance["config"],
  payload: {
    id: string;
    username: string;
    role: string;
    token: string;
    expiresAt: number;
    sealedVault?: unknown;
  },
) {
  const maxAge = Math.floor((payload.expiresAt - Date.now()) / 1000);
  const csrf = randomToken(24);
  reply.header("set-cookie", [
    sessionCookie(config, request, payload.token, maxAge),
    csrfCookie(config, request, csrf, maxAge),
  ]);
  return {
    id: payload.id,
    username: payload.username,
    role: payload.role,
    csrfToken: csrf,
    sealedVault: payload.sealedVault ?? null,
  };
}
