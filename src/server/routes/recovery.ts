/**
 * The other ways into an account: a second device, a recovery phrase, a PGP key.
 *
 * Every route here ends in the same place — a session, or nothing — and every one of them
 * is a path that bypasses the password, which is why they share one module and one set of
 * rules: the challenge is single-use (`lib/auth_flow.ts`), an unknown username is answered
 * exactly like a known one, and every failure returns the same sentence.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, unauthorized } from "../lib/errors.ts";
import { sha256 } from "../lib/ids.ts";
import { hashAuthSecret, verifyAuthSecret } from "../lib/password.ts";
import {
  createSession,
  pruneSessions,
  revokeAllCredentials,
  revokeOtherCredentials,
} from "../lib/sessions.ts";
import { recordSecurityEvent } from "../lib/security_events.ts";
import { today } from "../lib/time.ts";
import {
  asBase64Url,
  asId,
  asOptionalString,
  asOptionalText,
  asSealedVault,
  asUsername,
} from "../lib/validate.ts";
import { verifyEd25519 } from "../lib/signatures.ts";
import { inspectPublicKey, PgpError, verifyDetachedSignature } from "../lib/pgp.ts";
import {
  DECOY_KEY,
  LINK_TTL_MS,
  consumeChallenge,
  issueChallenge,
  limitByAccountName,
  replyWithSession,
} from "../lib/auth_flow.ts";

export async function registerRecoveryRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

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
    await recordSecurityEvent(db, user.id, "login.device");
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
   *
   * The row is written either way, with a null `user_id` when there is nobody behind the
   * name. The previous version wrote a row only for accounts that could answer, which
   * meant the *work* differed even though the response did not — one insert against none,
   * observable as timing and as a table that only grows for names that exist. That was a
   * known, documented gap (docs/SECURITY_REVIEW.md); this closes it, because a decoy row
   * costs one insert and an oracle costs a user their anonymity.
   */
  app.post("/api/auth/recovery/challenge", async (request) => {
    const body = (request.body ?? {}) as { username?: unknown };
    const username = asUsername(body.username);
    await app.requireWork(request);
    await app.limit(request, "recovery");
    await limitByAccountName(db, config, username);

    const user = await db.get<{ id: string; recovery_public_key: string | null }>(
      "SELECT id, recovery_public_key FROM users WHERE username = ? AND status = 'active'",
      [username],
    );
    // A decoy row for a name nobody registered, so the work is the same either way, and a
    // statement that names the service, the purpose and the expiry (ADR-0087).
    return issueChallenge(db, config, "recovery", user?.recovery_public_key ? user.id : null);
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

    // One answer for every way this can fail — unknown challenge, expired challenge, decoy
    // challenge for a name nobody registered, account without a recovery key, suspended
    // account, wrong signature. Any distinction here would rebuild the oracle that step one
    // just closed, because an attacker can always reach this endpoint (point 70).
    const refuse = () => unauthorized("that recovery challenge or signature is not valid");

    const claimed = await consumeChallenge(db, challengeId, "recovery");
    if (!claimed) throw refuse();

    const user = claimed.user_id
      ? await db.get<{
          id: string;
          username: string;
          role: string;
          status: string;
          recovery_public_key: string | null;
        }>("SELECT id, username, role, status, recovery_public_key FROM users WHERE id = ?", [
          claimed.user_id,
        ])
      : null;

    // The signature is verified against a key that cannot match rather than skipped, so a
    // decoy costs the same Ed25519 verification as a real account. Constant work is the
    // point; DECOY_KEY is a fixed public key nobody holds the private half of.
    const valid = verifyEd25519(
      Buffer.from(user?.recovery_public_key ?? DECOY_KEY, "base64url"),
      Buffer.from(claimed.challenge, "utf8"),
      Buffer.from(signature, "base64url"),
    );
    if (!valid || !user?.recovery_public_key || user.status !== "active") throw refuse();

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
    // Sessions, pending challenges and parked device-link codes all go: a recovery is
    // exactly the moment to assume every credential minted before it is hostile (ADR-0089).
    await revokeAllCredentials(db, user.id);
    await recordSecurityEvent(db, user.id, "recovery.completed");
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
   * PGP, step one: a challenge to sign, for one of the three things that can happen to a
   * key. The purpose is decided here, from the account's state and the caller's intent,
   * and it goes into the signed statement — so a signature made to *add* a key is not a
   * signature that replaces or removes one (ADR-0087, ADR-0088).
   *
   *   * no key yet, `intent: "key"`   → `pgp-enroll`, signed by the key being added;
   *   * key present, `intent: "key"`  → `pgp-rotate`, signed by **both** keys;
   *   * key present, `intent: "remove"` → `pgp-remove`, signed by the key being removed.
   *
   * Requires a session, because this is an account setting rather than a way in.
   */
  app.post("/api/auth/pgp/challenge", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const body = (request.body ?? {}) as { intent?: unknown };
    const intent = body.intent === undefined ? "key" : asOptionalString(body.intent, "intent", 16);
    if (intent !== "key" && intent !== "remove") {
      throw badRequest("intent must be \"key\" or \"remove\"");
    }
    const current = await currentPgpKey(user.id);
    if (intent === "remove" && !current) {
      throw badRequest("this account has no PGP key", "pgp_absent");
    }
    const purpose = intent === "remove" ? "pgp-remove" : current ? "pgp-rotate" : "pgp-enroll";
    const issued = await issueChallenge(db, config, purpose, user.id);
    return { ...issued, purpose, currentKeySignatureRequired: purpose !== "pgp-enroll" };
  });

  /**
   * PGP, step two: enrol a key, or replace the one that is there.
   *
   * Enrolling needs a session, the current password, and a signature from the key being
   * added — proof of possession, because enabling a key whose private half the user cannot
   * use would only lock the account out of itself.
   *
   * **Replacing needs one thing more: a signature from the key being replaced** (ADR-0088).
   * Without it, the second factor was only ever worth the session and password that could
   * swap it out — which is exactly what an attacker holding both would do first. Someone who
   * has genuinely lost their key does not use this route; they use the recovery phrase,
   * which clears the factor and is the documented way back.
   */
  app.post("/api/auth/pgp/key", async (request) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const publicKey = asOptionalText(body.publicKey, "publicKey", 64 * 1024);
    const challengeId = asId(body.challengeId, "challengeId");
    const signature = asOptionalText(body.signature, "signature", 64 * 1024);
    const currentSignature = asOptionalText(body.currentSignature, "currentSignature", 64 * 1024);
    if (!publicKey || !signature) throw badRequest("publicKey and signature are required");
    await app.limit(request, "sensitive");
    await requirePassword(user.id, authSecret);

    const current = await currentPgpKey(user.id);
    const claimed = await consumeChallenge(db, challengeId, current ? "pgp-rotate" : "pgp-enroll");
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
    if (current) {
      if (!currentSignature) {
        throw badRequest(
          "replacing a key needs a signature from the key being replaced",
          "current_key_signature_required",
        );
      }
      if (!(await verifyDetachedSignature(current, claimed.challenge, currentSignature))) {
        throw unauthorized("that signature does not match the key on this account");
      }
    }

    await db.run("UPDATE users SET pgp_public_key = ?, pgp_fingerprint = ? WHERE id = ?", [
      publicKey.trim(),
      facts.fingerprint,
      user.id,
    ]);
    // The second factor changed, so every session that was minted without it — or with the
    // key being replaced — ends here (point 131, ADR-0102). This session survives: it just
    // proved the password and a signature from the outgoing key.
    await revokeOtherCredentials(db, user.id, user.sessionId);
    await recordSecurityEvent(db, user.id, current ? "pgp.rotated" : "pgp.enrolled");
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

    const claimed = await consumeChallenge(db, challengeId, "pgp-login");
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
    await recordSecurityEvent(db, user.id, "login.pgp");
    await pruneSessions(db, config.sessionIdleDays);
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
   * Turn the second factor off — with the key that is being turned off (ADR-0088).
   *
   * The password alone used to be enough, which made the factor removable by exactly the
   * attacker it exists to stop: someone holding a session and a password, and no key. Now
   * it takes all three, and the way out for a user who has lost the key is the recovery
   * phrase. The vault is untouched — this changes how future logins are authenticated — but
   * the other sessions are not: taking a factor off the account ends the sessions that were
   * signed in under it (point 131, ADR-0102).
   */
  app.post("/api/auth/pgp/remove", async (request) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const challengeId = asId(body.challengeId, "challengeId");
    const signature = asOptionalText(body.signature, "signature", 64 * 1024);
    if (!signature) throw badRequest("signature is required");
    await app.limit(request, "sensitive");
    await requirePassword(user.id, authSecret);

    const current = await currentPgpKey(user.id);
    const claimed = await consumeChallenge(db, challengeId, "pgp-remove");
    if (!current || !claimed || claimed.user_id !== user.id) {
      throw unauthorized("that challenge is unknown or expired");
    }
    if (!(await verifyDetachedSignature(current, claimed.challenge, signature))) {
      throw unauthorized("that signature does not match the key on this account");
    }

    await db.run(
      "UPDATE users SET pgp_public_key = NULL, pgp_fingerprint = NULL WHERE id = ?",
      [user.id],
    );
    await revokeOtherCredentials(db, user.id, user.sessionId);
    await recordSecurityEvent(db, user.id, "pgp.removed");
    return { ok: true };
  });

  /**
   * Set or replace the recovery public key. Requires the current password, not a session
   * alone — and, like every other credential rotation here, it ends the other sessions
   * (point 131, ADR-0102): the key that can mint a login without the password has changed.
   */
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
    await revokeOtherCredentials(db, user.id, user.sessionId);
    await recordSecurityEvent(db, user.id, "recovery.key_set");
    return { ok: true };
  });

  /** The armoured public key on this account, or null. One query, one meaning. */
  async function currentPgpKey(userId: string): Promise<string | null> {
    const row = await db.get<{ pgp_public_key: string | null }>(
      "SELECT pgp_public_key FROM users WHERE id = ?",
      [userId],
    );
    return row?.pgp_public_key ?? null;
  }

  /** Every key operation costs the current password as well as a session. */
  async function requirePassword(userId: string, authSecret: string): Promise<void> {
    const row = await db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE id = ?",
      [userId],
    );
    if (!(await verifyAuthSecret(row?.password_hash ?? null, authSecret))) {
      throw unauthorized("password is wrong");
    }
  }
}
