/**
 * The three things the account routes share.
 *
 * `routes/auth.ts` (registration, login, sessions) and `routes/recovery.ts` (device
 * linking, recovery phrases, PGP) are separate domains that meet in exactly these places:
 * a challenge table that is consumed once, a rate-limit bucket counted against a username,
 * and the reply that hands a browser a session. They live here rather than in either route
 * module because a route module never imports another one (test/architecture.test.ts).
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../config.ts";
import type { Db } from "../db/index.ts";
import { csrfCookie, sessionCookie } from "../app.ts";
import { consume } from "./rate_limit.ts";
import { newId as randomUuid, randomToken } from "./ids.ts";

/** Long enough to paste a phrase and sign, short enough to be useless if intercepted. */
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** Long enough to walk to the other device, short enough that a photographed screen ages out. */
export const LINK_TTL_MS = 5 * 60 * 1000;

/**
 * A syntactically valid Ed25519 public key used to verify signatures for accounts that do
 * not exist, so that a decoy challenge does the same work as a real one. It is the
 * all-zero point: no private half exists, and verification against it always fails.
 */
export const DECOY_KEY = Buffer.alloc(32).toString("base64url");

/**
 * What a challenge is *for*. It is stored in `auth_challenges.kind` and written into the
 * signed statement, so the two cannot drift: a signature made to add a key is not a
 * signature that removes one, whatever row an attacker points it at.
 */
export type ChallengePurpose =
  | "recovery"
  | "pgp-enroll"
  | "pgp-login"
  | "pgp-rotate"
  | "pgp-remove";

/** The protocol version inside the signed bytes. Bump it if the statement's shape changes. */
export const CHALLENGE_PROTOCOL = "symvolon-auth-v1";

/**
 * The bytes a user actually signs (ADR-0087).
 *
 * A bare random nonce proves freshness and nothing else: it does not say which service
 * asked, what the signature authorises, or when it stops being valid — so a signature
 * collected for one operation is, cryptographically, a signature for any operation that
 * accepts the same shape. This statement carries all four, in one line a person can read
 * before they sign it:
 *
 *   symvolon-auth-v1 service=<id> purpose=<what it authorises> id=<challenge id>
 *   expires=<ISO 8601> nonce=<32 random bytes>
 *
 * The whole statement is stored in `auth_challenges.challenge` and verified as-is, so the
 * server never rebuilds it from parts that might disagree with the row.
 */
export function challengeStatement(input: {
  serviceId: string;
  purpose: ChallengePurpose;
  id: string;
  expiresAt: number;
  nonce: string;
}): string {
  return [
    CHALLENGE_PROTOCOL,
    `service=${input.serviceId}`,
    `purpose=${input.purpose}`,
    `id=${input.id}`,
    `expires=${new Date(input.expiresAt).toISOString()}`,
    `nonce=${input.nonce}`,
  ].join(" ");
}

export interface IssuedChallenge {
  challengeId: string;
  challenge: string;
  expiresInSeconds: number;
}

/**
 * Write one challenge and return it. Issuing replaces any earlier challenge of the same
 * purpose for the same account: otherwise every request left a live token behind, and an
 * attacker who ever saw one signature could hold a stack of challenges waiting for it.
 * One account, one purpose, one outstanding challenge.
 *
 * `userId` may be null — that is the decoy row a recovery challenge writes for a username
 * nobody registered, so the work is identical either way (R-10).
 */
export async function issueChallenge(
  db: Db,
  config: Pick<Config, "serviceId">,
  purpose: ChallengePurpose,
  userId: string | null,
  now = Date.now(),
): Promise<IssuedChallenge> {
  const id = randomUuid();
  const expiresAt = now + CHALLENGE_TTL_MS;
  const challenge = challengeStatement({
    serviceId: config.serviceId,
    purpose,
    id,
    expiresAt,
    nonce: randomToken(32),
  });
  await db.transaction(async (tx) => {
    if (userId) {
      await tx.run("DELETE FROM auth_challenges WHERE user_id = ? AND kind = ?", [userId, purpose]);
    }
    await tx.run(
      `INSERT INTO auth_challenges (id, user_id, kind, challenge, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [id, userId, purpose, challenge, expiresAt],
    );
  });
  return { challengeId: id, challenge, expiresInSeconds: CHALLENGE_TTL_MS / 1000 };
}

/**
 * Take a challenge out of the table, once. Expired rows go with it. The row is deleted
 * whether or not the signature that follows turns out to be valid, so a challenge cannot
 * be ground against offline guesses, and a valid signature cannot be replayed.
 */
export async function consumeChallenge(
  db: Db,
  id: string,
  kind: ChallengePurpose,
): Promise<{ user_id: string | null; challenge: string } | null> {
  return db.transaction(async (tx) => {
    await tx.run("DELETE FROM auth_challenges WHERE expires_at < ?", [Date.now()]);
    const row = await tx.get<{ user_id: string | null; challenge: string }>(
      "SELECT user_id, challenge FROM auth_challenges WHERE id = ? AND kind = ?",
      [id, kind],
    );
    if (!row) return null;
    await tx.run("DELETE FROM auth_challenges WHERE id = ?", [id]);
    return row;
  });
}

/**
 * Charge an attempt to the *name* it targets, whether or not that name exists. Keyed this
 * way it costs an attacker one token per guess no matter how many addresses they have;
 * keyed uniformly it tells them nothing, because a name nobody registered has a bucket
 * exactly like a name somebody did. The subject is HMACed with the daily pepper before it
 * becomes a key (lib/rate_limit.ts), so no username is stored.
 */
export async function limitByAccountName(
  db: Db,
  config: Config,
  username: string,
): Promise<void> {
  await consume(db, config.bucketPepper, "account_attempt", `name:${username}`, config.rateLimits);
}

/** Mint the session and CSRF cookies, and answer with what the client needs to continue. */
export function replyWithSession(
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
