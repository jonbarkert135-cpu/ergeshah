/**
 * Server side of the proof-of-work gate (point 71, ADR-0039).
 *
 * Why this exists at all: the unauthenticated endpoints — register, login, recovery — are
 * the ones a script attacks, and they are exactly the ones where the rate limiter is
 * weakest. It counts against the client address when there is no account yet, and on the
 * onion service every request arrives from one address (the `tor` container), so the
 * address bucket is a single bucket shared by everybody. Tightening it throttles the
 * users; loosening it stops defending anything. A cost the *client* pays does not have
 * that shape: it scales with the number of attempts, not with the number of addresses.
 *
 * The challenge is a MAC, not a row. Issuing one is a hash, so being asked for challenges
 * is not itself an attack; only redeeming one writes, and that write is what makes it
 * single-use.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import type { Db } from "../db/index.ts";
import { badRequest, proofOfWorkRequired } from "./errors.ts";
import { hmac, randomToken } from "./ids.ts";
import { meetsDifficulty, powPreimage } from "../../shared/pow.ts";

/** Long enough to solve on a slow phone, short enough to be worthless to stockpile. */
export const POW_TTL_MS = 5 * 60 * 1000;

export interface ProofOfWork {
  challenge: string;
  mac: string;
  bits: number;
  expiresInSeconds: number;
}

function macFor(pepper: string, challenge: string, bits: number): string {
  return hmac(pepper, `pow:${challenge}:${bits}`);
}

/** Mint a challenge. No state: the MAC is what makes it ours, the timestamp what ages it. */
export function issueProofOfWork(pepper: string, bits: number, now = Date.now()): ProofOfWork {
  const challenge = `${randomToken(12)}.${now}`;
  return {
    challenge,
    mac: macFor(pepper, challenge, bits),
    bits,
    expiresInSeconds: POW_TTL_MS / 1000,
  };
}

function equal(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Check a submitted solution, or throw the 428 that carries a fresh challenge. Every
 * failure — absent, forged, stale, wrong, replayed — ends the same way, because the only
 * useful thing to tell a client is "here is a new one".
 */
export async function requireProofOfWork(
  db: Db,
  pepper: string,
  bits: number,
  submitted: unknown,
  now = Date.now(),
): Promise<void> {
  if (bits <= 0) return;
  const fresh = () =>
    proofOfWorkRequired(
      { ...issueProofOfWork(pepper, bits, now) },
      "this request needs a proof of work; solve the challenge in this response and retry",
    );

  const proof = (submitted ?? {}) as { challenge?: unknown; mac?: unknown; nonce?: unknown };
  if (
    typeof proof.challenge !== "string" ||
    typeof proof.mac !== "string" ||
    typeof proof.nonce !== "number" ||
    !Number.isSafeInteger(proof.nonce) ||
    proof.nonce < 0 ||
    proof.challenge.length > 64
  ) {
    throw fresh();
  }

  if (!equal(proof.mac, macFor(pepper, proof.challenge, bits))) throw fresh();

  const issuedAt = Number(proof.challenge.split(".")[1]);
  if (!Number.isFinite(issuedAt) || issuedAt > now + 60_000 || now - issuedAt > POW_TTL_MS) {
    throw fresh();
  }

  const digest = createHash("sha256").update(powPreimage(proof.challenge, proof.nonce)).digest();
  if (!meetsDifficulty(digest, bits)) throw fresh();

  // Single use. The row is the receipt, and the primary key is the enforcement: a second
  // redemption of the same challenge collides and is refused. `auth_challenges` already
  // holds exactly this kind of short-lived one-time row, and its expiry index already
  // exists, so no new table is created for a value that lives five minutes.
  await db.run("DELETE FROM auth_challenges WHERE kind = 'pow' AND expires_at < ?", [now]);
  try {
    await db.run(
      `INSERT INTO auth_challenges (id, user_id, kind, challenge, expires_at)
       VALUES (?, NULL, 'pow', ?, ?)`,
      [proof.challenge, proof.mac, issuedAt + POW_TTL_MS],
    );
  } catch {
    // Already redeemed. Not `fresh()`: a replay is a client bug or an attacker, and either
    // way the honest answer is that this particular proof is spent.
    throw badRequest("this proof of work has already been used", "pow_spent");
  }
}
