/**
 * Sealed sender (MD-4, ADR-0084): single-use tokens that let a client post an envelope
 * without presenting a session.
 *
 * The gap this closes was written down in `docs/METADATA.md` long before it was fixed:
 * `envelopes` has no sender column, so the *stored* message says nothing about who wrote
 * it — but the *request* that stored it carried a session cookie, so a server that chose
 * to write that down could. The token removes the cookie from the request that matters.
 *
 * How it works, in three rows of one table:
 *
 *   * an authenticated client asks for a batch of tokens (`POST /api/messages/tokens`).
 *     The server hands back random strings and keeps only their SHA-256 hashes — no
 *     owner column, no issued-at column, nothing that says which account asked;
 *   * to send, the client presents one token in `x-send-token` and *omits* its cookies.
 *     The token is deleted in the same statement that accepts it, so it works once;
 *   * tokens expire (`SEND_TOKEN_TTL_MS`) and are swept by housekeeping like envelopes.
 *
 * **What this does not claim.** It defeats an adversary who reads the database — a
 * backup, a seized disk, a subpoena for stored records — because those rows cannot be
 * joined to an account. It does not defeat an operator who modifies the running server to
 * record which account received which token: unlinkable issuance needs a blind signature,
 * which needs a primitive this project does not have and will not hand-roll (see the ADR).
 * The honest summary is "the sender is no longer in the data at rest", and the roadmap
 * item says exactly that rather than the word "anonymous".
 *
 * The expiry carries a few minutes of random jitter per token. Without it, a batch shares
 * one `expires_at` to the millisecond, which is a grouping key: an operator who saw one
 * token spent would know the rest of that batch belonged to the same person, and a batch
 * is a conversation's worth of messages.
 */
import type { Db } from "../db/index.ts";
import { randomToken, sha256 } from "./ids.ts";
import { randomInt } from "node:crypto";

/** Spread within a batch, so a shared expiry is not a batch fingerprint. */
const JITTER_MS = 15 * 60_000;

export function sendTokenHash(token: string): string {
  return sha256(token);
}

/**
 * Mint `count` tokens. The caller is authenticated — that is how the quota is charged —
 * and nothing about them is written down here.
 */
export async function issueSendTokens(
  db: Db,
  count: number,
  ttlMs: number,
  now = Date.now(),
): Promise<string[]> {
  const tokens: string[] = [];
  await db.transaction(async (tx) => {
    for (let index = 0; index < count; index += 1) {
      const token = randomToken(32);
      await tx.run("INSERT INTO send_tokens (token_hash, expires_at) VALUES (?, ?)", [
        sendTokenHash(token),
        now + ttlMs + randomInt(JITTER_MS),
      ]);
      tokens.push(token);
    }
  });
  return tokens;
}

/**
 * Accept a token, once. Deleting the row *is* the acceptance: two requests racing with the
 * same token cannot both find it, so a captured token is worth at most one envelope, and
 * an expired one is worth none.
 */
export async function spendSendToken(db: Db, token: string, now = Date.now()): Promise<boolean> {
  if (typeof token !== "string" || token.length < 16 || token.length > 128) return false;
  const spent = await db.get<{ token_hash: string }>(
    "DELETE FROM send_tokens WHERE token_hash = ? AND expires_at > ? RETURNING token_hash",
    [sendTokenHash(token), now],
  );
  return spent !== undefined && spent !== null;
}

/** Retention: an unspent token is deleted when it expires. Called from housekeeping. */
export async function pruneSendTokens(db: Db, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM send_tokens WHERE expires_at < ?", [now]);
}
