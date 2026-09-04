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
 *
 * **Revocation (MD-5, ADR-0111).** Because a token has no owner, a suspension cannot select
 * one account's stockpile — so revocation here is global and blunt: every token is minted
 * under an epoch it carries in its own string, and a spend is refused when that epoch is
 * below the floor in `send_token_epoch`. An operator raising the floor (`incident.mjs
 * send-tokens:revoke`) invalidates every outstanding token at once, in one O(1) write;
 * clients refetch on their next send. The epoch is deliberately global and coarse — everyone
 * minting between two bumps shares it — so it never becomes the grouping key that a
 * per-batch value would be, which is the owner-column-by-another-name MD-5 exists to avoid.
 */
import type { Db } from "../db/index.ts";
import { randomToken, sha256 } from "./ids.ts";
import { randomInt } from "node:crypto";

/** Spread within a batch, so a shared expiry is not a batch fingerprint. */
const JITTER_MS = 15 * 60_000;

/** How long the epoch floor is reused between reads. Short enough that a revocation is
 *  effectively immediate; long enough that it is not a query on every mint and every send.
 *  A spend it lets through in that window is one the token holder could already make. */
const EPOCH_CACHE_MS = 2_000;

let cachedEpoch: { at: number; min: number } | null = null;

/** The current revocation floor. Missing table or row (a deployment before this migration, or
 *  after the table is dropped to disable the feature) reads as 0 — every token's epoch is then
 *  valid, which is the pre-MD-5 behaviour. */
async function minEpoch(db: Db, now: number): Promise<number> {
  if (cachedEpoch && now - cachedEpoch.at < EPOCH_CACHE_MS) return cachedEpoch.min;
  let min = 0;
  try {
    const row = await db.get<{ min_epoch: number }>("SELECT min_epoch FROM send_token_epoch WHERE id = 1");
    if (row) min = row.min_epoch;
  } catch {
    min = 0; // table absent: treat as no revocation floor
  }
  cachedEpoch = { at: now, min };
  return min;
}

/** Tests need the floor without waiting for the cache to expire. */
export function forgetSendTokenEpochCache(): void {
  cachedEpoch = null;
}

/** The epoch a token carries, or null if the string is not `<digits>.<random>`. */
function epochOf(token: string): number | null {
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const prefix = token.slice(0, dot);
  if (!/^\d{1,15}$/.test(prefix)) return null;
  return Number(prefix);
}

export function sendTokenHash(token: string): string {
  return sha256(token);
}

/**
 * Raise the revocation floor by one, so every token minted under a lower epoch is refused on
 * its next spend. One O(1) write invalidates the whole outstanding population; the dead rows
 * are swept by housekeeping when they expire, not deleted here — a bump during an incident
 * should not be an O(n) write over the table. Returns the new floor. Used by `incident.mjs`.
 */
export async function revokeSendTokens(db: Db): Promise<number> {
  const row = await db.get<{ min_epoch: number }>(
    "UPDATE send_token_epoch SET min_epoch = min_epoch + 1 WHERE id = 1 RETURNING min_epoch",
  );
  cachedEpoch = null; // the next read must see the bump, not the stale floor
  return row?.min_epoch ?? 0;
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
  // Stamp each token with the current floor so it stays valid until the next revocation. The
  // epoch lives in the token string, not in a column — the stored hash is over the whole
  // string, so a client cannot forge a higher epoch, and nothing about the batch is at rest.
  const epoch = await minEpoch(db, now);
  const tokens: string[] = [];
  await db.transaction(async (tx) => {
    for (let index = 0; index < count; index += 1) {
      const token = `${epoch}.${randomToken(32)}`;
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
  // Refuse a token whose epoch has been revoked before touching the table (MD-5): a token
  // minted under an older floor is dead, whether or not its row is still there. Same false
  // answer as a spent or forged token — the distinction is not worth publishing.
  const epoch = epochOf(token);
  if (epoch === null || epoch < (await minEpoch(db, now))) return false;
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
