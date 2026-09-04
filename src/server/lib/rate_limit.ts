/**
 * Token-bucket rate limiting that never stores a client address.
 *
 * The bucket key is HMAC-SHA256(pepper || unix-day, subject || scope): it rotates every
 * day, and even with the database *and* the pepper an attacker only gets a set of hashes
 * for one day, not an access log.
 *
 * **The subject is the account when there is one, and the address only otherwise.** On an
 * onion service every request arrives from 127.0.0.1, so address-keyed limits would be one
 * global bucket shared by every user — a spammer would throttle everyone else and barely
 * inconvenience themselves. Keying authenticated traffic to the account also matches what
 * the limits are actually defending: an account can be made to wait, a Tor exit cannot.
 *
 * Every scope below is a separate bucket, so exhausting one operation never disables
 * another: a login flood cannot stop anyone from sending messages, and a bot creating
 * listings does not lock the site's search.
 */
import type { Db } from "../db/index.ts";
import { hmac } from "./ids.ts";
import { today } from "./time.ts";
import { tooManyRequests } from "./errors.ts";

export interface Limit {
  /** Bucket capacity: how many requests may burst. */
  burst: number;
  /** Sustained refill rate, in requests per minute. */
  perMinute: number;
}

/**
 * Defaults, one bucket per operation class. They are deliberately generous for things a
 * person does and mean for things a script does: guessing a password, creating accounts,
 * filing seller applications, or running the only query in this system that reads every
 * listing row (search).
 *
 * Every value is overridable per deployment — see `RATE_LIMITS` in `.env.example` — so an
 * operator under attack can tighten a single scope without a code change or a restart of
 * the argument about what the "right" number is.
 */
export const DEFAULT_LIMITS = {
  /** Account creation: the cheapest thing to automate, so the tightest bucket here. */
  register: { burst: 5, perMinute: 0.5 },
  /** Login, including the password verification that follows it. */
  login: { burst: 10, perMinute: 1 },
  /**
   * Attempts aimed at one *named* account — logins and recovery challenges — counted
   * against the name rather than against whoever is asking. It is the bucket that still
   * means something when the attacker has many addresses, or when every request arrives
   * from the same one because the service is reached over Tor.
   *
   * Deliberately loose. A tight per-account bucket is an account-lockout tool handed to
   * anyone who knows a username: they would spend it and leave the owner locked out. This
   * is sized to stop bulk credential stuffing while staying far above what a person who
   * keeps mistyping their own password will ever reach (see docs/THREAT_MODEL.md).
   */
  account_attempt: { burst: 50, perMinute: 10 },
  /** Recovery-phrase login: same shape as a password guess, and a longer secret. */
  recovery: { burst: 5, perMinute: 0.5 },
  /** Password change, key rotation, device linking, account deletion. */
  sensitive: { burst: 10, perMinute: 2 },
  /** Sending an envelope. High, because a real conversation is bursty. */
  message_send: { burst: 60, perMinute: 60 },
  /**
   * Minting sealed-sender tokens (ADR-0084). One call mints a batch, so this is the real
   * ceiling on sending: three batches at once, one a minute sustained. Generous for a
   * person, and the only place an account is charged for a message it will later post
   * without a cookie.
   */
  send_tokens: { burst: 3, perMinute: 1 },
  /**
   * Uploading an encrypted attachment. Megabytes per call and no owner column to charge a
   * quota against (see migration 011), so the bucket is the quota: a dozen at once, three a
   * minute sustained. A person sharing photographs does not notice; a script filling the
   * operator's disk pays for every one.
   */
  attachment: { burst: 12, perMinute: 3 },
  /**
   * The same uploads, charged in **bytes** rather than in calls (ADR-0093).
   *
   * `attachment` bounds how *often* a blob may be posted; this bounds how much disk one
   * account may turn into rows, which is the thing the operator actually pays for. One
   * token is one byte of ciphertext: 128 MiB may be spent at once, and the allowance refills
   * at 2 MiB a minute (about 2.8 GiB a day) whether or not anything is uploaded.
   *
   * It needs no `owner` column on `attachments` — the bucket is an HMAC of the account with
   * a pepper that rotates daily, exactly like every other limit, so nothing here links an
   * account to a blob (which is why ADR-0043 and ADR-0057 refused the quota they were
   * offered, and this one is not that quota).
   */
  upload_bytes: { burst: 128 * 1024 * 1024, perMinute: 2 * 1024 * 1024 },
  /** Applying to become a seller. A human does this once. */
  seller_application: { burst: 3, perMinute: 0.2 },
  /** Creating or editing a listing. */
  listing_write: { burst: 20, perMinute: 5 },
  /** Placing an order or moving its status. */
  order_write: { burst: 20, perMinute: 5 },
  /** Leaving a review. */
  review: { burst: 10, perMinute: 1 },
  /**
   * Asking this server to move money: a payout request or its cancellation. Tight, because a
   * human does it rarely and a script doing it in a loop is either an attack or a bug, and
   * because each call writes a ledger entry.
   */
  wallet_write: { burst: 6, perMinute: 1 },
  /** Reports and moderation actions. */
  moderation: { burst: 30, perMinute: 10 },
  /** Listing search: the one query that scans, so it gets its own, tighter bucket. */
  search: { burst: 30, perMinute: 30 },
  /**
   * Claiming a prekey bundle. Separate from `read` because it is the one read that
   * *consumes* something of somebody else's: one one-time prekey per device, per call.
   */
  key_bundle: { burst: 30, perMinute: 10 },
  /** Ordinary reads. */
  read: { burst: 240, perMinute: 240 },
  /** Anything else that writes. */
  write: { burst: 30, perMinute: 20 },
} satisfies Record<string, Limit>;

export type LimitName = keyof typeof DEFAULT_LIMITS;
export type Limits = Record<LimitName, Limit>;

/**
 * Parses the `RATE_LIMITS` override: `{"login":{"burst":3,"perMinute":0.5}}`. Unknown
 * scopes and nonsense values are a configuration error and stop the server at boot rather
 * than silently leaving a limit at its default — a limit you think you tightened and did
 * not is worse than no limit at all.
 */
export function resolveLimits(raw: string | undefined): Limits {
  const limits: Limits = { ...DEFAULT_LIMITS };
  if (!raw || !raw.trim()) return limits;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("RATE_LIMITS must be JSON, e.g. {\"login\":{\"burst\":3,\"perMinute\":0.5}}");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("RATE_LIMITS must be a JSON object of scope -> {burst, perMinute}");
  }

  for (const [scope, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!(scope in DEFAULT_LIMITS)) {
      throw new Error(
        `RATE_LIMITS: unknown scope ${JSON.stringify(scope)}; known scopes are ${Object.keys(DEFAULT_LIMITS).join(", ")}`,
      );
    }
    const limit = value as Partial<Limit>;
    const burst = Number(limit?.burst);
    const perMinute = Number(limit?.perMinute);
    if (!Number.isFinite(burst) || burst < 1 || !Number.isFinite(perMinute) || perMinute <= 0) {
      throw new Error(`RATE_LIMITS.${scope}: burst must be >= 1 and perMinute > 0`);
    }
    limits[scope as LimitName] = { burst, perMinute };
  }
  return limits;
}

function bucketKey(pepper: string, scope: string, subject: string): string {
  return hmac(`${pepper}:${today()}`, `${scope}:${subject}`);
}

export async function consume(
  db: Db,
  pepper: string,
  scope: LimitName,
  /** `user:<id>` for an authenticated caller, `addr:<ip>` otherwise. */
  subject: string,
  limits: Limits = DEFAULT_LIMITS,
  now = Date.now(),
  /** How many tokens this call spends. Bytes for `upload_bytes`, one request everywhere else. */
  cost = 1,
): Promise<void> {
  const limit = limits[scope];
  const key = bucketKey(pepper, scope, subject);
  const refillPerMs = limit.perMinute / 60_000;
  // The bucket's current level, refilled to this instant and capped at the burst, as one SQL
  // expression over the row *as the database sees it when the statement runs* — not as this
  // process read it a moment ago. Written with CASE rather than MIN/LEAST so that both
  // dialects run the same text.
  const refilled =
    "CASE WHEN tokens + (? - updated_at) * ? > ? THEN ? ELSE tokens + (? - updated_at) * ? END";
  const refilledParams = [now, refillPerMs, limit.burst, limit.burst, now, refillPerMs];
  await db.transaction(async (tx) => {
    // A bucket that has never been seen starts full. `ON CONFLICT DO NOTHING` makes the
    // first sight of a bucket safe against itself: two requests creating it at once leave
    // one row, and both then spend from it below.
    await tx.run(
      "INSERT INTO rate_limits (bucket, tokens, updated_at) VALUES (?, ?, ?) ON CONFLICT (bucket) DO NOTHING",
      [key, limit.burst, now],
    );
    // The spend is one conditional UPDATE. A read-then-write here was correct on SQLite,
    // which serialises transactions, and wrong on PostgreSQL, where READ COMMITTED let
    // several requests read the same level and each write `level - cost`: k concurrent
    // requests cost one token (SEC-2026-011). The database evaluates the condition against
    // the row it is about to change, under the row lock, so the k-th request finds the
    // bucket the previous k-1 left behind.
    const spent = await tx.get<{ tokens: number }>(
      `UPDATE rate_limits
          SET tokens = ${refilled} - ?, updated_at = ?
        WHERE bucket = ? AND ${refilled} >= ?
        RETURNING tokens`,
      [...refilledParams, cost, now, key, ...refilledParams, cost],
    );
    if (spent) return;
    // Refused. Say when a retry can succeed: how long the missing tokens take to appear,
    // rounded up — the earliest moment rather than a number that sounds reassuring.
    const row = await tx.get<{ tokens: number; updated_at: number }>(
      "SELECT tokens, updated_at FROM rate_limits WHERE bucket = ?",
      [key],
    );
    const tokens = row
      ? Math.min(limit.burst, Number(row.tokens) + (now - Number(row.updated_at)) * refillPerMs)
      : 0;
    const seconds = Math.max(1, Math.ceil((cost - tokens) / refillPerMs / 1000));
    // One bucket counts bytes rather than calls, and "too many upload_bytes requests"
    // would be a sentence about the implementation instead of about what happened.
    const message = scope === "upload_bytes"
      ? "this account has uploaded its allowance for now — try again later"
      : `too many ${scope} requests — slow down`;
    throw tooManyRequests(message, seconds);
  });
}

/** Buckets are worthless after a day; deleting them keeps the table from growing. */
export async function pruneRateLimits(db: Db, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM rate_limits WHERE updated_at < ?", [now - 24 * 60 * 60 * 1000]);
}
