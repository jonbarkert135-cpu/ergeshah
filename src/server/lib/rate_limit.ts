/**
 * Token-bucket rate limiting that never stores a client address.
 *
 * The bucket key is HMAC-SHA256(pepper || unix-day, address || scope): it rotates every
 * day, and even with the database *and* the pepper an attacker only gets a set of
 * hashes for one day, not an access log. Failing closed on a database error would let a
 * single bad query disable login for everybody, so we fail closed only for the request
 * that errored.
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

export const LIMITS = {
  auth: { burst: 10, perMinute: 1 },
  register: { burst: 5, perMinute: 0.5 },
  send: { burst: 60, perMinute: 60 },
  read: { burst: 240, perMinute: 240 },
  write: { burst: 30, perMinute: 20 },
} satisfies Record<string, Limit>;

export type LimitName = keyof typeof LIMITS;

export function bucketKey(pepper: string, scope: string, address: string): string {
  return hmac(`${pepper}:${today()}`, `${scope}:${address}`);
}

export async function consume(
  db: Db,
  pepper: string,
  scope: LimitName,
  address: string,
  now = Date.now(),
): Promise<void> {
  const limit = LIMITS[scope];
  const key = bucketKey(pepper, scope, address);
  await db.transaction(async (tx) => {
    const row = await tx.get<{ tokens: number; updated_at: number }>(
      "SELECT tokens, updated_at FROM rate_limits WHERE bucket = ?",
      [key],
    );
    const refillPerMs = limit.perMinute / 60_000;
    const tokens = row
      ? Math.min(limit.burst, row.tokens + (now - row.updated_at) * refillPerMs)
      : limit.burst;
    if (tokens < 1) throw tooManyRequests(`too many ${scope} requests — slow down`);
    const remaining = tokens - 1;
    if (row) {
      await tx.run("UPDATE rate_limits SET tokens = ?, updated_at = ? WHERE bucket = ?", [
        remaining,
        now,
        key,
      ]);
    } else {
      await tx.run("INSERT INTO rate_limits (bucket, tokens, updated_at) VALUES (?, ?, ?)", [
        key,
        remaining,
        now,
      ]);
    }
  });
}

/** Buckets are worthless after a day; deleting them keeps the table from growing. */
export async function pruneRateLimits(db: Db, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM rate_limits WHERE updated_at < ?", [now - 24 * 60 * 60 * 1000]);
}
