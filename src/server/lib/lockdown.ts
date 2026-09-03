/**
 * Lockdown: the freeze an operator throws during a breach (ADR-0080).
 *
 * While the `lockdown` row exists the application answers every write with 503
 * `locked_down` and keeps serving reads. That combination is the whole design:
 *
 *  * **Nothing changes.** No order, no message, no listing, no balance movement, no payout
 *    claimed by the worker, no new session or account. An attacker inside a stolen admin
 *    session can no longer move money, and an attacker with a stolen user session can no
 *    longer spend a balance.
 *  * **Nothing is destroyed.** The books are the record of what this platform owes; the
 *    audit log and the order history are the evidence of what happened. A "self-destruct"
 *    that deletes them robs the sellers and blinds the investigation at the same time.
 *  * **People can still see their own money.** A frozen marketplace that also hides
 *    balances is indistinguishable, from the outside, from an exit scam.
 *
 * The flag is read from the database rather than from an environment variable so that
 * throwing it does not need a restart, and it is cached for a few seconds so that a freeze
 * does not add a query to every request forever. Two seconds of staleness at the moment of
 * engaging is acceptable: the write it lets through is one an attacker was already making.
 */
import type { Db } from "../db/index.ts";

/** How long the answer is reused. Short enough that a freeze is effectively immediate. */
const CACHE_MS = 2_000;

let cached: { at: number; engaged: boolean } | null = null;

export async function isLockedDown(db: Db): Promise<boolean> {
  const now = Date.now();
  if (cached && now - cached.at < CACHE_MS) return cached.engaged;
  const row = await db.get<{ engaged_at: number }>("SELECT engaged_at FROM lockdown WHERE id = 1");
  cached = { at: now, engaged: row !== null };
  return cached.engaged;
}

/** Tests and the boot log need the answer without waiting for the cache to expire. */
export function forgetLockdownCache(): void {
  cached = null;
}
