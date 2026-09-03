/**
 * Sending back a top-up that was too small to credit (ADR-0071).
 *
 * ADR-0067 made the deposit minimum real: a transfer under `MIN_DEPOSIT_XMR` is recorded with
 * status `below_minimum` and no ledger entry, because crediting dust costs more in payout
 * fees than the dust is worth. That left the money in the platform's wallet, its owner's name
 * on it, and a support conversation as the only way to get it back — which is exactly the
 * shape of complaint a custodial marketplace deserves to be judged by.
 *
 * This module is the way out, and it is deliberately not a new kind of money movement. A
 * refund is the moment a `below_minimum` deposit is finally credited — one `deposit` entry
 * per row, each naming the deposit it came from — and immediately held for a payout that
 * returns it to an address its owner names. Both halves happen in one transaction, so there
 * is no instant in which the money is spendable and no crash that can credit without queueing.
 *
 * Two rules keep it honest:
 *
 * 1. **Only rows this call claimed are credited.** The `UPDATE ... RETURNING` moves them out
 *    of `below_minimum` first, so two requests racing produce one refund and one refusal
 *    rather than the same dust sent twice.
 * 2. **A refund has to be worth its own network fee.** Under `MIN_REFUND_XMR` the whole
 *    transaction rolls back and the deposits stay where they were: the alternative is a
 *    stranger paying a hundred one-piconero transfers and being handed a hundred outgoing
 *    fees from the platform's float.
 */
import type { Db } from "../db/index.ts";
import { badRequest, conflict } from "./errors.ts";
import { accountFor, apply, queueWithdrawal, type WithdrawalStatus } from "./ledger.ts";

/** What arrived, was not credited, and is therefore still owed to its payer. */
export async function belowMinimumTotal(db: Db, userId: string): Promise<number> {
  const row = await db.get<{ total: number | null }>(
    "SELECT SUM(amount_pico) AS total FROM deposits WHERE user_id = ? AND status = 'below_minimum'",
    [userId],
  );
  return Number(row?.total ?? 0);
}

/** Every uncredited top-up on the platform, which is a liability like any balance. */
export async function belowMinimumLiability(db: Db): Promise<number> {
  const row = await db.get<{ total: number | null }>(
    "SELECT SUM(amount_pico) AS total FROM deposits WHERE status = 'below_minimum'",
  );
  return Number(row?.total ?? 0);
}

export interface Refund {
  withdrawalId: string;
  status: WithdrawalStatus;
  amountPico: number;
  /** How many uncredited transfers went into it — one refund pays one network fee. */
  deposits: number;
}

/**
 * Credits every below-minimum top-up this account has and queues it back to `address`.
 *
 * The whole total, always: the fee is charged per transfer, so refunding half of it twice is
 * strictly worse for everybody. `limitPico` is the account's automatic payout ceiling, which
 * still applies — a refund large enough to need a human is possible (a payer who sent a
 * hundred small transfers) and it waits in the same queue as any other large payout.
 */
export async function refundBelowMinimum(
  db: Db,
  input: { userId: string; address: string; minRefundPico: number; limitPico: number },
): Promise<Refund> {
  const now = Date.now();
  return db.transaction(async (tx) => {
    // Claimed first, credited second: a row that is no longer `below_minimum` is one another
    // request — or an operator's manual refund — has already taken responsibility for.
    const claimed = await tx.all<{ id: string; amount_pico: number }>(
      `UPDATE deposits SET status = 'credited', credited_at = ?
        WHERE user_id = ? AND status = 'below_minimum'
        RETURNING id, amount_pico`,
      [now, input.userId],
    );
    if (claimed.length === 0) {
      throw conflict("there is no uncredited top-up on this account", "nothing_to_refund");
    }
    const amountPico = claimed.reduce((total, row) => total + row.amount_pico, 0);
    if (amountPico < input.minRefundPico) {
      // Rolls the claim back with it, which is the point of doing this inside a transaction:
      // the deposits are exactly as they were, and the owner can ask again when more arrives.
      throw badRequest(
        "this is less than it costs to send back; it stays on the account until there is more of it",
        "refund_too_small",
      );
    }
    await apply(
      tx,
      claimed.map((row) => ({
        accountId: accountFor(input.userId),
        userId: input.userId,
        kind: "deposit" as const,
        availableDelta: row.amount_pico,
        heldDelta: 0,
        depositId: row.id,
      })),
      now,
    );
    const queued = await queueWithdrawal(
      tx,
      {
        userId: input.userId,
        amountPico,
        address: input.address,
        limitPico: input.limitPico,
      },
      now,
    );
    return {
      withdrawalId: queued.id,
      status: queued.status,
      amountPico,
      deposits: claimed.length,
    };
  });
}
