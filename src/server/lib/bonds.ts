/**
 * The seller bond (MKT-6, ADR-0086): money a seller stakes on their own honesty, and the
 * one path by which it can end up somewhere other than back in their pocket.
 *
 * The mechanism exists because escrow has a gap. While an order is open the buyer's money
 * is held, so a moderator who upholds their dispute simply cancels it and the buyer is
 * whole. Once an order has *completed* the money is gone to the seller, and a buyer who
 * discovers a week later that what they received was worthless has nothing to be made whole
 * from. That is the case the bond covers, and the reason a claim is only possible on a
 * completed order that was disputed.
 *
 * Three rules, and they are what separate this from the proposal it answers:
 *
 * 1. **The platform never benefits.** A forfeited bond moves to the harmed buyer. Nothing is
 *    burnt, nothing lands on the platform account, and there is no fee on the way: a
 *    platform that profits from forfeiture will find reasons to forfeit.
 * 2. **A human decides, on a case, with a reason.** The trigger is a moderator claiming a
 *    specific amount on a specific order — audited like every other moderator action — not a
 *    counter of complaints that three coordinated accounts could aim at an honest seller.
 * 3. **The seller's own money stays theirs.** A bond is released on request after a
 *    cool-off with no open dispute, suspended sellers included: we hold it, we do not own
 *    it, and a suspension is not a fine.
 */
import type { Db } from "../db/index.ts";
import { apply, accountFor, insufficientFunds } from "./ledger.ts";
import { HttpError, badRequest, conflict, notFound } from "./errors.ts";

export interface BondState {
  bondPico: number;
  postedAt: number | null;
}

export async function bondFor(db: Db, sellerUserId: string): Promise<BondState> {
  const row = await db.get<{ bond_pico: number; bond_posted_at: number | null }>(
    "SELECT bond_pico, bond_posted_at FROM sellers WHERE user_id = ?",
    [sellerUserId],
  );
  if (!row) throw notFound("no such seller");
  return {
    bondPico: Number(row.bond_pico ?? 0),
    postedAt: row.bond_posted_at === null ? null : Number(row.bond_posted_at),
  };
}

/**
 * Stake more. The money moves from available to held on the seller's own account, so it is
 * subject to the same non-negative guard as everything else, and the cool-off restarts:
 * otherwise a seller could top up for the badge, then withdraw the top-up immediately.
 */
export async function postBond(
  db: Db,
  input: { sellerUserId: string; amountPico: number; now?: number },
): Promise<BondState> {
  const now = input.now ?? Date.now();
  if (input.amountPico <= 0) throw badRequest("a bond must be a positive amount");
  return await db.transaction(async (tx) => {
    try {
      await apply(
        tx,
        [
          {
            accountId: accountFor(input.sellerUserId),
            userId: input.sellerUserId,
            kind: "bond_hold",
            availableDelta: -input.amountPico,
            heldDelta: input.amountPico,
          },
        ],
        now,
      );
    } catch (error) {
      if (error instanceof HttpError && error.code === "insufficient_balance") {
        throw insufficientFunds("your balance does not cover that bond");
      }
      throw error;
    }
    await tx.run(
      "UPDATE sellers SET bond_pico = bond_pico + ?, bond_posted_at = ? WHERE user_id = ?",
      [input.amountPico, now, input.sellerUserId],
    );
    return await bondFor(tx, input.sellerUserId);
  });
}

/** An order of this seller that is arguing right now. A bond cannot leave while one exists. */
export async function openDisputeCount(db: Db, sellerUserId: string): Promise<number> {
  const row = await db.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM orders WHERE seller_user_id = ? AND status = 'disputed'",
    [sellerUserId],
  );
  return Number(row?.count ?? 0);
}

/**
 * Give it back. Refused while a dispute is open or the cool-off has not run out — a bond a
 * seller can withdraw the moment an argument starts is decoration — and allowed for a
 * suspended seller, because their money is still their money.
 */
export async function releaseBond(
  db: Db,
  input: { sellerUserId: string; cooloffMs: number; now?: number },
): Promise<BondState> {
  const now = input.now ?? Date.now();
  const state = await bondFor(db, input.sellerUserId);
  if (state.bondPico === 0) throw conflict("there is no bond to release");
  if (state.postedAt !== null && now - state.postedAt < input.cooloffMs) {
    throw conflict("this bond is still within its cool-off period");
  }
  if ((await openDisputeCount(db, input.sellerUserId)) > 0) {
    throw conflict("a bond cannot be released while one of your orders is disputed");
  }
  return await db.transaction(async (tx) => {
    // Re-read inside the transaction, then *take* the bond with a compare-and-swap before a
    // single pico moves. A plain re-read is not enough: PostgreSQL runs these transactions
    // under READ COMMITTED with no row lock, so two releases racing both read the same stake
    // and both credit it — the seller would be paid twice for one bond (SEC-2026-008). The
    // guarded UPDATE is the same idiom the ledger uses for balances (`ledger.ts`, `apply`):
    // the loser of the race finds a row it no longer matches and stops here.
    const current = await tx.get<{ bond_pico: number }>(
      "SELECT bond_pico FROM sellers WHERE user_id = ?",
      [input.sellerUserId],
    );
    const amount = Number(current?.bond_pico ?? 0);
    if (amount === 0) throw conflict("there is no bond to release");
    const taken = await tx.get<{ user_id: string }>(
      `UPDATE sellers SET bond_pico = 0, bond_posted_at = NULL
        WHERE user_id = ? AND bond_pico = ?
        RETURNING user_id`,
      [input.sellerUserId, amount],
    );
    if (!taken) throw conflict("there is no bond to release");
    await apply(
      tx,
      [
        {
          accountId: accountFor(input.sellerUserId),
          userId: input.sellerUserId,
          kind: "bond_release",
          availableDelta: amount,
          heldDelta: -amount,
        },
      ],
      now,
    );
    return await bondFor(tx, input.sellerUserId);
  });
}

/**
 * A moderator's decision: this much of the seller's bond goes to this buyer, on this order.
 * Two movements that sum to zero, and no third one for the platform.
 */
export async function claimBond(
  db: Db,
  input: {
    orderId: string;
    sellerUserId: string;
    buyerUserId: string;
    amountPico: number;
    now?: number;
  },
): Promise<{ paidPico: number; bondPico: number }> {
  const now = input.now ?? Date.now();
  if (input.amountPico <= 0) throw badRequest("a claim must be a positive amount");
  return await db.transaction(async (tx) => {
    // Debit the bond column first, guarded, so that two claims racing on PostgreSQL cannot
    // both pass a read of the same balance (SEC-2026-008); the ledger movements below are
    // guarded the same way and the transaction holds both or neither.
    const debited = await tx.get<{ bond_pico: number }>(
      `UPDATE sellers SET bond_pico = bond_pico - ?
        WHERE user_id = ? AND bond_pico >= ?
        RETURNING bond_pico`,
      [input.amountPico, input.sellerUserId, input.amountPico],
    );
    if (!debited) throw conflict("that is more than this seller's bond holds");
    await apply(
      tx,
      [
        {
          accountId: accountFor(input.sellerUserId),
          userId: input.sellerUserId,
          kind: "bond_forfeit",
          availableDelta: 0,
          heldDelta: -input.amountPico,
          orderId: input.orderId,
        },
        {
          accountId: accountFor(input.buyerUserId),
          userId: input.buyerUserId,
          kind: "bond_compensation",
          availableDelta: input.amountPico,
          heldDelta: 0,
          orderId: input.orderId,
        },
      ],
      now,
    );
    return { paidPico: input.amountPico, bondPico: Number(debited.bond_pico) };
  });
}

/** Has this order already had a claim against it? One order, one compensation. */
export async function alreadyClaimed(db: Db, orderId: string): Promise<boolean> {
  const row = await db.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM ledger_entries WHERE order_id = ? AND kind = 'bond_compensation'",
    [orderId],
  );
  return Number(row?.count ?? 0) > 0;
}
