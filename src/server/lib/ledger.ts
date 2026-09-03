/**
 * The ledger: every piconero this platform holds, and why.
 *
 * The marketplace is custodial (ADR-0066), which means the honest version of this module is
 * double-entry bookkeeping rather than a `balance` column somebody increments. Three rules
 * hold everywhere below:
 *
 * 1. **A balance is never written without its ledger entry, in the same transaction.**
 *    `balances` is a running total that exists for speed; `ledger_entries` is the truth.
 *    `test/wallet.test.ts` re-adds the entries and compares.
 * 2. **Value moves, it is never created.** Every operation is a set of movements that either
 *    sums to zero (a hold, a settlement) or names the outside world (a confirmed deposit
 *    arriving, a payout leaving). There is no function that credits an account for nothing —
 *    the closest is `creditDeposit`, and it requires a transaction the wallet has seen.
 * 3. **An account cannot go negative.** Each UPDATE carries its own guard, so two requests
 *    racing to spend the same balance produce one success and one refusal rather than an
 *    overdraft; the CHECK constraints in migration 014 are the second line behind it.
 *
 * What this module deliberately does *not* do: touch Monero. It knows nothing about
 * addresses, nodes or keys — a deposit is credited by whoever watches the wallet, and a
 * payout is a row a separate process picks up (docs/PAYMENTS.md). The web application holds
 * no spend key, so the worst an attacker who owns this process can do is move numbers in a
 * database that a human reconciles against a wallet.
 */
import type { Db } from "../db/index.ts";
import { HttpError, conflict } from "./errors.ts";
import { newId } from "./ids.ts";

/** The platform's own account. Fees are moved here; nothing is minted here. */
export const PLATFORM_ACCOUNT = "platform";

export type LedgerKind =
  /** A confirmed incoming transfer, credited once. */
  | "deposit"
  /** Buyer's money committed to an open order, and the two ways it comes back out. */
  | "order_hold"
  | "order_release"
  /** Settlement of a completed order: what the seller earns, and the platform's fee. */
  | "order_earnings"
  | "order_fee"
  /** A payout: requested (held), sent (gone), or returned because it was not sent. */
  | "withdrawal_hold"
  | "withdrawal_sent"
  | "withdrawal_returned";

export interface Movement {
  accountId: string;
  /** Null for the platform account; the owner's id for a user account. */
  userId: string | null;
  kind: LedgerKind;
  availableDelta: number;
  heldDelta: number;
  orderId?: string | null;
  depositId?: string | null;
  withdrawalId?: string | null;
}

/**
 * 402 Payment Required, which for once is literally true: the request is well formed and
 * the account has not got the money.
 */
export const insufficientFunds = (message: string) =>
  new HttpError(402, "insufficient_balance", message);

/** A user's account id is their user id. One row per account, created on first use. */
export function accountFor(userId: string): string {
  return userId;
}

/**
 * The platform's cut of one order, in piconero, rounded *down* — the remainder stays with
 * the seller. At 5% and any price this marketplace allows the difference is at most one
 * piconero, and it goes to the person who did the work rather than to the house.
 */
export function feeFor(amountPico: number, feeBps: number): number {
  return Math.floor((amountPico * feeBps) / 10_000);
}

async function ensureAccount(tx: Db, accountId: string, userId: string | null): Promise<void> {
  await tx.run(
    `INSERT INTO balances (account_id, user_id, available_pico, held_pico, updated_at)
     VALUES (?, ?, 0, 0, ?) ON CONFLICT (account_id) DO NOTHING`,
    [accountId, userId, Date.now()],
  );
}

/**
 * Applies movements inside an open transaction. The guard in the WHERE clause is the whole
 * concurrency story: a balance that would go negative is not updated, and the caller is
 * told rather than the row being left in a state a CHECK constraint has to catch.
 */
export async function apply(tx: Db, movements: Movement[], now = Date.now()): Promise<void> {
  for (const movement of movements) {
    await ensureAccount(tx, movement.accountId, movement.userId);
    const moved = await tx.get<{ account_id: string }>(
      `UPDATE balances
          SET available_pico = available_pico + ?, held_pico = held_pico + ?, updated_at = ?
        WHERE account_id = ?
          AND available_pico + ? >= 0
          AND held_pico + ? >= 0
        RETURNING account_id`,
      [
        movement.availableDelta,
        movement.heldDelta,
        now,
        movement.accountId,
        movement.availableDelta,
        movement.heldDelta,
      ],
    );
    if (!moved) throw insufficientFunds("not enough balance for this operation");
    await tx.run(
      `INSERT INTO ledger_entries (id, account_id, kind, available_delta, held_delta,
                                   order_id, deposit_id, withdrawal_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        newId(),
        movement.accountId,
        movement.kind,
        movement.availableDelta,
        movement.heldDelta,
        movement.orderId ?? null,
        movement.depositId ?? null,
        movement.withdrawalId ?? null,
        now,
      ],
    );
  }
}

export interface Balance {
  availablePico: number;
  heldPico: number;
}

export async function balanceOf(db: Db, accountId: string): Promise<Balance> {
  const row = await db.get<{ available_pico: number; held_pico: number }>(
    "SELECT available_pico, held_pico FROM balances WHERE account_id = ?",
    [accountId],
  );
  return { availablePico: row?.available_pico ?? 0, heldPico: row?.held_pico ?? 0 };
}

/**
 * Credits a confirmed incoming transfer, once.
 *
 * Idempotent by construction: `deposits` has a unique key on (txid, subaddress index,
 * amount), so a watcher that re-reads the same transfer after a restart inserts nothing and
 * this returns null. That is the property that matters — a deposit credited twice is money
 * the platform does not have.
 *
 * `minPico` is the enforced minimum top-up (ADR-0067). A smaller transfer is *recorded* with
 * status `below_minimum` and no ledger entry: not credited, and equally not quietly kept —
 * the row is the platform's admission that the money arrived, it is shown to its owner on the
 * wallet screen, and it is what an operator refunds from by hand. Recording rather than
 * ignoring is the whole point; a payment the database does not mention is indistinguishable
 * from theft.
 */
export async function creditDeposit(
  db: Db,
  input: {
    userId: string;
    amountPico: number;
    txid: string;
    subaddressIndex: number;
    confirmations: number;
    minPico?: number;
  },
): Promise<string | null> {
  if (!Number.isInteger(input.amountPico) || input.amountPico <= 0) {
    throw new Error("a deposit is a positive whole number of piconero");
  }
  const credited = input.amountPico >= (input.minPico ?? 0);
  const id = newId();
  const now = Date.now();
  try {
    return await db.transaction(async (tx) => {
      await tx.run(
        `INSERT INTO deposits (id, user_id, amount_pico, txid, subaddress_index, confirmations,
                               status, detected_at, credited_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          input.userId,
          input.amountPico,
          input.txid,
          input.subaddressIndex,
          input.confirmations,
          credited ? "credited" : "below_minimum",
          now,
          credited ? now : null,
        ],
      );
      if (credited) {
        await apply(
          tx,
          [
            {
              accountId: accountFor(input.userId),
              userId: input.userId,
              kind: "deposit",
              availableDelta: input.amountPico,
              heldDelta: 0,
              depositId: id,
            },
          ],
          now,
        );
      }
      return id;
    });
  } catch (error) {
    // Anything the unique key refused is a transfer already credited, which is a success
    // for the caller: it asked for this deposit to exist exactly once.
    if (isDuplicate(error)) return null;
    throw error;
  }
}

function isDuplicate(error: unknown): boolean {
  const failure = error as { errcode?: number; code?: string };
  return (
    (typeof failure?.errcode === "number" && (failure.errcode & 0xff) === 19) ||
    (typeof failure?.code === "string" && failure.code.startsWith("23"))
  );
}

/** Buyer's money committed to an order. Throws 402 if it is not there. */
export async function holdForOrder(
  tx: Db,
  input: { userId: string; orderId: string; amountPico: number },
): Promise<void> {
  if (input.amountPico === 0) return; // a free listing needs no escrow
  try {
    await apply(tx, [
      {
        accountId: accountFor(input.userId),
        userId: input.userId,
        kind: "order_hold",
        availableDelta: -input.amountPico,
        heldDelta: input.amountPico,
        orderId: input.orderId,
      },
    ]);
  } catch (error) {
    if (error instanceof HttpError && error.code === "insufficient_balance") {
      throw insufficientFunds("top up your balance before placing this order");
    }
    throw error;
  }
}

/** The order ended without a sale: the hold goes back to the buyer, whole. */
export async function releaseHold(
  tx: Db,
  input: { userId: string; orderId: string; amountPico: number },
): Promise<void> {
  if (input.amountPico === 0) return;
  await apply(tx, [
    {
      accountId: accountFor(input.userId),
      userId: input.userId,
      kind: "order_release",
      availableDelta: input.amountPico,
      heldDelta: -input.amountPico,
      orderId: input.orderId,
    },
  ]);
}

/**
 * The order completed: the hold leaves the buyer, the seller is credited the price less the
 * platform fee, and the fee lands on the platform account. Three movements, one
 * transaction, and they sum to zero.
 */
export async function settleOrder(
  tx: Db,
  input: {
    orderId: string;
    buyerUserId: string;
    sellerUserId: string;
    amountPico: number;
    feeBps: number;
  },
): Promise<{ feePico: number; earningsPico: number }> {
  if (input.amountPico === 0) return { feePico: 0, earningsPico: 0 };
  const feePico = feeFor(input.amountPico, input.feeBps);
  const earningsPico = input.amountPico - feePico;
  await apply(tx, [
    {
      accountId: accountFor(input.buyerUserId),
      userId: input.buyerUserId,
      kind: "order_hold",
      availableDelta: 0,
      heldDelta: -input.amountPico,
      orderId: input.orderId,
    },
    {
      accountId: accountFor(input.sellerUserId),
      userId: input.sellerUserId,
      kind: "order_earnings",
      availableDelta: earningsPico,
      heldDelta: 0,
      orderId: input.orderId,
    },
    {
      accountId: PLATFORM_ACCOUNT,
      userId: null,
      kind: "order_fee",
      availableDelta: feePico,
      heldDelta: 0,
      orderId: input.orderId,
    },
  ]);
  return { feePico, earningsPico };
}

export type WithdrawalStatus =
  | "queued"
  | "approval_required"
  | "sending"
  | "sent"
  | "failed"
  | "rejected";

/**
 * Requests a payout: the amount leaves `available` for `held` immediately, so it cannot be
 * spent twice while it waits, and the row is either queued for the payout worker or parked
 * for a human.
 *
 * `limitPico` is this account's automatic ceiling — per request and per rolling 24 hours —
 * and it is why a compromise of this process is not a drained wallet. It is not a ceiling on
 * what the owner may withdraw: a larger amount is queued for an administrator, who approves
 * it and it goes out in one transaction (docs/PAYMENTS.md §Limits).
 */
export async function requestWithdrawal(
  db: Db,
  input: {
    userId: string;
    amountPico: number;
    address: string;
    limitPico: number;
  },
): Promise<{ id: string; status: WithdrawalStatus }> {
  const now = Date.now();
  const id = newId();
  return db.transaction(async (tx) => {
    const recent = await tx.get<{ total: number | null }>(
      `SELECT SUM(amount_pico) AS total FROM withdrawals
        WHERE user_id = ? AND requested_at > ? AND status IN ('queued', 'sending', 'sent')`,
      [input.userId, now - 24 * 60 * 60 * 1000],
    );
    const automatic =
      input.amountPico <= input.limitPico &&
      Number(recent?.total ?? 0) + input.amountPico <= input.limitPico;
    const status: WithdrawalStatus = automatic ? "queued" : "approval_required";
    await tx.run(
      `INSERT INTO withdrawals (id, user_id, amount_pico, address, address_hint, status,
                                requested_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, input.userId, input.amountPico, input.address, addressHint(input.address), status, now],
    );
    await apply(
      tx,
      [
        {
          accountId: accountFor(input.userId),
          userId: input.userId,
          kind: "withdrawal_hold",
          availableDelta: -input.amountPico,
          heldDelta: input.amountPico,
          withdrawalId: id,
        },
      ],
      now,
    );
    return { id, status };
  });
}

/**
 * This account's automatic payout ceiling, or the deployment default when it has none. Read
 * before every payout request rather than cached: an administrator lowering a limit means it
 * from the next request, not from the next restart.
 */
export async function payoutLimitFor(
  db: Db,
  userId: string,
  fallbackPico: number,
): Promise<number> {
  const row = await db.get<{ payout_limit_pico: number | null }>(
    "SELECT payout_limit_pico FROM balances WHERE account_id = ?",
    [accountFor(userId)],
  );
  return row?.payout_limit_pico ?? fallbackPico;
}

/**
 * Sets one account's automatic payout ceiling: a hand-set number, given to a seller when
 * their application is approved and changed later as they earn trust. Creates the balance row
 * if the account has never held money, so a limit can be granted before the first sale.
 */
export async function setPayoutLimit(
  db: Db,
  userId: string,
  limitPico: number | null,
): Promise<void> {
  await db.transaction(async (tx) => {
    await ensureAccount(tx, accountFor(userId), userId);
    await tx.run("UPDATE balances SET payout_limit_pico = ?, updated_at = ? WHERE account_id = ?", [
      limitPico,
      Date.now(),
      accountFor(userId),
    ]);
  });
}

/**
 * An administrator's decision on a parked payout. Approving only queues it — this process
 * cannot send anything, by design.
 */
export async function decideWithdrawal(
  db: Db,
  input: { id: string; approve: boolean; adminUserId: string },
): Promise<{ userId: string; amountPico: number }> {
  const now = Date.now();
  return db.transaction(async (tx) => {
    const row = await tx.get<{ user_id: string; amount_pico: number }>(
      `UPDATE withdrawals SET status = ?, decided_by = ?, settled_at = ?
        WHERE id = ? AND status = 'approval_required'
        RETURNING user_id, amount_pico`,
      [input.approve ? "queued" : "rejected", input.adminUserId, input.approve ? null : now, input.id],
    );
    if (!row) throw conflict("this payout is not awaiting a decision", "stale_status");
    if (!input.approve) {
      // A refused payout keeps no destination: the address was needed to send, and this one
      // is not being sent.
      await tx.run("UPDATE withdrawals SET address = NULL WHERE id = ?", [input.id]);
      await apply(
        tx,
        [
          {
            accountId: accountFor(row.user_id),
            userId: row.user_id,
            kind: "withdrawal_returned",
            availableDelta: row.amount_pico,
            heldDelta: -row.amount_pico,
            withdrawalId: input.id,
          },
        ],
        now,
      );
    }
    return { userId: row.user_id, amountPico: row.amount_pico };
  });
}

/**
 * The payout left the wallet. Called by the payout worker with the transaction id, which is
 * the only thing about a sent Monero payment worth keeping: the destination is deleted here,
 * because after this moment it is a permanent link between an account and a wallet and it
 * buys nothing.
 */
export async function markWithdrawalSent(
  db: Db,
  input: { id: string; txid: string; networkFeePico: number },
): Promise<void> {
  const now = Date.now();
  await db.transaction(async (tx) => {
    const row = await tx.get<{ user_id: string; amount_pico: number }>(
      `UPDATE withdrawals
          SET status = 'sent', txid = ?, network_fee_pico = ?, settled_at = ?, address = NULL
        WHERE id = ? AND status IN ('queued', 'sending')
        RETURNING user_id, amount_pico`,
      [input.txid, input.networkFeePico, now, input.id],
    );
    if (!row) throw conflict("this payout is not waiting to be sent", "stale_status");
    await apply(
      tx,
      [
        {
          accountId: accountFor(row.user_id),
          userId: row.user_id,
          kind: "withdrawal_sent",
          availableDelta: 0,
          heldDelta: -row.amount_pico,
          withdrawalId: input.id,
        },
      ],
      now,
    );
  });
}

/**
 * The owner changed their mind before the payout left. Returns false if there was nothing to
 * cancel — a payout already sent, already refused, or belonging to somebody else, all of
 * which are the same answer to the caller.
 */
export async function cancelWithdrawal(
  db: Db,
  input: { id: string; userId: string },
): Promise<boolean> {
  const now = Date.now();
  return db.transaction(async (tx) => {
    const row = await tx.get<{ amount_pico: number }>(
      `UPDATE withdrawals SET status = 'cancelled', settled_at = ?, address = NULL
        WHERE id = ? AND user_id = ? AND status IN ('queued', 'approval_required')
        RETURNING amount_pico`,
      [now, input.id, input.userId],
    );
    if (!row) return false;
    await apply(
      tx,
      [
        {
          accountId: accountFor(input.userId),
          userId: input.userId,
          kind: "withdrawal_returned",
          availableDelta: row.amount_pico,
          heldDelta: -row.amount_pico,
          withdrawalId: input.id,
        },
      ],
      now,
    );
    return true;
  });
}

/** The payout could not be sent: the money goes back to where the owner can use it. */
export async function markWithdrawalFailed(db: Db, id: string): Promise<void> {
  const now = Date.now();
  await db.transaction(async (tx) => {
    const row = await tx.get<{ user_id: string; amount_pico: number }>(
      `UPDATE withdrawals SET status = 'failed', settled_at = ?, address = NULL
        WHERE id = ? AND status IN ('queued', 'sending')
        RETURNING user_id, amount_pico`,
      [now, id],
    );
    if (!row) throw conflict("this payout is not waiting to be sent", "stale_status");
    await apply(
      tx,
      [
        {
          accountId: accountFor(row.user_id),
          userId: row.user_id,
          kind: "withdrawal_returned",
          availableDelta: row.amount_pico,
          heldDelta: -row.amount_pico,
          withdrawalId: id,
        },
      ],
      now,
    );
  });
}

/**
 * First six and last six characters of a destination. Enough for the owner to recognise
 * their own wallet in a list, useless for correlation: a Monero address appears nowhere in
 * the blockchain, so there is nothing to look it up in.
 */
export function addressHint(address: string): string {
  return address.length <= 14 ? address : `${address.slice(0, 6)}…${address.slice(-6)}`;
}
