/**
 * The account's money: what it holds, where a top-up goes, and how it leaves.
 *
 * This module is deliberately small, because the interesting decisions are elsewhere: the
 * bookkeeping is `lib/ledger.ts`, the Monero side is a separate process that this server
 * cannot even reach (docs/PAYMENTS.md), and the fee is charged by the order state machine in
 * `routes/market.ts`. What is left here is a balance to show, a history to page through, and
 * a payout to request.
 *
 * Two things this route does not have. There is no endpoint that credits a balance: money
 * appears only when a watcher with the wallet's *view* key sees a confirmed transfer, so
 * there is nothing for a compromised session to call. And there is no transfer between
 * accounts — an internal payment rail with no order attached to it is a money transmitter's
 * product, and it is the first thing an abuser of a marketplace looks for.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, notFound } from "../lib/errors.ts";
import { dayToIsoDate } from "../lib/time.ts";
import { asId, asMoneroAddress, asXmrAmount, onlyKeys } from "../lib/validate.ts";
import {
  accountFor,
  addressHint,
  balanceOf,
  cancelWithdrawal,
  payoutLimitFor,
  requestWithdrawal,
  type LedgerKind,
} from "../lib/ledger.ts";
import { depositAddressFor } from "../lib/deposits.ts";
import { quietly } from "../lib/monero.ts";
import { xmrString } from "../../shared/money.ts";

/** Ledger kinds as a person reads them, so the client renders a word rather than a code. */
const ENTRY_LABELS: Record<LedgerKind, string> = {
  deposit: "top-up",
  order_hold: "held for an order",
  order_release: "returned from an order",
  order_earnings: "earned on a sale",
  order_fee: "marketplace fee",
  withdrawal_hold: "payout requested",
  withdrawal_sent: "payout sent",
  withdrawal_returned: "payout returned",
};

export async function registerWalletRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  /**
   * The balance, the deposit address, and the numbers a client needs to explain the rules
   * without hard-coding them: the fee, the minimum payout, and the point above which a
   * payout waits for a human.
   */
  app.get("/api/wallet", async (request) => {
    await app.limit(request, "read");
    const user = await app.authenticate(request);
    const balance = await balanceOf(db, accountFor(user.id));
    // Created on first sight of this screen, from the wallet itself, and stored for good: an
    // account keeps one address for its lifetime, so a payer who saved it can use it again
    // (lib/deposits.ts). A wallet that is down answers null and the screen says so.
    const address = await quietly("wallet.address_failed", () =>
      depositAddressFor(db, app.wallet, user.id),
    );
    return {
      availableXmr: xmrString(balance.availablePico),
      heldXmr: xmrString(balance.heldPico),
      // Null until this deployment has a wallet: the address is one the wallet generated,
      // never one this server invented. A client shows "top-ups are not open yet" rather
      // than an address nobody controls.
      depositAddress: address ?? null,
      minDepositXmr: xmrString(config.minDepositPico),
      // Enforced, not advertised (ADR-0067): a smaller transfer is recorded and not credited.
      // The total sits here so the owner sees it on their own screen instead of finding a
      // balance that does not match what they sent.
      belowMinimumXmr: xmrString(
        Number(
          (
            await db.get<{ total: number | null }>(
              "SELECT SUM(amount_pico) AS total FROM deposits WHERE user_id = ? AND status = 'below_minimum'",
              [user.id],
            )
          )?.total ?? 0,
        ),
      ),
      minWithdrawalXmr: xmrString(config.minWithdrawalPico),
      // The account's own automatic ceiling, so the screen can say "above this a payout waits
      // for approval" with the number that will actually apply to this person.
      reviewAboveXmr: xmrString(await payoutLimitFor(db, user.id, config.autoPayoutMaxPico)),
      orderFeePercent: config.orderFeeBps / 100,
    };
  });

  /**
   * The account's own ledger. Every movement, with the order it belongs to when it has one:
   * this is the page that answers "why is my balance this number", which is the question a
   * custodial platform owes an answer to.
   */
  app.get("/api/wallet/entries", async (request) => {
    await app.limit(request, "read");
    const user = await app.authenticate(request);
    const rows = await db.all<{
      kind: LedgerKind;
      available_delta: number;
      held_delta: number;
      order_id: string | null;
      created_at: number;
    }>(
      `SELECT kind, available_delta, held_delta, order_id, created_at
         FROM ledger_entries WHERE account_id = ?
        ORDER BY created_at DESC, id DESC LIMIT 100`,
      [accountFor(user.id)],
    );
    return {
      entries: rows.map((row) => ({
        kind: row.kind,
        label: ENTRY_LABELS[row.kind] ?? row.kind,
        // Signed strings: a movement is not an amount, and hiding the direction in a colour
        // would leave the API lying to anything that is not a browser.
        availableXmr: signed(row.available_delta),
        heldXmr: signed(row.held_delta),
        orderId: row.order_id,
        // Day granularity, like every other long-lived timestamp here (ADR-0018): the hour
        // a person moved money is not a fact this database needs to keep.
        on: dayToIsoDate(Math.floor(row.created_at / 86_400_000)),
      })),
    };
  });

  /**
   * Requests a payout.
   *
   * The amount leaves the spendable balance now, so it cannot be spent twice while it waits.
   * Whether it goes to the queue or to an administrator is `lib/ledger.ts`'s decision, and
   * the answer says which happened — a client that pretends everything is instant is a
   * client that will be accused of losing money.
   */
  app.post("/api/wallet/withdrawals", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "wallet_write");
    const body = (request.body ?? {}) as Record<string, unknown>;
    onlyKeys(body, ["amountXmr", "address"]);
    const amountPico = asXmrAmount(body.amountXmr, "amountXmr", config.minWithdrawalPico);
    const address = asMoneroAddress(body.address, "address");

    const pending = await db.get<{ id: string }>(
      "SELECT id FROM withdrawals WHERE user_id = ? AND status IN ('queued', 'approval_required', 'sending')",
      [user.id],
    );
    // One payout at a time per account. Not a technical limit: it keeps the queue readable,
    // it makes the daily ceiling mean something, and it removes the class of bug where two
    // requests share a balance check.
    if (pending) throw badRequest("finish or cancel your pending payout first", "payout_pending");

    const created = await requestWithdrawal(db, {
      userId: user.id,
      amountPico,
      address,
      limitPico: await payoutLimitFor(db, user.id, config.autoPayoutMaxPico),
    });
    return {
      id: created.id,
      status: created.status,
      amountXmr: xmrString(amountPico),
      addressHint: addressHint(address),
    };
  });

  /** The account's own payouts. The destination is shown as a hint, never in full. */
  app.get("/api/wallet/withdrawals", async (request) => {
    await app.limit(request, "read");
    const user = await app.authenticate(request);
    const rows = await db.all<{
      id: string;
      amount_pico: number;
      address_hint: string;
      status: string;
      txid: string | null;
      network_fee_pico: number | null;
      requested_at: number;
    }>(
      `SELECT id, amount_pico, address_hint, status, txid, network_fee_pico, requested_at
         FROM withdrawals WHERE user_id = ? ORDER BY requested_at DESC LIMIT 50`,
      [user.id],
    );
    return {
      withdrawals: rows.map((row) => ({
        id: row.id,
        amountXmr: xmrString(row.amount_pico),
        addressHint: row.address_hint,
        status: row.status,
        // The transaction id is the payee's receipt: with it and their own wallet they can
        // prove the payment arrived, without asking this server to be believed.
        txid: row.txid,
        networkFeeXmr: row.network_fee_pico === null ? null : xmrString(row.network_fee_pico),
        requestedOn: dayToIsoDate(Math.floor(row.requested_at / 86_400_000)),
      })),
    };
  });

  /**
   * Cancels a payout that has not been sent. The money goes back to the spendable balance,
   * and the destination is forgotten.
   */
  app.post("/api/wallet/withdrawals/:id/cancel", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "wallet_write");
    const id = asId((request.params as { id: string }).id, "id");
    const cancelled = await cancelWithdrawal(db, { id, userId: user.id });
    if (!cancelled) throw notFound("no such payout");
    return { id, status: "cancelled" };
  });
}

function signed(delta: number): string {
  if (delta === 0) return "0";
  return delta > 0 ? `+${xmrString(delta)}` : `-${xmrString(-delta)}`;
}
