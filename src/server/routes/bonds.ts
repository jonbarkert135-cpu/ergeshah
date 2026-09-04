/**
 * Seller bonds (MKT-6, ADR-0086): three routes, and the reasoning is in `lib/bonds.ts`.
 *
 * A seller stakes money against their own conduct; a buyer sees the number before they
 * order; a moderator who upholds a dispute on an order that already *completed* — the case
 * escrow cannot fix, because the money has left it — may pay the buyer out of that stake.
 *
 * The claim route lives here rather than in `routes/moderation.ts` for two reasons: that
 * file is at its size limit, and everything about bonds is easier to review in one place
 * than spread across the module that happens to own the actor.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict, forbidden, notFound } from "../lib/errors.ts";
import { asId, asString } from "../lib/validate.ts";
import { parseXmr, xmrString } from "../../shared/money.ts";
import { recordAudit } from "../lib/audit.ts";
import {
  alreadyClaimed,
  bondFor,
  claimBond,
  openDisputeCount,
  openReportCount,
  postBond,
  releaseBond,
} from "../lib/bonds.ts";

/** The amount field, in XMR as a string, the way every other money route takes it. */
function amountPico(value: unknown, field: string): number {
  const parsed = parseXmr(asString(value, field, 32));
  if (parsed === null || parsed <= 0) throw badRequest(`${field} must be an amount in XMR`);
  return parsed;
}

export async function registerBondRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  async function ownSeller(userId: string): Promise<void> {
    const seller = await db.get<{ user_id: string }>(
      "SELECT user_id FROM sellers WHERE user_id = ?",
      [userId],
    );
    if (!seller) throw forbidden("only a seller can stake a bond");
  }

  /** Stake, or top up. */
  app.post("/api/market/seller/bond", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "write");
    await ownSeller(user.id);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const pico = amountPico(body.amountXmr, "amountXmr");
    if (pico < config.bondMinPico) {
      throw badRequest(`the smallest bond is ${xmrString(config.bondMinPico)} XMR`);
    }
    const state = await postBond(db, { sellerUserId: user.id, amountPico: pico });
    return {
      bondXmr: xmrString(state.bondPico),
      releasableInDays: Math.ceil(config.bondCooloffMs / 86_400_000),
    };
  });

  /** Take it back, if the conditions that make it a promise are satisfied. */
  app.post("/api/market/seller/bond/release", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "write");
    await ownSeller(user.id);
    const state = await releaseBond(db, {
      sellerUserId: user.id,
      cooloffMs: config.bondCooloffMs,
    });
    return { bondXmr: xmrString(state.bondPico) };
  });

  /** What I have staked, and what stands between me and getting it back. */
  app.get("/api/market/seller/bond", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    await ownSeller(user.id);
    const state = await bondFor(db, user.id);
    const disputes = await openDisputeCount(db, user.id);
    const reports = await openReportCount(db, user.id);
    const releasableAt =
      state.postedAt === null ? null : state.postedAt + config.bondCooloffMs;
    return {
      bondXmr: xmrString(state.bondPico),
      openDisputes: disputes,
      openReports: reports,
      releasable:
        state.bondPico > 0 &&
        disputes === 0 &&
        reports === 0 &&
        releasableAt !== null &&
        releasableAt <= Date.now(),
      releasableInDays:
        releasableAt === null
          ? null
          : Math.max(0, Math.ceil((releasableAt - Date.now()) / 86_400_000)),
    };
  });

  /**
   * A moderator pays a harmed buyer out of the seller's bond.
   *
   * Deliberately narrow. The order must be `completed` and must have been complained about —
   * disputed while it was open, or reported afterwards. While an order is open its own escrow
   * is the remedy, and cancelling it returns the buyer's money in full, so a bond claim there
   * would be a second payment for one loss. One claim per order, capped at what the buyer
   * paid, and never more than the bond holds.
   */
  app.post("/api/market/moderation/orders/:id/bond-claim", async (request) => {
    const moderator = await app.requireRole(request, ["moderator", "admin"]);
    await app.limit(request, "moderation");
    const orderId = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const order = await db.get<{
      id: string;
      status: string;
      buyer_user_id: string;
      seller_user_id: string;
      price_pico: number;
    }>(
      "SELECT id, status, buyer_user_id, seller_user_id, price_pico FROM orders WHERE id = ?",
      [orderId],
    );
    if (!order) throw notFound("no such order");
    // Conflict of interest: a claim pays the buyer out of the seller's bond, on the say-so
    // of the moderator. A moderator who is that buyer (or that seller) would be paying
    // themselves, or forgiving themselves; they get a stranger's answer here and take the
    // order to a colleague (SEC-2026-012).
    if (order.buyer_user_id === moderator.id || order.seller_user_id === moderator.id) {
      throw forbidden("a moderator cannot decide a bond claim on their own order");
    }
    if (order.status !== "completed") {
      throw conflict(
        "a bond claim belongs to an order that completed and went wrong afterwards: " +
          "while an order is open, settling it returns the buyer's money in full",
      );
    }
    // Somebody must have complained about *this order*, in one of the two ways the product
    // has: a dispute while it was open, or a report afterwards. An order is terminal once
    // completed (the state machine has no way back), which is exactly why the buyer's route
    // here is the report queue — and why a moderator acting on their own recollection, with
    // nothing on file, is not a path this route offers.
    const disputed = await db.get<{ count: number }>(
      "SELECT COUNT(*) AS count FROM order_events WHERE order_id = ? AND to_status = 'disputed'",
      [orderId],
    );
    // The report must be the buyer's own: `POST /api/moderation/reports` accepts any order
    // id from any account, so a report from anyone else would let a third account
    // manufacture the precondition for a claim (SEC-2026-012).
    const reported = await db.get<{ count: number }>(
      `SELECT COUNT(*) AS count FROM reports
        WHERE target_type = 'order' AND target_id = ? AND reporter_user_id = ?`,
      [orderId, order.buyer_user_id],
    );
    if (Number(disputed?.count ?? 0) === 0 && Number(reported?.count ?? 0) === 0) {
      throw conflict("nobody has disputed or reported this order");
    }
    if (await alreadyClaimed(db, orderId)) {
      throw conflict("this order has already been compensated from a bond");
    }
    const pico = amountPico(body.amountXmr, "amountXmr");
    if (pico > Number(order.price_pico)) {
      throw badRequest("a claim cannot exceed what the buyer paid for the order");
    }
    const note = asString(body.note ?? "", "note", 280);
    if (note.trim().length < 8) {
      throw badRequest("say why: a claim on someone's money needs a reason in the audit log");
    }

    const result = await claimBond(db, {
      orderId,
      sellerUserId: order.seller_user_id,
      buyerUserId: order.buyer_user_id,
      amountPico: pico,
    });
    await recordAudit(db, {
      actorUserId: moderator.id,
      action: "bond.claimed",
      subjectType: "order",
      subjectId: orderId,
      note: `${xmrString(pico)} XMR: ${note}`,
    });
    return {
      paidXmr: xmrString(result.paidPico),
      remainingBondXmr: xmrString(result.bondPico),
    };
  });
}
