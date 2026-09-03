/**
 * Moderation and administration.
 *
 * Moderators work with what is public: listings, reviews, seller applications, reports.
 * There is no "read messages" endpoint, no impersonation, and no way to disable a user's
 * encryption — those powers are absent from the codebase, not merely unexposed. Every
 * action a moderator takes is written to the audit log.
 */
import type { FastifyInstance } from "fastify";
import { recordAudit } from "../lib/audit.ts";
import { badRequest, conflict, notFound } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { xmrString } from "../../shared/money.ts";
import { dayToIsoDate, today } from "../lib/time.ts";
import {
  asEnum,
  asId,
  asOptionalText,
  asString,
  asUsername,
  asXmrAmount,
  onlyKeys,
  REPORT_REASONS,
  REPORT_TARGETS,
} from "../lib/validate.ts";
import { destroyAllSessions } from "../lib/sessions.ts";

import { notify, notifyQuietly } from "../lib/notify.ts";
import {
  decideWithdrawal,
  markWithdrawalFailed,
  markWithdrawalSent,
  PAYOUT_STUCK_MS,
  PLATFORM_ACCOUNT,
  setPayoutLimit,
} from "../lib/ledger.ts";
import { solvency } from "../lib/deposits.ts";
import { belowMinimumLiability } from "../lib/refunds.ts";
import { evidenceForOrder } from "../lib/evidence.ts";
import {
  penaliseSellerStanding,
  restoreSellerStanding,
  sellerReputation,
} from "../lib/reputation.ts";
import { quietly } from "../lib/monero.ts";

export async function registerModerationRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;
  const staff = ["moderator", "admin"] as const;

  app.post("/api/moderation/reports", async (request) => {
    const user = await app.authenticate(request);
       await app.limit(request, "moderation");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const targetType = asEnum(body.targetType, "targetType", REPORT_TARGETS);
    const targetId = asString(body.targetId, "targetId", 64);
    const reason = asEnum(body.reason, "reason", REPORT_REASONS);
    // A dispute is opened on the order itself (POST /api/market/orders/:id/status), which
    // checks that the reporter is the buyer; the bare report route must not offer a way
    // to file one against any order id.
    if (reason === "dispute") throw badRequest("open a dispute from the order");
    const details = asOptionalText(body.details, "details", 2000);

    const id = newId();
    await db.run(
      `INSERT INTO reports (id, target_type, target_id, reporter_user_id, reason, details, status, created_day)
       VALUES (?, ?, ?, ?, ?, ?, 'open', ?)`,
      [id, targetType, targetId, user.id, reason, details, today()],
    );
    return { id, status: "open" };
  });

  app.get("/api/moderation/queue", async (request) => {
    await app.requireRole(request, [...staff]);
       await app.limit(request, "moderation");
    const reports = await db.all<{
      id: string;
      target_type: string;
      target_id: string;
      reason: string;
      details: string;
      created_day: number;
      reporter: string;
    }>(
      `SELECT r.id, r.target_type, r.target_id, r.reason, r.details, r.created_day, u.username AS reporter
         FROM reports r JOIN users u ON u.id = r.reporter_user_id
        WHERE r.status = 'open' ORDER BY r.created_day, r.id LIMIT 100`,
    );
    const applications = await db.all<{
      id: string;
      display_name: string;
      statement: string;
      created_day: number;
      username: string;
    }>(
      `SELECT a.id, a.display_name, a.statement, a.created_day, u.username
         FROM seller_applications a JOIN users u ON u.id = a.user_id
        WHERE a.status = 'pending' ORDER BY a.created_day, a.id LIMIT 100`,
    );
    // A report about an order is a dispute (or a complaint) a moderator has to settle, and
    // settling needs the public facts of the order: what, who, where it stands, and how the
    // seller has fared before. Never the channel: the conversation stays unreadable.
    const orderIds = reports.filter((row) => row.target_type === "order").map((row) => row.target_id);
    const orders = new Map<string, Awaited<ReturnType<typeof orderSummary>>>();
    for (const id of orderIds) {
      const summary = await orderSummary(app, id);
      if (summary) orders.set(id, summary);
    }
    return {
      reports: reports.map((row) => ({
        id: row.id,
        targetType: row.target_type,
        targetId: row.target_id,
        reason: row.reason,
        details: row.details,
        reporter: row.reporter,
        reportedOn: dayToIsoDate(row.created_day),
        order: orders.get(row.target_id) ?? null,
      })),
      sellerApplications: applications.map((row) => ({
        id: row.id,
        username: row.username,
        displayName: row.display_name,
        statement: row.statement,
        submittedOn: dayToIsoDate(row.created_day),
      })),
    };
  });

  app.post("/api/moderation/seller-applications/:id/decide", async (request) => {
    const moderator = await app.requireRole(request, [...staff]);
    await app.limit(request, "moderation");
    const id = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const decision = asEnum(body.decision, "decision", ["approved", "rejected"] as const);
    const note = asOptionalText(body.note, "note", 1000);
    // How much this seller may take out without an administrator looking: set here, by hand,
    // at the moment somebody is deciding how much they trust them. Absent means the
    // deployment default, which is what an ordinary account gets (docs/PAYMENTS.md §Limits).
    const payoutLimitPico =
      body.payoutLimitXmr === undefined || body.payoutLimitXmr === null
        ? null
        : asXmrAmount(body.payoutLimitXmr, "payoutLimitXmr", 0);

    const application = await db.get<{
      id: string;
      user_id: string;
      display_name: string;
      status: string;
    }>("SELECT id, user_id, display_name, status FROM seller_applications WHERE id = ?", [id]);
    if (!application) throw notFound("no such application");
    if (application.status !== "pending") throw conflict("this application was already decided");

    await db.transaction(async (tx) => {
      // Two moderators deciding the same application at once: one decision is recorded,
      // the other is told it came second (point 44).
      const decided = await tx.get(
        `UPDATE seller_applications SET status = ?, decision_note = ?, decided_by = ?, decided_day = ?
          WHERE id = ? AND status = 'pending' RETURNING id`,
        [decision, note, moderator.id, today(), id],
      );
      if (!decided) throw conflict("this application was already decided");
      // The applicant is told the outcome by the same transaction that records it (point 48).
      await notify(tx, {
        userId: application.user_id,
        kind: "seller_application",
        detail: decision,
      });
      if (decision === "approved") {
        const taken = await tx.get("SELECT user_id FROM sellers WHERE display_name = ?", [
          application.display_name,
        ]);
        if (taken) throw conflict("that seller name was taken in the meantime");
        await tx.run(
          "INSERT INTO sellers (user_id, display_name, bio, status, joined_day) VALUES (?, ?, '', 'active', ?)",
          [application.user_id, application.display_name, today()],
        );
      }
    });
    if (decision === "approved" && payoutLimitPico !== null) {
      await setPayoutLimit(db, application.user_id, payoutLimitPico);
      await recordAudit(db, {
        actorUserId: moderator.id,
        action: "payout_limit.set",
        subjectType: "user",
        subjectId: application.user_id,
        note: xmrString(payoutLimitPico),
      });
    }
    await recordAudit(db, {
      actorUserId: moderator.id,
      action: "seller_application.decided",
      subjectType: "seller_application",
      subjectId: id,
      note: decision,
    });
    return { id, status: decision };
  });

  app.post("/api/moderation/listings/:id/remove", async (request) => {
    const moderator = await app.requireRole(request, [...staff]);
    await app.limit(request, "moderation");
    const id = asId((request.params as { id: string }).id, "id");
    const note = asOptionalText((request.body as Record<string, unknown>)?.note, "note", 1000);
    const listing = await db.get<{ id: string; seller_user_id: string }>(
      "SELECT id, seller_user_id FROM listings WHERE id = ?",
      [id],
    );
    if (!listing) throw notFound("no such listing");
    await db.run("UPDATE listings SET status = 'removed', updated_day = ? WHERE id = ?", [
      today(),
      id,
    ]);
    // A moderation action a seller is not told about is one they can only discover by
    // noticing the absence of their own listing.
    await notifyQuietly(db, {
      userId: listing.seller_user_id,
      kind: "moderation",
      subjectType: "listing",
      subjectId: id,
      detail: "removed",
    });
    await recordAudit(db, {
      actorUserId: moderator.id,
      action: "listing.removed",
      subjectType: "listing",
      subjectId: id,
      note,
    });
    return { ok: true };
  });

  app.post("/api/moderation/users/:username/status", async (request) => {
    const moderator = await app.requireRole(request, [...staff]);
    await app.limit(request, "moderation");
    const username = asUsername((request.params as { username: string }).username);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const status = asEnum(body.status, "status", ["active", "suspended"] as const);
    const reason = asOptionalText(body.reason, "reason", 500);

    const target = await db.get<{ id: string; role: string }>(
      "SELECT id, role FROM users WHERE username = ?",
      [username],
    );
    if (!target) throw notFound("no such user");
    if (target.role === "admin" && moderator.role !== "admin") {
      throw badRequest("only an admin can change another admin", "forbidden");
    }
    if (target.id === moderator.id) throw badRequest("you cannot suspend yourself");

    await db.run("UPDATE users SET status = ?, status_reason = ? WHERE id = ?", [
      status,
      status === "suspended" ? reason : null,
      target.id,
    ]);
    if (status === "suspended") {
      await destroyAllSessions(db, target.id);
      await db.run("UPDATE sellers SET status = 'suspended' WHERE user_id = ?", [target.id]);
      // The listings go out of the catalogue with the suspension; the standing behind them
      // used to survive it untouched, so a reinstated account came back above every seller
      // who had been trading honestly throughout. It costs a level now (ADR-0072).
      await penaliseSellerStanding(db, target.id, {
        decayDays: app.config.sellerLevelDecayDays,
      });
    } else {
      await db.run("UPDATE sellers SET status = 'active' WHERE user_id = ?", [target.id]);
      // Back in the catalogue at the standing their own trade currently supports — the
      // penalty stays, and so does whatever dormancy accumulated while they were gone.
      await restoreSellerStanding(db, target.id, {
        decayDays: app.config.sellerLevelDecayDays,
      });
    }
    await notifyQuietly(db, {
      userId: target.id,
      kind: "moderation",
      subjectType: "user",
      subjectId: target.id,
      detail: status === "suspended" ? "suspended" : "reinstated",
    });
    await recordAudit(db, {
      actorUserId: moderator.id,
      action: status === "suspended" ? "user.suspended" : "user.reinstated",
      subjectType: "user",
      subjectId: target.id,
      note: reason,
    });
    return { username, status };
  });

  app.post("/api/moderation/reviews/:id/hide", async (request) => {
    const moderator = await app.requireRole(request, [...staff]);
    await app.limit(request, "moderation");
    const id = asId((request.params as { id: string }).id, "id");
    const note = asOptionalText((request.body as Record<string, unknown>)?.note, "note", 1000);
    const review = await db.get<{ id: string; author_user_id: string }>(
      "SELECT id, author_user_id FROM reviews WHERE id = ?",
      [id],
    );
    if (!review) throw notFound("no such review");
    await db.run("UPDATE reviews SET status = 'hidden' WHERE id = ?", [id]);
    await notifyQuietly(db, {
      userId: review.author_user_id,
      kind: "moderation",
      subjectType: "review",
      subjectId: id,
      detail: "hidden",
    });
    await recordAudit(db, {
      actorUserId: moderator.id,
      action: "review.hidden",
      subjectType: "review",
      subjectId: id,
      note,
    });
    return { ok: true };
  });

  app.post("/api/moderation/reports/:id/resolve", async (request) => {
    const moderator = await app.requireRole(request, [...staff]);
    await app.limit(request, "moderation");
    const id = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const outcome = asEnum(body.outcome, "outcome", ["actioned", "dismissed"] as const);
    const note = asOptionalText(body.note, "note", 1000);
    const report = await db.get<{ id: string; status: string }>(
      "SELECT id, status FROM reports WHERE id = ?",
      [id],
    );
    if (!report) throw notFound("no such report");
    if (report.status !== "open") throw conflict("this report is already resolved");
    const resolved = await db.get(
      `UPDATE reports SET status = ?, resolution_note = ?, resolved_by = ?, resolved_day = ?
        WHERE id = ? AND status = 'open' RETURNING id`,
      [outcome, note, moderator.id, today(), id],
    );
    if (!resolved) throw conflict("this report is already resolved");
    await recordAudit(db, {
      actorUserId: moderator.id,
      action: "report.resolved",
      subjectType: "report",
      subjectId: id,
      note: outcome,
    });
    return { id, status: outcome };
  });

  app.post("/api/admin/users/:username/role", async (request) => {
    const admin = await app.requireRole(request, ["admin"]);
    const username = asUsername((request.params as { username: string }).username);
    const role = asEnum((request.body as Record<string, unknown>)?.role, "role", [
      "user",
      "moderator",
      "admin",
    ] as const);
    const target = await db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
      username,
    ]);
    if (!target) throw notFound("no such user");
    if (target.id === admin.id) throw badRequest("you cannot change your own role");
    await db.run("UPDATE users SET role = ? WHERE id = ?", [role, target.id]);
    await recordAudit(db, {
      actorUserId: admin.id,
      action: "user.role_changed",
      subjectType: "user",
      subjectId: target.id,
      note: role,
    });
    return { username, role };
  });

  /* ------------------------------- money oversight ------------------------------- */

  /**
   * Changes one account's automatic payout ceiling.
   *
   * Admin only, and audited with the amount: this is the dial that decides how much a stolen
   * session or a compromised server could move without a human, so who changed it and to what
   * is part of the record. `"default"` puts the account back on the deployment default.
   */
  app.post("/api/admin/users/:username/payout-limit", async (request) => {
    const admin = await app.requireRole(request, ["admin"]);
    await app.limit(request, "moderation");
    const username = asUsername((request.params as { username: string }).username);
    const raw = (request.body as Record<string, unknown>)?.limitXmr;
    const limitPico = raw === "default" ? null : asXmrAmount(raw, "limitXmr", 0);
    const target = await db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
      username,
    ]);
    if (!target) throw notFound("no such user");
    await setPayoutLimit(db, target.id, limitPico);
    await recordAudit(db, {
      actorUserId: admin.id,
      action: "payout_limit.set",
      subjectType: "user",
      subjectId: target.id,
      note: limitPico === null ? "default" : xmrString(limitPico),
    });
    return { username, limitXmr: limitPico === null ? null : xmrString(limitPico) };
  });

  /**
   * Payouts waiting for a human, oldest first.
   *
   * Readable by staff, decidable by an admin only (below): a moderator handling disputes has
   * no business moving money, and the split is what makes the audit log worth reading.
   * Destinations appear as hints — the full address is needed by the payout worker and by
   * nobody in this interface.
   */
  app.get("/api/moderation/withdrawals", async (request) => {
    await app.requireRole(request, [...staff]);
    await app.limit(request, "moderation");
    const rows = await db.all<{
      id: string;
      amount_pico: number;
      address_hint: string;
      status: string;
      requested_at: number;
      claimed_at: number | null;
      username: string;
    }>(
      `SELECT w.id, w.amount_pico, w.address_hint, w.status, w.requested_at, w.claimed_at,
              u.username
         FROM withdrawals w JOIN users u ON u.id = w.user_id
        WHERE w.status IN ('approval_required', 'queued', 'sending')
        ORDER BY w.requested_at ASC LIMIT 100`,
    );
    const now = Date.now();
    return {
      withdrawals: rows.map((row) => ({
        id: row.id,
        username: row.username,
        amountXmr: xmrString(row.amount_pico),
        addressHint: row.address_hint,
        status: row.status,
        requestedOn: dayToIsoDate(Math.floor(row.requested_at / 86_400_000)),
        // For a payout the worker has taken: how long it has been gone, and whether that is
        // long enough to need a human (ADR-0073). Null for everything still in the queue.
        sendingForMinutes:
          row.claimed_at === null ? null : Math.floor((now - row.claimed_at) / 60_000),
        stuck: row.claimed_at !== null && now - row.claimed_at > PAYOUT_STUCK_MS,
      })),
    };
  });

  /**
   * Approve or refuse one payout. Approving does not send anything: it moves the row into the
   * queue the payout worker reads, and that worker is the only thing in this system that
   * holds a spend key (docs/PAYMENTS.md). Refusing returns the money to the owner's
   * spendable balance in the same transaction.
   */
  app.post("/api/moderation/withdrawals/:id/decide", async (request) => {
    const admin = await app.requireRole(request, ["admin"]);
    await app.limit(request, "moderation");
    const id = asId((request.params as { id: string }).id, "id");
    const decision = asEnum((request.body as Record<string, unknown>)?.decision, "decision", [
      "approved",
      "rejected",
    ] as const);
    const approve = decision === "approved";
    const settled = await decideWithdrawal(db, { id, approve, adminUserId: admin.id });
    await recordAudit(db, {
      actorUserId: admin.id,
      action: "withdrawal.decided",
      subjectType: "withdrawal",
      subjectId: id,
      note: decision,
    });
    // The owner is told a decision was made about their payout; the word is this codebase's,
    // and the amount is already theirs to see.
    await notifyQuietly(db, { userId: settled.userId, kind: "payout", detail: decision });
    return { id, status: approve ? "queued" : "rejected" };
  });

  /**
   * Resolves a payout the worker took and never reported (ADR-0073).
   *
   * This is the manual half of a deliberate decision: nothing re-queues a `sending` payout,
   * because only the process with the spend key knows whether a transaction was signed, and
   * an automatic retry on an uncertain outcome pays somebody twice. So a human reads their
   * own wallet history and says which of the two things happened — and that is all this route
   * does. It sends nothing; it cannot.
   *
   * Admin only, audited, and refused for anything that is not `sending`: a queued payout
   * belongs to the worker, and marking one sent by hand would strand money that never left.
   */
  app.post("/api/moderation/withdrawals/:id/resolve", async (request) => {
    const admin = await app.requireRole(request, ["admin"]);
    await app.limit(request, "moderation");
    const id = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    onlyKeys(body, ["outcome", "txid", "networkFeeXmr"]);
    const outcome = asEnum(body.outcome, "outcome", ["sent", "failed"] as const);

    const row = await db.get<{ user_id: string; status: string }>(
      "SELECT user_id, status FROM withdrawals WHERE id = ?",
      [id],
    );
    if (!row) throw notFound("no such payout");
    if (row.status !== "sending") {
      throw conflict("only a payout the worker has taken can be resolved by hand", "stale_status");
    }

    if (outcome === "sent") {
      // The transaction id is not decoration: it is the payee's receipt, and requiring it
      // means an operator has to have found the transfer before they can say it happened.
      const txid = body.txid;
      if (typeof txid !== "string" || !/^[0-9a-f]{64}$/.test(txid)) {
        throw badRequest("txid must be a 64-character Monero transaction hash", "invalid_txid");
      }
      const networkFeePico = asXmrAmount(body.networkFeeXmr ?? "0", "networkFeeXmr", 0);
      await markWithdrawalSent(db, { id, txid, networkFeePico });
    } else {
      // Nothing left the wallet, so the money goes back to where its owner can use it.
      await markWithdrawalFailed(db, id);
    }
    await recordAudit(db, {
      actorUserId: admin.id,
      action: "withdrawal.resolved",
      subjectType: "withdrawal",
      subjectId: id,
      note: outcome,
    });
    await notifyQuietly(db, { userId: row.user_id, kind: "payout", detail: outcome });
    return { id, status: outcome };
  });

  /**
   * The books, in one answer: what users are owed, what the platform has earned, and what is
   * committed to open orders and queued payouts.
   *
   * Admin only, and it names nobody — this is the total an operator reconciles against the
   * wallet, not a list of who holds what. If `liabilities` ever exceeds what the wallet
   * actually holds, the platform is insolvent and this is the number that says so before a
   * seller does.
   */
  app.get("/api/admin/treasury", async (request) => {
    await app.requireRole(request, ["admin"]);
    await app.limit(request, "moderation");
    const users = await db.get<{ available: number | null; held: number | null }>(
      `SELECT SUM(available_pico) AS available, SUM(held_pico) AS held
         FROM balances WHERE account_id <> ?`,
      [PLATFORM_ACCOUNT],
    );
    const platform = await db.get<{ available_pico: number; held_pico: number }>(
      "SELECT available_pico, held_pico FROM balances WHERE account_id = ?",
      [PLATFORM_ACCOUNT],
    );
    const available = Number(users?.available ?? 0);
    const held = Number(users?.held ?? 0);
    const earned = Number(platform?.available_pico ?? 0);
    const queued = await db.get<{ total: number | null }>(
      "SELECT SUM(amount_pico) AS total FROM withdrawals WHERE status IN ('queued', 'approval_required', 'sending')",
    );
    // Top-ups that arrived below the minimum and were never credited (ADR-0067). They are
    // in the wallet and they are owed to whoever sent them — either refunded on request
    // (ADR-0071) or by hand — so they belong in the liability, not in the surplus.
    const uncredited = await belowMinimumLiability(db);
    // The comparison that matters, when there is a wallet to compare against: what the books
    // say is owed, against what the wallet actually holds. A deployment with no Monero tier
    // gets nulls rather than a reassuring zero (ADR-0070).
    const books = app.wallet
      ? await quietly("treasury.solvency_failed", () => solvency(db, app.wallet!))
      : null;
    return {
      userAvailableXmr: xmrString(available),
      userHeldXmr: xmrString(held),
      platformEarnedXmr: xmrString(earned),
      queuedPayoutsXmr: xmrString(Number(queued?.total ?? 0)),
      uncreditedTopUpsXmr: xmrString(uncredited),
      // What the wallet must hold for this platform to be solvent, fees and uncredited
      // top-ups included.
      liabilitiesXmr: xmrString(available + held + earned + uncredited),
      walletXmr: books ? xmrString(books.walletPico) : null,
      shortfallXmr: books ? xmrString(books.shortfallPico) : null,
      orderFeePercent: app.config.orderFeeBps / 100,
    };
  });

  /** The audit log is readable by staff: oversight that only admins can see is not oversight. */
  app.get("/api/moderation/audit", async (request) => {
    await app.requireRole(request, [...staff]);
       await app.limit(request, "moderation");
    const rows = await db.all<{
      id: string;
      action: string;
      subject_type: string;
      subject_id: string;
      note: string;
      created_at: number;
      actor: string | null;
    }>(
      `SELECT a.id, a.action, a.subject_type, a.subject_id, a.note, a.created_at, u.username AS actor
         FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
        ORDER BY a.created_at DESC LIMIT 200`,
    );
    return {
      entries: rows.map((row) => ({
        id: row.id,
        actor: row.actor,
        action: row.action,
        subjectType: row.subject_type,
        subjectId: row.subject_id,
        note: row.note,
        at: new Date(row.created_at).toISOString(),
      })),
    };
  });
}

/** The public facts of one order, for a moderator settling a report about it. */
async function orderSummary(app: FastifyInstance, id: string) {
  const row = await app.db.get<{
    id: string;
    status: string;
    title: string;
    kind: string;
    price_pico: number;
    buyer: string;
    seller: string;
    buyer_user_id: string;
    seller_user_id: string;
    updated_at: number;
  }>(
    `SELECT o.id, o.status, l.title, l.kind, o.price_pico, o.updated_at, o.seller_user_id,
            o.buyer_user_id, b.username AS buyer, s.username AS seller
       FROM orders o
       JOIN listings l ON l.id = o.listing_id
       JOIN users b ON b.id = o.buyer_user_id
       JOIN users s ON s.id = o.seller_user_id
      WHERE o.id = ?`,
    [id],
  );
  if (!row) return null;
  return {
    id: row.id,
    status: row.status,
    title: row.title,
    kind: row.kind,
    priceXmr: xmrString(row.price_pico),
    buyer: row.buyer,
    seller: row.seller,
    updatedOn: dayToIsoDate(Math.floor(row.updated_at / 86_400_000)),
    sellerRecord: await sellerReputation(app.db, row.seller_user_id),
    // The digests both parties committed to, and whether each was published before the
    // argument started (ADR-0074). It is not evidence that a file was good — it is proof
    // that neither side's story has changed since.
    evidence: await evidenceForOrder(app.db, row),
  };
}
