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
import { dayToIsoDate, today } from "../lib/time.ts";
import { asEnum, asId, asOptionalString, asString, asUsername } from "../lib/validate.ts";
import { destroyAllSessions } from "../lib/sessions.ts";

const REPORT_TARGETS = ["listing", "user", "review", "order"] as const;
const REPORT_REASONS = [
  "prohibited_goods",
  "fraud",
  "impersonation",
  "spam",
  "harassment",
  "other",
] as const;

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
    const details = asOptionalString(body.details, "details", 2000);

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
    return {
      reports: reports.map((row) => ({
        id: row.id,
        targetType: row.target_type,
        targetId: row.target_id,
        reason: row.reason,
        details: row.details,
        reporter: row.reporter,
        reportedOn: dayToIsoDate(row.created_day),
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
    const note = asOptionalString(body.note, "note", 1000);

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
    const note = asOptionalString((request.body as Record<string, unknown>)?.note, "note", 1000);
    const listing = await db.get<{ id: string }>("SELECT id FROM listings WHERE id = ?", [id]);
    if (!listing) throw notFound("no such listing");
    await db.run("UPDATE listings SET status = 'removed', updated_day = ? WHERE id = ?", [
      today(),
      id,
    ]);
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
    const reason = asOptionalString(body.reason, "reason", 500);

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
    } else {
      await db.run("UPDATE sellers SET status = 'active' WHERE user_id = ?", [target.id]);
    }
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
    const note = asOptionalString((request.body as Record<string, unknown>)?.note, "note", 1000);
    const review = await db.get<{ id: string }>("SELECT id FROM reviews WHERE id = ?", [id]);
    if (!review) throw notFound("no such review");
    await db.run("UPDATE reviews SET status = 'hidden' WHERE id = ?", [id]);
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
    const note = asOptionalString(body.note, "note", 1000);
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
