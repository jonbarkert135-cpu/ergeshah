/**
 * Audit log for administrative actions only.
 *
 * What goes in: a moderator suspended an account, removed a listing, decided an
 * application. What never goes in: ordinary user activity, message metadata, addresses.
 * An audit trail that records everything is just a surveillance log with a nicer name.
 */
import type { Db } from "../db/index.ts";
import { newId } from "./ids.ts";

export type AuditAction =
  | "seller_application.decided"
  | "listing.removed"
  | "listing.restored"
  | "user.suspended"
  | "user.reinstated"
  | "user.role_changed"
  | "report.resolved"
  | "review.hidden";

export async function recordAudit(
  db: Db,
  entry: {
    actorUserId: string | null;
    action: AuditAction;
    subjectType: string;
    subjectId: string;
    note?: string;
  },
): Promise<void> {
  await db.run(
    `INSERT INTO audit_log (id, actor_user_id, action, subject_type, subject_id, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      newId(),
      entry.actorUserId,
      entry.action,
      entry.subjectType,
      entry.subjectId,
      entry.note ?? "",
      Date.now(),
    ],
  );
}
