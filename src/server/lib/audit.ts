/**
 * Audit log for administrative actions only.
 *
 * What goes in: a moderator suspended an account, removed a listing, decided an
 * application. What never goes in: ordinary user activity, message metadata, addresses.
 * An audit trail that records everything is just a surveillance log with a nicer name.
 *
 * Three properties keep this from turning into one:
 *
 * 1. **Only privileged actions.** Every call site is in the moderation routes or is a
 *    refusal of a privileged action. Ordinary users generate no entries by using the site.
 * 2. **No content.** An entry names an actor, an action, a subject and a result. `note` is
 *    a short controlled value — a role name, a decision — never user text, never a reason
 *    field somebody will paste an address into. There is no plaintext, no key, no token,
 *    no password, and nothing derived from one; `test/audit.test.ts` asserts it.
 * 3. **It expires.** `pruneAuditLog` deletes entries older than the retention window
 *    (`AUDIT_RETENTION_MS`, one year by default). Oversight needs recent history; keeping
 *    it forever just builds the personal-data pile this project exists to avoid.
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
  /** A moderator settled a disputed order: the one order transition staff can make. */
  | "order.settled"
  | "review.hidden"
  /** An administrator approved or refused one payout. */
  | "withdrawal.decided"
  /**
   * An administrator resolved by hand a payout the worker took and never reported. Nothing
   * automatic can do this (ADR-0070), so the audit entry is the whole record of the judgement.
   */
  | "withdrawal.resolved"
  /** An administrator set or cleared an account's automatic payout ceiling. */
  | "payout_limit.set"
  /** An authenticated account was refused a privileged route: recorded, not silent. */
  | "privileged.denied";

/**
 * How the action ended. A denied attempt is worth more than a successful one during an
 * incident: it is the shape a compromised or curious staff account leaves behind.
 */
export type AuditResult = "ok" | "denied" | "failed";

/** Bounded, so a caller cannot smuggle a paragraph of personal data into `note`. */
const MAX_NOTE = 64;

export async function recordAudit(
  db: Db,
  entry: {
    actorUserId: string | null;
    action: AuditAction;
    subjectType: string;
    subjectId: string;
    note?: string;
    result?: AuditResult;
  },
): Promise<void> {
  await db.run(
    `INSERT INTO audit_log (id, actor_user_id, action, subject_type, subject_id, note, result, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      newId(),
      entry.actorUserId,
      entry.action,
      entry.subjectType,
      entry.subjectId,
      (entry.note ?? "").slice(0, MAX_NOTE),
      entry.result ?? "ok",
      Date.now(),
    ],
  );
}

/**
 * Retention. Called from housekeeping alongside the session and envelope sweeps, so the
 * administrative log ages out on the same schedule as everything else here.
 */
export async function pruneAuditLog(db: Db, retentionMs: number, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM audit_log WHERE created_at < ?", [now - retentionMs]);
}
