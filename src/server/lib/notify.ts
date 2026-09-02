/**
 * Internal notifications (point 48).
 *
 * One function writes them, and its signature is the privacy rule: a `kind` from a closed
 * set, a subject that is a marketplace record the server can already see, and a `detail`
 * that is a status word this codebase chose. There is no parameter for free text, so no
 * caller can put a message, a review body or a moderator's note into the inbox by accident.
 *
 * A notification is a hint, never content. `message` says only that something arrived: the
 * client fetches its envelopes and decrypts them to learn what and from whom.
 */
import type { Db } from "../db/index.ts";
import { newId } from "./ids.ts";

export type NotificationKind =
  | "message"
  | "order"
  | "seller_application"
  | "moderation"
  | "review"
  | "dispute";

export interface NotificationInput {
  userId: string;
  kind: NotificationKind;
  subjectType?: "order" | "listing" | "review" | "user";
  subjectId?: string;
  /** A status word from this codebase (`placed`, `approved`, `suspended`…), never user text. */
  detail?: string;
}

/**
 * Writes one notification, or refreshes the single unread message hint.
 *
 * Notifying is never allowed to fail the action it describes: an order that was placed has
 * been placed, whether or not the recipient's inbox row was written. Callers that are inside
 * a transaction pass the transaction so the two commit together; callers that are not get
 * best-effort delivery.
 */
export async function notify(db: Db, input: NotificationInput): Promise<void> {
  const now = Date.now();
  if (input.kind === "message") {
    // Coalesced: one unread row per account, its timestamp moved forward. The partial
    // unique index `notifications_one_unread_message` is what actually holds under a race;
    // this UPDATE is what keeps the common case from hitting it.
    const refreshed = await db.get(
      `UPDATE notifications SET created_at = ?
        WHERE user_id = ? AND kind = 'message' AND read_at IS NULL RETURNING id`,
      [now, input.userId],
    );
    if (refreshed) return;
  }
  await db.run(
    `INSERT INTO notifications (id, user_id, kind, subject_type, subject_id, detail, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      newId(),
      input.userId,
      input.kind,
      input.subjectType ?? "",
      input.subjectId ?? "",
      input.detail ?? "",
      now,
    ],
  );
}

/**
 * Same thing, but a failure is swallowed. Used where the notification is a courtesy and the
 * action is the product: losing the race for the unread message hint must not turn a
 * delivered message into a 500.
 */
export async function notifyQuietly(db: Db, input: NotificationInput): Promise<void> {
  try {
    await notify(db, input);
  } catch {
    // Deliberately silent: there is nothing a user could do about it, and the alternative
    // is logging who was notified about what, which is the metadata this system does not keep.
  }
}

/** Retention: an inbox is a notice board, not a history. Called from housekeeping. */
export async function pruneNotifications(
  db: Db,
  retentionMs: number,
  now = Date.now(),
): Promise<void> {
  await db.run("DELETE FROM notifications WHERE created_at < ?", [now - retentionMs]);
}
