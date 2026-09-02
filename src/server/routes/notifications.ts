/**
 * The notification inbox: read it, and mark it read (point 48).
 *
 * Paginated the same way listing search is — a cursor over `(created_at, id)`, no offsets,
 * no total count — because an inbox is the other place where "page 400" invites a scan.
 */
import type { FastifyInstance } from "fastify";
import { asArray, asId, asInteger } from "../lib/validate.ts";
import { parseCursor } from "../lib/search.ts";

interface Row {
  id: string;
  kind: string;
  subject_type: string;
  subject_id: string;
  detail: string;
  created_at: number;
  read_at: number | null;
}

export async function registerNotificationRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;

  app.get("/api/notifications", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const query = request.query as Record<string, string | undefined>;
    const limit = query.limit ? asInteger(query.limit, "limit", 1, 50) : 20;
    const cursor = parseCursor(query.cursor);
    const params: unknown[] = [user.id];
    let where = "user_id = ?";
    if (cursor) {
      where += " AND (created_at < ? OR (created_at = ? AND id < ?))";
      params.push(cursor.key, cursor.key, cursor.id);
    }
    params.push(limit + 1);
    const rows = await db.all<Row>(
      // Column names are literals; `where` is built from the two literal strings above.
      // audit:allow
      `SELECT id, kind, subject_type, subject_id, detail, created_at, read_at
         FROM notifications WHERE ${where}
        ORDER BY created_at DESC, id DESC LIMIT ?`,
      params,
    );
    const page = rows.slice(0, limit);
    const last = page.at(-1);
    // The unread count is cheap (one account's unread rows, covered by the inbox index) and
    // it is what the client puts in the navigation.
    const unread = await db.get<{ n: number }>(
      "SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read_at IS NULL",
      [user.id],
    );
    return {
      notifications: page.map((row) => ({
        id: row.id,
        kind: row.kind,
        subjectType: row.subject_type || null,
        subjectId: row.subject_id || null,
        detail: row.detail || null,
        at: row.created_at,
        read: row.read_at !== null,
      })),
      unread: unread?.n ?? 0,
      nextCursor: rows.length > limit && last ? `${last.created_at}.${last.id}` : null,
    };
  });

  /** Mark specific notifications read, or the whole inbox. Reading is the only mutation. */
  app.post("/api/notifications/read", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "write");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const now = Date.now();
    if (body.all === true) {
      await db.run(
        "UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL",
        [now, user.id],
      );
      return { ok: true };
    }
    const ids = asArray(body.ids, "ids", 50).map((id) => asId(id, "ids[]"));
    await db.transaction(async (tx) => {
      for (const id of ids) {
        // Scoped to the account: an id from someone else's inbox matches nothing.
        await tx.run(
          "UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at IS NULL",
          [now, id, user.id],
        );
      }
    });
    return { ok: true };
  });
}
