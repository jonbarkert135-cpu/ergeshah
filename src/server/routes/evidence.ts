/**
 * Committing to dispute evidence, and reading what has been committed (ADR-0074).
 *
 * Two routes, and between them they do less than any other module in this directory: they
 * store 64 characters of hex a browser computed, and they hand the list back. The server
 * never sees the file, never computes the digest, and never checks that a digest corresponds
 * to anything — it cannot, and a route that pretended otherwise would be lying to a
 * moderator.
 *
 * What makes them worth having is *when* they run. A digest committed before an argument
 * starts cannot be swapped for a more convenient one afterwards, and `beforeDispute` on every
 * record is the fact a moderator actually uses (`lib/evidence.ts`).
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict, notFound, orConflict } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { asEnum, asId } from "../lib/validate.ts";
import {
  evidenceForOrder,
  EVIDENCE_KINDS,
  MAX_EVIDENCE_PER_PARTY,
} from "../lib/evidence.ts";

interface OrderParties {
  id: string;
  status: string;
  buyer_user_id: string;
  seller_user_id: string;
}

export async function registerEvidenceRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;

  /**
   * The order, or the same answer a wrong id gets. A stranger must not be able to learn that
   * an order exists by asking about its evidence (point 70) — the rule the order status route
   * and `routes/deliveries.ts` already follow.
   */
  async function orderFor(
    id: string,
    userId: string,
    role: string,
  ): Promise<{ order: OrderParties; side: "buyer" | "seller" | "moderator" }> {
    const order = await db.get<OrderParties>(
      "SELECT id, status, buyer_user_id, seller_user_id FROM orders WHERE id = ?",
      [id],
    );
    if (!order) throw notFound("no such order");
    if (order.buyer_user_id === userId) return { order, side: "buyer" };
    if (order.seller_user_id === userId) return { order, side: "seller" };
    if (role === "moderator" || role === "admin") return { order, side: "moderator" };
    throw notFound("no such order");
  }

  /**
   * Commits a digest of bytes this party says were exchanged.
   *
   * Only a party, never a moderator: a moderator committing evidence on somebody's order
   * would be a moderator putting a fact into a case they are about to decide. And only while
   * the order is still live — after it is completed or cancelled there is nothing left to
   * argue about, and a commitment made then is a claim about a closed case.
   */
  app.post("/api/market/orders/:id/evidence", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "order_write");
    const id = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const kind = asEnum(body.kind, "kind", EVIDENCE_KINDS);
    const digest = body.digest;
    // The shape is all this server can check: 64 lower-case hex characters, which is what
    // `HMAC-SHA256` produces in the browser. Whether it is the digest of anything is between
    // the two parties, who both have the file.
    if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
      throw badRequest(
        "digest must be 64 lower-case hex characters — HMAC-SHA256 of the file, keyed with the order id",
        "invalid_digest",
      );
    }

    const { order, side } = await orderFor(id, user.id, user.role);
    if (side === "moderator") {
      throw notFound("no such order"); // not a party: the same answer as a stranger
    }
    if (order.status === "completed" || order.status === "cancelled") {
      throw conflict("this order is finished; there is nothing left to commit to", "stale_status");
    }

    const mine = await db.get<{ count: number }>(
      "SELECT COUNT(*) AS count FROM order_evidence WHERE order_id = ? AND user_id = ?",
      [id, user.id],
    );
    if (Number(mine?.count ?? 0) >= MAX_EVIDENCE_PER_PARTY) {
      throw conflict(
        `you have committed the maximum of ${MAX_EVIDENCE_PER_PARTY} digests on this order`,
        "evidence_full",
      );
    }

    // Committing the same bytes twice is one commitment: the unique key says so, and the
    // caller is told it succeeded, because it did — that digest is on the record.
    await orConflict(
      db.run(
        `INSERT INTO order_evidence (id, order_id, user_id, kind, digest, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [newId(), id, user.id, kind, digest, Date.now()],
      ),
      conflict("you have already committed this digest on this order", "already_committed"),
    );
    return { orderId: id, digest, kind, by: side };
  });

  /**
   * Every commitment on this order: both sides, oldest first, with whether each was made
   * before the dispute. Readable by the two parties and by staff — the same list for all
   * three, because a dispute where the moderator sees something different is one nobody can
   * trust.
   */
  app.get("/api/market/orders/:id/evidence", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const id = asId((request.params as { id: string }).id, "id");
    const { order } = await orderFor(id, user.id, user.role);
    return { evidence: await evidenceForOrder(db, order) };
  });
}
