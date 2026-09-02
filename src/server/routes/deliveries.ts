/**
 * Digital delivery: blind storage for one file per order.
 *
 * The seller encrypts the file in the browser with a one-time key, uploads the
 * ciphertext, and sends the key to the buyer through the order's encrypted channel. The
 * server therefore stores a blob it cannot open, addressed to an order it already knows
 * about — it learns that a delivery happened and roughly how large it is (the padding
 * bucket), which is stated in `docs/THREAT_MODEL.md`, and nothing else.
 *
 * Retention is the other half of the design: the blob is deleted when the buyer
 * acknowledges it, when the order reaches a terminal status, or when it expires.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict, forbidden, notFound } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { asBase64Url, asId } from "../lib/validate.ts";

interface OrderParties {
  id: string;
  status: string;
  buyer_user_id: string;
  seller_user_id: string;
}

export async function registerDeliveryRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  /**
   * Seller delivers; the order moves to `delivered` in the same commit.
   *
   * Two shapes, because goods are not all files (point 45). `{ ciphertext }` is a blob the
   * seller encrypted in the browser — a file, a licence key, credentials, a link, any
   * bytes; the server never learns which, and the kind travels with the key in the
   * encrypted channel. `{ manual: true }` is a delivery that happened outside the
   * platform — a service rendered, a parcel posted, a key typed into the chat — and
   * stores nothing but the status change. The buyer confirms or disputes either way.
   */
  app.post("/api/market/orders/:id/delivery", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "message_send");
    const order = await orderFor(app, request, user.id);
    if (order.seller_user_id !== user.id) throw forbidden("only the seller can deliver an order");
    if (order.status !== "accepted") {
      throw forbidden(`an order can only be delivered from 'accepted', not '${order.status}'`);
    }
    const body = (request.body ?? {}) as { ciphertext?: unknown; manual?: unknown };
    const manual = body.manual === true;
    if (manual === (body.ciphertext !== undefined)) {
      throw badRequest("send either ciphertext or manual: true");
    }
    const ciphertext = manual
      ? null
      : asBase64Url(body.ciphertext, "ciphertext", config.maxDeliveryBytes);

    const now = Date.now();
    await db.transaction(async (tx) => {
      if (ciphertext) {
        // `deliveries.order_id` is UNIQUE: a second blob for one order is refused by the
        // schema, and surfaces as 409 through the constraint handler.
        await tx.run(
          `INSERT INTO deliveries (id, order_id, ciphertext, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?)`,
          [newId(), order.id, ciphertext, now, now + config.deliveryTtlMs],
        );
      }
      // Delivering *is* the status change: an order can never be "delivered" with no file,
      // or hold a file the buyer was never told about. The UPDATE is conditional on the
      // status checked above, so a cancellation that lands in between wins and the file
      // is never stored (point 44).
      const moved = await tx.get(
        "UPDATE orders SET status = 'delivered', updated_at = ? WHERE id = ? AND status = 'accepted' RETURNING id",
        [now, order.id],
      );
      if (!moved) throw conflict("this order is no longer accepted", "stale_status");
      await tx.run(
        `INSERT INTO order_events (id, order_id, actor_user_id, from_status, to_status, created_at)
         VALUES (?, ?, ?, ?, 'delivered', ?)`,
        [newId(), order.id, user.id, order.status, now],
      );
    });
    return { status: "delivered", expiresAt: ciphertext ? now + config.deliveryTtlMs : null };
  });

  /** Buyer downloads the ciphertext. The seller has the file already and is not served it. */
  app.get("/api/market/orders/:id/delivery", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const order = await orderFor(app, request, user.id);
    if (order.buyer_user_id !== user.id) throw forbidden("only the buyer can fetch a delivery");
    await sweep(app);
    const delivery = await db.get<{ ciphertext: string; created_at: number; expires_at: number }>(
      "SELECT ciphertext, created_at, expires_at FROM deliveries WHERE order_id = ?",
      [order.id],
    );
    if (!delivery) throw notFound("this order has no delivery waiting");
    return {
      ciphertext: delivery.ciphertext,
      createdAt: delivery.created_at,
      expiresAt: delivery.expires_at,
    };
  });

  /**
   * Buyer acknowledges a saved file and the server forgets it — the same "delete on
   * delivery" rule the message store follows. Deletion is not required: an untouched
   * blob expires on its own, and completing the order removes it too.
   */
  app.delete("/api/market/orders/:id/delivery", async (request) => {
    const user = await app.authenticate(request);
    const order = await orderFor(app, request, user.id);
    if (order.buyer_user_id !== user.id) throw forbidden("only the buyer can erase a delivery");
    await db.run("DELETE FROM deliveries WHERE order_id = ?", [order.id]);
    return { deleted: true };
  });
}

/** Expired blobs are removed opportunistically; there is no scheduler to compromise. */
export async function sweep(app: FastifyInstance): Promise<void> {
  await app.db.run("DELETE FROM deliveries WHERE expires_at < ?", [Date.now()]);
}

async function orderFor(
  app: FastifyInstance,
  request: { params: unknown },
  userId: string,
): Promise<OrderParties> {
  const id = asId((request.params as { id: string }).id, "id");
  const order = await app.db.get<OrderParties>(
    "SELECT id, status, buyer_user_id, seller_user_id FROM orders WHERE id = ?",
    [id],
  );
  // A stranger gets the same answer as a wrong id: order ids are not an oracle.
  if (!order || (order.buyer_user_id !== userId && order.seller_user_id !== userId)) {
    throw notFound("no such order");
  }
  return order;
}
