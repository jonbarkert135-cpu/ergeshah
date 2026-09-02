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
import { conflict, forbidden, notFound } from "../lib/errors.ts";
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

  /** Seller uploads the ciphertext; the order moves to `delivered` in the same commit. */
  app.post("/api/market/orders/:id/delivery", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "send");
    const order = await orderFor(app, request, user.id);
    if (order.seller_user_id !== user.id) throw forbidden("only the seller can deliver an order");
    if (order.status !== "accepted") {
      throw forbidden(`an order can only be delivered from 'accepted', not '${order.status}'`);
    }
    const ciphertext = asBase64Url(
      (request.body as { ciphertext?: unknown })?.ciphertext,
      "ciphertext",
      config.maxDeliveryBytes,
    );
    const existing = await db.get("SELECT id FROM deliveries WHERE order_id = ?", [order.id]);
    if (existing) throw conflict("this order already has a delivery", "already_delivered");

    const now = Date.now();
    await db.transaction(async (tx) => {
      await tx.run(
        `INSERT INTO deliveries (id, order_id, ciphertext, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
        [newId(), order.id, ciphertext, now, now + config.deliveryTtlMs],
      );
      // Delivering *is* the status change: an order can never be "delivered" with no file,
      // or hold a file the buyer was never told about.
      await tx.run("UPDATE orders SET status = 'delivered', updated_at = ? WHERE id = ?", [
        now,
        order.id,
      ]);
      await tx.run(
        `INSERT INTO order_events (id, order_id, actor_user_id, from_status, to_status, created_at)
         VALUES (?, ?, ?, ?, 'delivered', ?)`,
        [newId(), order.id, user.id, order.status, now],
      );
    });
    return { status: "delivered", expiresAt: now + config.deliveryTtlMs };
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
