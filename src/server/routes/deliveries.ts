/**
 * Blind storage: bytes the server holds and cannot open.
 *
 * Two customers, one idea. A **delivery** is one file per order: the seller encrypts it in
 * the browser with a one-time key, uploads the ciphertext, and sends the key to the buyer
 * through the order's encrypted channel. An **attachment** is the same thing for a
 * conversation (point 78) — a picture, a recording, a document — except that it is not
 * addressed to anything at all: its unguessable id *is* the capability, and that id travels
 * to the recipient inside the ciphertext of an ordinary message.
 *
 * The server therefore learns that a blob exists and roughly how large it is (the padding
 * bucket), which is stated in `docs/THREAT_MODEL.md`, and nothing else — no type, no name,
 * no sender, and for an attachment no recipient either.
 *
 * Retention is the other half of the design: a delivery is deleted when the buyer
 * acknowledges it, when the order reaches a terminal status, or when it expires; an
 * attachment is deleted when someone who holds its id says so, or when it expires.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict, forbidden, notFound, orConflict } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { asBase64Url, asId, onlyKeys } from "../lib/validate.ts";
import { pruneBlobs, requireBlobHeadroom, requireSpaceFor } from "../lib/storage.ts";
import { dirname } from "node:path";

interface OrderParties {
  id: string;
  status: string;
  buyer_user_id: string;
  seller_user_id: string;
}

export async function registerDeliveryRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;
  /** Where the bytes land: the SQLite file's directory, or the working directory for Postgres. */
  const dataPath = config.dialect === "sqlite" ? dirname(config.sqlitePath) : process.cwd();

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
    // Every upload is hostile, and the first hostile thing about one is its metadata. This
    // endpoint accepts two fields; a body that also carries `filename`, `mimeType` or a
    // `path` is refused rather than quietly ignored (point 49, ADR-0033).
    onlyKeys(body, ["ciphertext", "manual"]);
    const manual = body.manual === true;
    if (manual === (body.ciphertext !== undefined)) {
      throw badRequest("send either ciphertext or manual: true");
    }
    const ciphertext = manual
      ? null
      : asBase64Url(body.ciphertext, "ciphertext", config.maxDeliveryBytes);
    if (ciphertext) {
      await requireSpaceFor(dataPath, ciphertext.length, config.storageFloorBytes);
      await requireBlobHeadroom(db, config.maxBlobRows);
    }

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

  /* --------------------------- attachments (point 78) --------------------------- */

  /**
   * Upload one encrypted attachment and get its id back.
   *
   * HTTPS is not a substitute for end-to-end encryption, so this route refuses to be one:
   * it accepts an id and a base64url blob, and nothing that would describe either. There is
   * no `filename`, no `mimeType`, no `to` and no `channel` — the name and the kind are part
   * of the message the recipient decrypts, and the recipient is not the server's business.
   *
   * The **client** chooses the id, from 192 bits of its own randomness, because the id is
   * both the capability and the value the ciphertext is authenticated against: the browser
   * has to know it before it encrypts. A client that picks a colliding id is refused by the
   * primary key rather than overwriting anything, and a client that picks a guessable one
   * has only exposed its own blob.
   */
  app.post("/api/attachments", async (request) => {
    await app.authenticate(request);
    await app.limit(request, "attachment");
    const body = (request.body ?? {}) as { id?: unknown; ciphertext?: unknown };
    onlyKeys(body, ["id", "ciphertext"]);
    const id = asId(body.id, "id");
    const ciphertext = asBase64Url(body.ciphertext, "ciphertext", config.maxDeliveryBytes);
    // Uploads are the only requests that turn somebody else's bytes into disk, and the
    // rate limiter cannot see disk (docs/SELF_CRITIQUE.md, finding 1). Bytes first, then the
    // object count: a million small blobs cost little disk and plenty of everything else.
    await requireSpaceFor(dataPath, ciphertext.length, config.storageFloorBytes);
    await requireBlobHeadroom(db, config.maxBlobRows);
    const now = Date.now();
    await orConflict(
      db.run("INSERT INTO attachments (id, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?)", [
        id,
        ciphertext,
        now,
        now + config.deliveryTtlMs,
      ]),
      conflict("that attachment id is already taken", "id_taken"),
    );
    return { id, expiresAt: now + config.deliveryTtlMs };
  });

  /**
   * Fetch one, by an id only the conversation knows. Authenticated so that the store is not
   * open to the internet, but deliberately *not* scoped to a party: scoping it would mean
   * storing who may read it, which is the recipient column this table exists without.
   */
  app.get("/api/attachments/:id", async (request) => {
    await app.authenticate(request);
    await app.limit(request, "read");
    await sweep(app);
    const id = asId((request.params as { id: string }).id, "id");
    const row = await db.get<{ ciphertext: string; expires_at: number }>(
      "SELECT ciphertext, expires_at FROM attachments WHERE id = ?",
      [id],
    );
    if (!row) throw notFound("no such attachment");
    return { ciphertext: row.ciphertext, expiresAt: row.expires_at };
  });

  /**
   * Delete one early. The id is the only credential there is, so whoever holds it can
   * delete — which is the sender and the people they sent it to. That is a smaller risk
   * than the alternative (an owner column): the worst a recipient can do is remove bytes
   * they already have, and the sender is the one who wanted them gone anyway.
   */
  app.delete("/api/attachments/:id", async (request) => {
    await app.authenticate(request);
    await app.limit(request, "write");
    const id = asId((request.params as { id: string }).id, "id");
    const gone = await db.all<{ id: string }>(
      "DELETE FROM attachments WHERE id = ? RETURNING id",
      [id],
    );
    return { deleted: gone.length };
  });
}

/**
 * Expired blobs are removed on the way past, so a fetch can never serve one that should have
 * gone. Housekeeping runs the same function hourly (`lib/storage.ts`), because an instance
 * nobody uploads to still has a retention promise to keep.
 */
export async function sweep(app: FastifyInstance): Promise<void> {
  await pruneBlobs(app.db);
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
