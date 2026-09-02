/**
 * Marketplace: seller applications, listings, orders, reviews.
 *
 * Marketplace data is public or semi-public by nature — a listing has to be readable to
 * be bought. So the privacy work here is different from messaging: keep the *record* of
 * who bought what minimal (no shipping address, no payment identity, day-granularity
 * timestamps on anything long-lived), and push the negotiation itself into the encrypted
 * channel attached to the order.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict, forbidden, notFound, orConflict } from "../lib/errors.ts";
import { newId, randomToken } from "../lib/ids.ts";
import { dayToIsoDate, today } from "../lib/time.ts";
import {
  asEnum,
  asId,
  asInteger,
  asOptionalString,
  asString,
  CURRENCIES,
  LISTING_KINDS,
} from "../lib/validate.ts";
import { recordAudit } from "../lib/audit.ts";
import { listingRating, sellerReputation } from "../lib/reputation.ts";

type OrderStatus =
  | "placed"
  | "accepted"
  | "delivered"
  | "completed"
  | "cancelled"
  | "disputed";

/** Who may move an order from where to where. Everything else is rejected. */
const ORDER_TRANSITIONS: Record<OrderStatus, Partial<Record<OrderStatus, Array<"buyer" | "seller" | "moderator">>>> = {
  placed: {
    accepted: ["seller"],
    cancelled: ["buyer", "seller", "moderator"],
  },
  accepted: {
    delivered: ["seller"], // only via POST /api/market/orders/:id/delivery
    cancelled: ["seller", "moderator"],
    disputed: ["buyer"],
  },
  delivered: {
    completed: ["buyer"],
    disputed: ["buyer"],
  },
  disputed: {
    completed: ["moderator"],
    cancelled: ["moderator"],
  },
  completed: {},
  cancelled: {},
};

export async function registerMarketRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;

  /* ----------------------------- seller applications ----------------------------- */

  app.post("/api/market/seller-applications", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "seller_application");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const displayName = asString(body.displayName, "displayName", 40, 3);
    const statement = asString(body.statement, "statement", 2000, 20);

    const alreadySeller = await db.get("SELECT user_id FROM sellers WHERE user_id = ?", [user.id]);
    if (alreadySeller) throw conflict("you are already a seller", "already_seller");
    const pending = await db.get(
      "SELECT id FROM seller_applications WHERE user_id = ? AND status = 'pending'",
      [user.id],
    );
    if (pending) throw conflict("you already have an application under review", "already_applied");
    const nameTaken = await db.get("SELECT user_id FROM sellers WHERE display_name = ?", [
      displayName,
    ]);
    if (nameTaken) throw conflict("that seller name is taken", "display_name_taken");

    const id = newId();
    // The checks above are for the error message; `seller_applications_one_pending` is
    // what actually holds when two submissions arrive together.
    await orConflict(
      db.run(
        `INSERT INTO seller_applications (id, user_id, display_name, statement, status, created_day)
         VALUES (?, ?, ?, ?, 'pending', ?)`,
        [id, user.id, displayName, statement, today()],
      ),
      conflict("you already have an application under review", "already_applied"),
    );
    return { id, status: "pending" };
  });

  app.get("/api/market/seller-applications/mine", async (request) => {
    await app.limit(request, "read");
    const user = await app.authenticate(request);
    const rows = await db.all<{
      id: string;
      display_name: string;
      status: string;
      decision_note: string | null;
      created_day: number;
      decided_day: number | null;
    }>(
      `SELECT id, display_name, status, decision_note, created_day, decided_day
         FROM seller_applications WHERE user_id = ? ORDER BY created_day DESC`,
      [user.id],
    );
    return {
      applications: rows.map((row) => ({
        id: row.id,
        displayName: row.display_name,
        status: row.status,
        decisionNote: row.decision_note,
        submittedOn: dayToIsoDate(row.created_day),
        decidedOn: row.decided_day ? dayToIsoDate(row.decided_day) : null,
      })),
    };
  });

  /* ---------------------------------- listings ---------------------------------- */

  app.post("/api/market/listings", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "listing_write");
    const seller = await requireSeller(app, user.id);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const listing = {
      id: newId(),
      title: asString(body.title, "title", 120, 3),
      description: asString(body.description, "description", 8000, 20),
      category: asString(body.category, "category", 40, 2),
      kind: asEnum(body.kind, "kind", LISTING_KINDS),
      priceMinor: asInteger(body.priceMinor, "priceMinor", 0, 10 ** 12),
      currency: asEnum(body.currency, "currency", CURRENCIES),
    };
    await db.run(
      `INSERT INTO listings (id, seller_user_id, title, description, category, kind, price_minor,
                             currency, status, created_day, updated_day)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
      [
        listing.id,
        seller.user_id,
        listing.title,
        listing.description,
        listing.category,
        listing.kind,
        listing.priceMinor,
        listing.currency,
        today(),
        today(),
      ],
    );
    return { id: listing.id, status: "active" };
  });

  app.patch("/api/market/listings/:id", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "listing_write");
    const id = asId((request.params as { id: string }).id, "id");
    const listing = await db.get<{ seller_user_id: string; status: string }>(
      "SELECT seller_user_id, status FROM listings WHERE id = ?",
      [id],
    );
    if (!listing) throw notFound("no such listing");
    if (listing.seller_user_id !== user.id) throw forbidden("this listing is not yours");
    if (listing.status === "removed") throw forbidden("this listing was removed by moderation");

    const body = (request.body ?? {}) as Record<string, unknown>;
    const updates: Array<[string, unknown]> = [];
    if (body.title !== undefined) updates.push(["title", asString(body.title, "title", 120, 3)]);
    if (body.description !== undefined) {
      updates.push(["description", asString(body.description, "description", 8000, 20)]);
    }
    if (body.category !== undefined) {
      updates.push(["category", asString(body.category, "category", 40, 2)]);
    }
    if (body.priceMinor !== undefined) {
      updates.push(["price_minor", asInteger(body.priceMinor, "priceMinor", 0, 10 ** 12)]);
    }
    if (body.status !== undefined) {
      updates.push(["status", asEnum(body.status, "status", ["active", "paused"] as const)]);
    }
    if (updates.length === 0) throw badRequest("nothing to update");
    updates.push(["updated_day", today()]);
    await db.run(
      // Column names come from the literal strings pushed above, never from the request;
      // every *value* is still a bound parameter. audit:allow
      `UPDATE listings SET ${updates.map(([column]) => `${column} = ?`).join(", ")} WHERE id = ?`,
      [...updates.map(([, value]) => value), id],
    );
    return { ok: true };
  });

  app.get("/api/market/listings", async (request) => {
    // The only query in this system that scans: `LIKE '%term%'` cannot use an index, so
    // browsing gets its own bucket rather than sharing the generous `read` one.
    await app.limit(request, "search");
    const query = request.query as Record<string, string | undefined>;
    const search = asOptionalString(query.q, "q", 80).toLowerCase();
    const category = asOptionalString(query.category, "category", 40);
    const kind = query.kind ? asEnum(query.kind, "kind", LISTING_KINDS) : null;
    const limit = query.limit ? asInteger(query.limit, "limit", 1, 100) : 50;

    const conditions = ["l.status = 'active'", "s.status = 'active'"];
    const params: unknown[] = [];
    if (search) {
      conditions.push("(LOWER(l.title) LIKE ? OR LOWER(l.description) LIKE ?)");
      params.push(`%${search}%`, `%${search}%`);
    }
    if (category) {
      conditions.push("l.category = ?");
      params.push(category);
    }
    if (kind) {
      conditions.push("l.kind = ?");
      params.push(kind);
    }
    params.push(limit);

    const rows = await db.all<ListingRow>(
      `SELECT l.id, l.title, l.description, l.category, l.kind, l.price_minor, l.currency,
              l.created_day, s.display_name, u.username
         FROM listings l
         JOIN sellers s ON s.user_id = l.seller_user_id
         JOIN users u ON u.id = l.seller_user_id
        WHERE ${conditions.join(" AND ")}
        ORDER BY l.created_day DESC, l.id
        LIMIT ?`,
      params,
    );
    return { listings: await Promise.all(rows.map((row) => presentListing(app, row))) };
  });

  app.get("/api/market/listings/:id", async (request) => {
    await app.limit(request, "read");
    const id = asId((request.params as { id: string }).id, "id");
    const row = await db.get<ListingRow & { status: string }>(
      `SELECT l.id, l.title, l.description, l.category, l.kind, l.price_minor, l.currency,
              l.created_day, l.status, s.display_name, u.username
         FROM listings l
         JOIN sellers s ON s.user_id = l.seller_user_id
         JOIN users u ON u.id = l.seller_user_id
        WHERE l.id = ?`,
      [id],
    );
    if (!row || row.status !== "active") throw notFound("no such listing");
    const reviews = await db.all<{
      rating: number;
      body: string;
      created_day: number;
      username: string;
    }>(
      `SELECT r.rating, r.body, r.created_day, u.username
         FROM reviews r JOIN users u ON u.id = r.author_user_id
        WHERE r.listing_id = ? AND r.status = 'visible'
        ORDER BY r.created_day DESC LIMIT 50`,
      [id],
    );
    return {
      listing: await presentListing(app, row),
      reviews: reviews.map((review) => ({
        rating: review.rating,
        body: review.body,
        author: review.username,
        postedOn: dayToIsoDate(review.created_day),
      })),
    };
  });

  /* ----------------------------------- orders ----------------------------------- */

  app.post("/api/market/orders", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "order_write");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const listingId = asId(body.listingId, "listingId");
    const listing = await db.get<{
      id: string;
      seller_user_id: string;
      price_minor: number;
      currency: string;
      status: string;
    }>("SELECT id, seller_user_id, price_minor, currency, status FROM listings WHERE id = ?", [
      listingId,
    ]);
    if (!listing || listing.status !== "active") throw notFound("no such listing");
    if (listing.seller_user_id === user.id) throw badRequest("you cannot order your own listing");

    const id = newId();
    const now = Date.now();
    // Opaque channel id: the encrypted order chat is linked to the order only by a value
    // both clients know. The server cannot tie it to any other conversation.
    const channel = randomToken(24);
    // One open order per buyer per listing, enforced by `orders_one_open_per_listing`: a
    // double-click, a retried request or two tabs produce one order, and the loser of the
    // race is told so rather than billed twice (point 44).
    await orConflict(
      db.transaction(async (tx) => {
        await tx.run(
          `INSERT INTO orders (id, listing_id, buyer_user_id, seller_user_id, price_minor, currency,
                               status, channel, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 'placed', ?, ?, ?)`,
          [id, listing.id, user.id, listing.seller_user_id, listing.price_minor, listing.currency, channel, now, now],
        );
        await tx.run(
          `INSERT INTO order_events (id, order_id, actor_user_id, from_status, to_status, created_at)
           VALUES (?, ?, ?, '', 'placed', ?)`,
          [newId(), id, user.id, now],
        );
      }),
      conflict("you already have an open order for this listing", "already_ordered"),
    );
    return { id, status: "placed", channel };
  });

  app.get("/api/market/orders", async (request) => {
    await app.limit(request, "read");
    const user = await app.authenticate(request);
    const role = asEnum(
      (request.query as { role?: string }).role ?? "buyer",
      "role",
      ["buyer", "seller"] as const,
    );
    const column = role === "buyer" ? "buyer_user_id" : "seller_user_id";
    const rows = await db.all<{
      id: string;
      listing_id: string;
      title: string;
      kind: string;
      status: OrderStatus;
      price_minor: number;
      currency: string;
      channel: string;
      created_at: number;
      counterparty: string;
    }>(
      `SELECT o.id, o.listing_id, l.title, l.kind, o.status, o.price_minor, o.currency, o.channel, o.created_at,
              cu.username AS counterparty
         FROM orders o
         JOIN listings l ON l.id = o.listing_id
         JOIN users cu ON cu.id = ${role === "buyer" ? "o.seller_user_id" : "o.buyer_user_id"}
        WHERE o.${column} = ?
        ORDER BY o.created_at DESC LIMIT 100`,
      [user.id],
    );
    return {
      orders: rows.map((row) => ({
        id: row.id,
        listingId: row.listing_id,
        title: row.title,
        kind: row.kind,
        status: row.status,
        priceMinor: row.price_minor,
        currency: row.currency,
        channel: row.channel,
        counterparty: row.counterparty,
        placedOn: dayToIsoDate(Math.floor(row.created_at / 86_400_000)),
      })),
    };
  });

  app.post("/api/market/orders/:id/status", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "order_write");
    const id = asId((request.params as { id: string }).id, "id");
    const next = asEnum((request.body as { status?: unknown })?.status, "status", [
      "accepted",
      // 'delivered' is deliberately absent: it is set by POST .../delivery, so the status
      // cannot claim a delivery that does not exist.
      "completed",
      "cancelled",
      "disputed",
    ] as const);

    const order = await db.get<{
      id: string;
      status: OrderStatus;
      buyer_user_id: string;
      seller_user_id: string;
    }>("SELECT id, status, buyer_user_id, seller_user_id FROM orders WHERE id = ?", [id]);
    if (!order) throw notFound("no such order");

    const actorRoles: Array<"buyer" | "seller" | "moderator"> = [];
    if (order.buyer_user_id === user.id) actorRoles.push("buyer");
    if (order.seller_user_id === user.id) actorRoles.push("seller");
    if (user.role === "moderator" || user.role === "admin") actorRoles.push("moderator");
    if (actorRoles.length === 0) throw forbidden("this order is not yours");

    const allowed = ORDER_TRANSITIONS[order.status][next] ?? [];
    if (!allowed.some((role) => actorRoles.includes(role))) {
      throw forbidden(`cannot move an order from ${order.status} to ${next} in your role`);
    }
    // A dispute needs a reason a moderator can act on. It is the one piece of order text
    // the server stores in the clear, written by the buyer *for* the moderator: it goes
    // into `reports`, where every other moderator-facing complaint already lives.
    const reason =
      next === "disputed"
        ? asString((request.body as { reason?: unknown })?.reason, "reason", 2000, 10)
        : null;
    const settling = order.status === "disputed" && actorRoles.includes("moderator");

    const now = Date.now();
    await db.transaction(async (tx) => {
      // Compare-and-swap on the status that was authorised above. Two requests racing
      // from the same state (a buyer completing and disputing at once, a seller accepting
      // an order the buyer is cancelling) both pass the role check; only the one whose
      // UPDATE finds the row still in that state wins, and the other is told the truth.
      const moved = await tx.get(
        "UPDATE orders SET status = ?, updated_at = ? WHERE id = ? AND status = ? RETURNING id",
        [next, now, id, order.status],
      );
      if (!moved) throw conflict(`this order is no longer ${order.status}`, "stale_status");
      // A finished order keeps no file: the buyer has saved it or has lost the chance to.
      if (next === "completed" || next === "cancelled") {
        await tx.run("DELETE FROM deliveries WHERE order_id = ?", [id]);
      }
      await tx.run(
        `INSERT INTO order_events (id, order_id, actor_user_id, from_status, to_status, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [newId(), id, user.id, order.status, next, now],
      );
      if (reason) {
        await tx.run(
          `INSERT INTO reports (id, target_type, target_id, reporter_user_id, reason, details, status, created_day)
           VALUES (?, 'order', ?, ?, 'dispute', ?, 'open', ?)`,
          [newId(), id, user.id, reason, today()],
        );
      }
      if (settling) {
        // The order's outcome *is* the report's resolution; leaving the report open would
        // show a moderator work that is already done.
        await tx.run(
          `UPDATE reports SET status = 'actioned', resolution_note = ?, resolved_by = ?, resolved_day = ?
            WHERE target_type = 'order' AND target_id = ? AND status = 'open'`,
          [next, user.id, today(), id],
        );
      }
    });
    if (settling) {
      await recordAudit(db, {
        actorUserId: user.id,
        action: "order.settled",
        subjectType: "order",
        subjectId: id,
        note: next,
      });
    }
    return { id, status: next };
  });

  /* ----------------------------------- reviews ---------------------------------- */

  app.post("/api/market/orders/:id/review", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "review");
    const id = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const rating = asInteger(body.rating, "rating", 1, 5);
    const text = asOptionalString(body.body, "body", 2000);

    const order = await db.get<{
      id: string;
      listing_id: string;
      buyer_user_id: string;
      seller_user_id: string;
      status: OrderStatus;
    }>(
      "SELECT id, listing_id, buyer_user_id, seller_user_id, status FROM orders WHERE id = ?",
      [id],
    );
    if (!order) throw notFound("no such order");
    if (order.buyer_user_id !== user.id) throw forbidden("only the buyer can review an order");
    // Reputation that anyone can write is not reputation: a review requires a completed order.
    if (order.status !== "completed") throw forbidden("only completed orders can be reviewed");
    const existing = await db.get("SELECT id FROM reviews WHERE order_id = ?", [id]);
    if (existing) throw conflict("this order has already been reviewed", "already_reviewed");

    await db.run(
      `INSERT INTO reviews (id, order_id, listing_id, seller_user_id, author_user_id, rating, body,
                            status, created_day)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'visible', ?)`,
      [newId(), order.id, order.listing_id, order.seller_user_id, user.id, rating, text, today()],
    );
    return { ok: true };
  });

  app.get("/api/market/sellers/:username", async (request) => {
    await app.limit(request, "read");
    const username = asString((request.params as { username: string }).username, "username", 32)
      .toLowerCase();
    const seller = await db.get<{
      user_id: string;
      display_name: string;
      bio: string;
      joined_day: number;
      status: string;
    }>(
      `SELECT s.user_id, s.display_name, s.bio, s.joined_day, s.status
         FROM sellers s JOIN users u ON u.id = s.user_id WHERE u.username = ?`,
      [username],
    );
    if (!seller || seller.status !== "active") throw notFound("no such seller");
    const reputation = await sellerReputation(app.db, seller.user_id);
    const listings = await db.all<ListingRow>(
      `SELECT l.id, l.title, l.description, l.category, l.kind, l.price_minor, l.currency,
              l.created_day, s.display_name, u.username
         FROM listings l
         JOIN sellers s ON s.user_id = l.seller_user_id
         JOIN users u ON u.id = l.seller_user_id
        WHERE l.seller_user_id = ? AND l.status = 'active'
        ORDER BY l.created_day DESC LIMIT 100`,
      [seller.user_id],
    );
    return {
      seller: {
        username,
        displayName: seller.display_name,
        bio: seller.bio,
        joinedOn: dayToIsoDate(seller.joined_day),
        ...reputation,
      },
      listings: await Promise.all(listings.map((row) => presentListing(app, row))),
    };
  });
}

interface ListingRow {
  id: string;
  title: string;
  description: string;
  category: string;
  kind: string;
  price_minor: number;
  currency: string;
  created_day: number;
  display_name: string;
  username: string;
}

async function presentListing(app: FastifyInstance, row: ListingRow) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    category: row.category,
    kind: row.kind,
    priceMinor: row.price_minor,
    currency: row.currency,
    seller: { username: row.username, displayName: row.display_name },
    listedOn: dayToIsoDate(row.created_day),
    ...(await listingRating(app.db, row.id)),
  };
}

async function requireSeller(app: FastifyInstance, userId: string): Promise<{ user_id: string }> {
  const seller = await app.db.get<{ user_id: string; status: string }>(
    "SELECT user_id, status FROM sellers WHERE user_id = ?",
    [userId],
  );
  if (!seller) throw forbidden("you need an approved seller application first");
  if (seller.status !== "active") throw forbidden("your seller account is suspended");
  return seller;
}
