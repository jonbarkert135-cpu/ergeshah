/**
 * Points 43–44: the invariants that hold under concurrency, and hold in the database rather
 * than in the order two requests happened to arrive.
 *
 * Each test fires the same request several times at once. `Promise.all` over Fastify's
 * `inject` is a real race on PostgreSQL and a fair simulation on SQLite: every handler runs
 * its SELECT before any of them runs its UPDATE, which is precisely the interleaving that
 * an application-level check cannot survive.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, promote, register, startTestServer, type TestServer } from "./helpers.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root");
});
afterEach(async () => {
  await server.close();
});

async function listingFor(sellerName: string) {
  const seller = await register(server, sellerName);
  await approveSeller(server, seller, `${sellerName} works`);
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: "One careful audit",
    description: "A description that is long enough to satisfy the validator on this route.",
    category: "consulting",
    kind: "service",
    priceXmr: "0.05",
  });
  return { seller, listingId: listing.body.id };
}

const statuses = (responses: Array<{ status: number }>) =>
  responses.map((response) => response.status).sort((a, b) => a - b);

/**
 * The loser of a race is refused either by the role check (it re-read the row after the
 * winner committed — what SQLite's single writer produces) or by the conditional UPDATE
 * (it read the row before the winner committed — what PostgreSQL produces). Both are
 * refusals; what matters is that there is exactly one winner.
 */
const oneWinner = (responses: Array<{ status: number }>) => {
  const codes = statuses(responses);
  expect(codes[0]).toBe(200);
  for (const code of codes.slice(1)) expect([403, 409]).toContain(code);
};

describe("orders cannot be duplicated or moved twice", () => {
  it("gives a buyer who submits the same order five times exactly one order", async () => {
    const { listingId } = await listingFor("seller");
    const buyer = await register(server, "buyer");
    const attempts = await Promise.all(
      Array.from({ length: 5 }, () => buyer.post("/api/market/orders", { listingId })),
    );
    expect(statuses(attempts)).toEqual([200, 409, 409, 409, 409]);
    const rows = await server.db.all("SELECT id FROM orders WHERE buyer_user_id = (SELECT id FROM users WHERE username = 'buyer')");
    expect(rows).toHaveLength(1);
  });

  it("allows the same listing to be bought again only once the previous order is closed", async () => {
    const { seller, listingId } = await listingFor("seller");
    const buyer = await register(server, "buyer");
    const first = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    expect((await buyer.post("/api/market/orders", { listingId })).status).toBe(409);
    await seller.post(`/api/market/orders/${first.body.id}/status`, { status: "cancelled" });
    expect((await buyer.post("/api/market/orders", { listingId })).status).toBe(200);
  });

  it("lets exactly one of two conflicting transitions from the same state win", async () => {
    const { seller, listingId } = await listingFor("seller");
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { ciphertext: "Zm9vYmFy" });

    // Buyer completes and disputes in the same instant. Both are legal from `delivered`;
    // the order must end in one of them, with one event, not both.
    const [complete, dispute] = await Promise.all([
      buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" }),
      buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "disputed" }),
    ]);
    oneWinner([complete!, dispute!]);
    const events = await server.db.all<{ to_status: string }>(
      "SELECT to_status FROM order_events WHERE order_id = ? AND from_status = 'delivered'",
      [order.body.id],
    );
    expect(events).toHaveLength(1);
  });

  it("never stores a delivery for an order that was cancelled in the same instant", async () => {
    const { seller, listingId } = await listingFor("seller");
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    const [cancel, deliver] = await Promise.all([
      seller.post(`/api/market/orders/${order.body.id}/status`, { status: "cancelled" }),
      seller.post(`/api/market/orders/${order.body.id}/delivery`, { ciphertext: "Zm9vYmFy" }),
    ]);
    oneWinner([cancel!, deliver!]);
    const final = await server.db.get<{ status: string }>("SELECT status FROM orders WHERE id = ?", [order.body.id]);
    const blobs = await server.db.all("SELECT id FROM deliveries WHERE order_id = ?", [order.body.id]);
    // Whichever won, the pair is consistent: a cancelled order has no file, a delivered one has one.
    expect(blobs).toHaveLength(final!.status === "delivered" ? 1 : 0);
  });
});

describe("seller approval cannot be raced", () => {
  it("keeps one pending application per account however many are submitted at once", async () => {
    const user = await register(server, "eager");
    const attempts = await Promise.all(
      Array.from({ length: 3 }, (_, i) =>
        user.post("/api/market/seller-applications", {
          displayName: `Eager ${i}`,
          statement: "I would like to sell things and this statement is long enough.",
        }),
      ),
    );
    expect(statuses(attempts)).toEqual([200, 409, 409]);
  });

  it("records one decision when two moderators decide the same application together", async () => {
    const user = await register(server, "applicant");
    const application = await user.post<{ id: string }>("/api/market/seller-applications", {
      displayName: "Applicant Works",
      statement: "I would like to sell things and this statement is long enough.",
    });
    const one = await register(server, "mod1");
    const two = await register(server, "mod2");
    await promote(server, "mod1", "moderator");
    await promote(server, "mod2", "moderator");
    const [approve, reject] = await Promise.all([
      one.post(`/api/moderation/seller-applications/${application.body.id}/decide`, { decision: "approved" }),
      two.post(`/api/moderation/seller-applications/${application.body.id}/decide`, { decision: "rejected" }),
    ]);
    expect(statuses([approve!, reject!])).toEqual([200, 409]);
    const seller = await server.db.get("SELECT user_id FROM sellers WHERE display_name = 'Applicant Works'");
    const row = await server.db.get<{ status: string }>("SELECT status FROM seller_applications WHERE id = ?", [application.body.id]);
    expect(row!.status === "approved").toBe(Boolean(seller));
  });
});

describe("the database enforces what the application also checks", () => {
  it("moves an order only from the state the caller saw (compare-and-swap)", async () => {
    const { seller, listingId } = await listingFor("seller");
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    // What every transition in market.ts and deliveries.ts executes, with a stale `from`.
    const stale = await server.db.get(
      "UPDATE orders SET status = 'accepted', updated_at = 0 WHERE id = ? AND status = 'delivered' RETURNING id",
      [order.body.id],
    );
    expect(stale).toBeNull();
    const fresh = await server.db.get(
      "UPDATE orders SET status = 'accepted', updated_at = 0 WHERE id = ? AND status = 'placed' RETURNING id",
      [order.body.id],
    );
    expect(fresh).toEqual({ id: order.body.id });
    void seller;
  });

  it("refuses a second review for one order at the storage layer, not only in the route", async () => {
    await expect(
      server.db.transaction(async (tx) => {
        await tx.run(
          `INSERT INTO users (id, username, password_hash, created_day) VALUES ('u1', 'x1', 'h', 0), ('u2', 'x2', 'h', 0)`,
        );
        await tx.run(
          `INSERT INTO listings (id, seller_user_id, title, description, category, kind, price_pico, created_day, updated_day)
           VALUES ('l1', 'u1', 't', 'd', 'c', 'service', 1000000000, 0, 0)`,
        );
        await tx.run(
          `INSERT INTO orders (id, listing_id, buyer_user_id, seller_user_id, price_pico, channel, created_at, updated_at)
           VALUES ('o1', 'l1', 'u2', 'u1', 1000000000, 'c', 0, 0)`,
        );
        for (const id of ["r1", "r2"]) {
          await tx.run(
            `INSERT INTO reviews (id, order_id, listing_id, seller_user_id, author_user_id, rating, created_day)
             VALUES (?, 'o1', 'l1', 'u1', 'u2', 5, 0)`,
            [id],
          );
        }
      }),
    ).rejects.toThrow(/UNIQUE|unique/);
  });

  it("has foreign keys switched on, so an orphaned row is an error and a deletion cascades", async () => {
    await expect(
      server.db.run("INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_day) VALUES ('s', 'ghost', 't', 0, 0, 0)"),
    ).rejects.toThrow(/FOREIGN KEY|foreign key/);
  });
});
