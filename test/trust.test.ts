/**
 * Points 45–46: goods that are not files, and reputation that is hard to buy.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, promote, register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root");
});
afterEach(async () => {
  await server.close();
});

async function seller(name: string, kind: "service" | "digital_good" = "service") {
  const client = await register(server, name);
  await approveSeller(server, client, `${name} works`);
  const listing = await client.post<{ id: string }>("/api/market/listings", {
    title: `${name}'s offer`,
    description: "A description that is long enough to satisfy the validator on this route.",
    category: "consulting",
    kind,
    priceXmr: "0.05",
  });
  return { client, listingId: listing.body.id };
}

/** Buyer orders, seller accepts and delivers manually, buyer completes and reviews. */
async function completedOrder(buyer: TestClient, vendor: TestClient, listingId: string, rating: number) {
  const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
  await vendor.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
  await vendor.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
  await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
  const review = await buyer.post(`/api/market/orders/${order.body.id}/review`, { rating, body: "" });
  expect(review.status).toBe(200);
  return order.body.id;
}

describe("delivery is not only a file", () => {
  it("lets a seller mark a service delivered without storing anything", async () => {
    const { client: vendor, listingId } = await seller("vendor");
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string; kind: string }>("/api/market/orders", { listingId });
    await vendor.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });

    const both = await vendor.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true, ciphertext: "Zm9v" });
    expect(both.status).toBe(400);
    const neither = await vendor.post(`/api/market/orders/${order.body.id}/delivery`, {});
    expect(neither.status).toBe(400);

    const delivered = await vendor.post<{ status: string; expiresAt: number | null }>(
      `/api/market/orders/${order.body.id}/delivery`,
      { manual: true },
    );
    expect(delivered.body).toEqual({ status: "delivered", expiresAt: null });
    expect(await server.db.all("SELECT id FROM deliveries")).toEqual([]);

    const mine = await buyer.get<{ orders: Array<{ status: string; kind: string }> }>("/api/market/orders");
    expect(mine.body.orders[0]).toMatchObject({ status: "delivered", kind: "service" });
    expect((await buyer.get(`/api/market/orders/${order.body.id}/delivery`)).status).toBe(404);
    expect((await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" })).status).toBe(200);
  });
});

describe("disputes reach a moderator and are settled once", () => {
  it("files the buyer's reason where the moderation queue can see it, with the order's facts", async () => {
    const { client: vendor, listingId } = await seller("vendor");
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await vendor.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, {
      status: "disputed",
      reason: "The work delivered is not what the listing described.",
    });

    // Nobody can fabricate a dispute through the plain report route.
    const forged = await buyer.post("/api/moderation/reports", { targetType: "order", targetId: order.body.id, reason: "dispute" });
    expect(forged.status).toBe(400);

    const moderator = await register(server, "referee");
    await promote(server, "referee", "moderator");
    const queue = await moderator.get<{
      reports: Array<{ reason: string; targetId: string; details: string; order: { status: string; buyer: string; seller: string; sellerRecord: { disputedOrders: number } } | null }>;
    }>("/api/moderation/queue");
    const report = queue.body.reports.find((row) => row.targetId === order.body.id)!;
    expect(report.reason).toBe("dispute");
    expect(report.details).toContain("not what the listing described");
    expect(report.order).toMatchObject({ status: "disputed", buyer: "buyer", seller: "vendor" });
    expect(report.order!.sellerRecord.disputedOrders).toBe(1);

    const settled = await moderator.post(`/api/market/orders/${order.body.id}/status`, { status: "cancelled" });
    expect(settled.status).toBe(200);
    const after = await moderator.get<{ reports: Array<{ targetId: string }> }>("/api/moderation/queue");
    expect(after.body.reports.find((row) => row.targetId === order.body.id)).toBeUndefined();
    const audit = await moderator.get<{ entries: Array<{ action: string; subjectId: string; note: string }> }>("/api/moderation/audit");
    expect(audit.body.entries[0]).toMatchObject({ action: "order.settled", subjectId: order.body.id, note: "cancelled" });

    // Settled, but not forgotten: the dispute stays on the seller's record.
    const profile = await buyer.get<{ seller: { disputedOrders: number } }>("/api/market/sellers/vendor");
    expect(profile.body.seller.disputedOrders).toBe(1);
  });
});

describe("reputation counts buyers, not reviews", () => {
  it("weighs one account's repeated five stars as one voice", async () => {
    const { client: vendor, listingId } = await seller("vendor");
    const fan = await register(server, "fan");
    const critic = await register(server, "critic");
    for (let i = 0; i < 3; i += 1) await completedOrder(fan, vendor, listingId, 5);
    await completedOrder(critic, vendor, listingId, 1);

    const page = await critic.get<{
      seller: { reviewCount: number; distinctReviewers: number; averageRating: number; completedOrders: number };
      listings: Array<{ reviewCount: number; distinctReviewers: number; averageRating: number }>;
    }>("/api/market/sellers/vendor");
    // Four reviews, two buyers: (5 + 1) / 2, not (5 + 5 + 5 + 1) / 4.
    expect(page.body.seller).toMatchObject({ reviewCount: 4, distinctReviewers: 2, averageRating: 3, completedOrders: 4 });
    expect(page.body.listings[0]).toMatchObject({ reviewCount: 4, distinctReviewers: 2, averageRating: 3 });
  });

  it("uses a buyer's latest verdict, so a changed mind counts and a hidden review does not", async () => {
    const { client: vendor, listingId } = await seller("vendor");
    const buyer = await register(server, "buyer");
    await completedOrder(buyer, vendor, listingId, 2);
    const second = await completedOrder(buyer, vendor, listingId, 4);
    const page = () => buyer.get<{ seller: { averageRating: number } }>("/api/market/sellers/vendor");
    expect((await page()).body.seller.averageRating).toBe(4);

    const moderator = await register(server, "referee");
    await promote(server, "referee", "moderator");
    const review = await server.db.get<{ id: string }>("SELECT id FROM reviews WHERE order_id = ?", [second]);
    await moderator.post(`/api/moderation/reviews/${review!.id}/hide`, {});
    expect((await page()).body.seller.averageRating).toBe(2);
  });
});
