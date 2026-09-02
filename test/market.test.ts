import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, promote, register, startTestServer, type TestServer } from "./helpers.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  // The first account on a fresh instance bootstraps as admin; take that role out of the
  // way so the rest of the tests exercise ordinary, unprivileged users.
  await register(server, "root");
});
afterEach(async () => {
  await server.close();
});

async function sellerWithListing() {
  const seller = await register(server, "seller");
  await approveSeller(server, seller, "Quiet Works");
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: "Static site audit",
    description: "A careful review of your site for privacy leaks and performance issues.",
    category: "consulting",
    kind: "service",
    priceMinor: 15_000,
    currency: "EUR",
  });
  return { seller, listingId: listing.body.id };
}

describe("becoming a seller", () => {
  it("requires an approved application before listing anything", async () => {
    const user = await register(server, "hopeful");
    const denied = await user.post("/api/market/listings", {
      title: "Something",
      description: "A description that is definitely long enough to pass validation.",
      category: "misc",
      kind: "service",
      priceMinor: 100,
      currency: "USD",
    });
    expect(denied.status).toBe(403);

    await approveSeller(server, user, "Hopeful Studio");
    const allowed = await user.post("/api/market/listings", {
      title: "Something",
      description: "A description that is definitely long enough to pass validation.",
      category: "misc",
      kind: "service",
      priceMinor: 100,
      currency: "USD",
    });
    expect(allowed.status).toBe(200);
  });

  it("does not let two sellers share a display name", async () => {
    const first = await register(server, "one");
    await approveSeller(server, first, "Same Name");
    const second = await register(server, "two");
    const clash = await second.post("/api/market/seller-applications", {
      displayName: "Same Name",
      statement: "I would like to use a name that is already taken by someone else.",
    });
    expect(clash.status).toBe(409);
  });
});

describe("listings", () => {
  it("publishes, searches and shows a listing", async () => {
    const { listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    const search = await buyer.get<{ listings: Array<{ id: string; seller: { username: string } }> }>(
      "/api/market/listings?q=audit",
    );
    expect(search.body.listings.map((listing) => listing.id)).toContain(listingId);
    expect(search.body.listings[0]!.seller.username).toBe("seller");

    const detail = await buyer.get<{ listing: { title: string }; reviews: unknown[] }>(
      `/api/market/listings/${listingId}`,
    );
    expect(detail.body.listing.title).toBe("Static site audit");
    expect(detail.body.reviews).toEqual([]);
  });

  it("refuses to let one seller edit another seller's listing", async () => {
    const { listingId } = await sellerWithListing();
    const other = await register(server, "rival");
    await approveSeller(server, other, "Rival Works");
    const attempt = await other.patch(`/api/market/listings/${listingId}`, { priceMinor: 1 });
    expect(attempt.status).toBe(403);
  });
});

describe("orders and reviews", () => {
  it("walks the full order lifecycle and records a review", async () => {
    const { seller, listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");

    const order = await buyer.post<{ id: string; status: string; channel: string }>(
      "/api/market/orders",
      { listingId },
    );
    expect(order.body.status).toBe("placed");
    expect(order.body.channel).toHaveLength(32);

    // The buyer cannot skip the seller's steps.
    expect((await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "delivered" })).status).toBe(403);
    expect((await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" })).status).toBe(200);
    expect((await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "delivered" })).status).toBe(200);
    // Only the buyer can confirm completion.
    expect((await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" })).status).toBe(403);
    expect((await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" })).status).toBe(200);

    const review = await buyer.post(`/api/market/orders/${order.body.id}/review`, {
      rating: 5,
      body: "Thorough and quick.",
    });
    expect(review.status).toBe(200);
    const duplicate = await buyer.post(`/api/market/orders/${order.body.id}/review`, { rating: 1 });
    expect(duplicate.status).toBe(409);

    const detail = await buyer.get<{ listing: { averageRating: number }; reviews: unknown[] }>(
      `/api/market/listings/${listingId}`,
    );
    expect(detail.body.listing.averageRating).toBe(5);
    expect(detail.body.reviews).toHaveLength(1);
  });

  it("does not accept a review without a completed order", async () => {
    const { listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    const early = await buyer.post(`/api/market/orders/${order.body.id}/review`, { rating: 5 });
    expect(early.status).toBe(403);
  });

  it("keeps orders invisible to everyone but the two parties and moderation", async () => {
    const { listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    const stranger = await register(server, "stranger");

    const list = await stranger.get<{ orders: unknown[] }>("/api/market/orders?role=buyer");
    expect(list.body.orders).toEqual([]);
    const meddling = await stranger.post(`/api/market/orders/${order.body.id}/status`, {
      status: "cancelled",
    });
    expect(meddling.status).toBe(403);
  });

  it("lets a moderator settle a dispute, and nobody else", async () => {
    const { seller, listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "disputed" });

    expect((await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" })).status).toBe(403);
    const moderator = await register(server, "referee");
    await promote(server, "referee", "moderator");
    const settled = await moderator.post(`/api/market/orders/${order.body.id}/status`, {
      status: "cancelled",
    });
    expect(settled.status).toBe(200);
  });

  it("does not let a seller order from themselves to inflate reputation", async () => {
    const { seller, listingId } = await sellerWithListing();
    const attempt = await seller.post("/api/market/orders", { listingId });
    expect(attempt.status).toBe(400);
  });
});
