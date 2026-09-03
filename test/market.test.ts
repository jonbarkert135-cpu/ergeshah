import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { approveSeller, promote, fund, register, startTestServer, type TestServer } from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";

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
    priceXmr: "0.15",
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
      priceXmr: "0.001",
    });
    expect(denied.status).toBe(403);

    await approveSeller(server, user, "Hopeful Studio");
    const allowed = await user.post("/api/market/listings", {
      title: "Something",
      description: "A description that is definitely long enough to pass validation.",
      category: "misc",
      kind: "service",
      priceXmr: "0.001",
    });
    expect(allowed.status).toBe(200);
  });

  it("does not let two sellers share a display name", async () => {
    const first = await register(server, "one");
    await fund(server, first, "5");
    await approveSeller(server, first, "Same Name");
    const second = await register(server, "two");
    await fund(server, second, "5");
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
    await fund(server, buyer, "5");
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
    const attempt = await other.patch(`/api/market/listings/${listingId}`, { priceXmr: "0.002" });
    expect(attempt.status).toBe(403);
  });
});

describe("orders and reviews", () => {
  it("walks the full order lifecycle and records a review", async () => {
    const { seller, listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    await fund(server, buyer, "5");

    const order = await buyer.post<{ id: string; status: string; channel: string }>(
      "/api/market/orders",
      { listingId },
    );
    expect(order.body.status).toBe("placed");
    expect(order.body.channel).toHaveLength(32);

    // The buyer cannot skip the seller's steps, and nobody can *declare* a delivery:
    // "delivered" is reached by uploading one (see delivery.test.ts).
    expect((await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "delivered" })).status).toBe(400);
    expect((await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" })).status).toBe(200);
    expect(
      (await seller.post(`/api/market/orders/${order.body.id}/delivery`, { ciphertext: "Zm9vYmFy" }))
        .status,
    ).toBe(200);
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
    await fund(server, buyer, "5");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    const early = await buyer.post(`/api/market/orders/${order.body.id}/review`, { rating: 5 });
    expect(early.status).toBe(403);
  });

  it("keeps orders invisible to everyone but the two parties and moderation", async () => {
    const { listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    await fund(server, buyer, "5");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    const stranger = await register(server, "stranger");

    const list = await stranger.get<{ orders: unknown[] }>("/api/market/orders?role=buyer");
    expect(list.body.orders).toEqual([]);
    // 404, not 403: a stranger must not be able to tell a real order id from an invented
    // one, so the answer for both has to be the same one (point 70).
    const meddling = await stranger.post(`/api/market/orders/${order.body.id}/status`, {
      status: "cancelled",
    });
    const invented = await stranger.post(`/api/market/orders/${randomUUID()}/status`, {
      status: "cancelled",
    });
    expect(meddling.status).toBe(404);
    expect(meddling.body).toEqual(invented.body);
  });

  it("lets a moderator settle a dispute, and nobody else", async () => {
    const { seller, listingId } = await sellerWithListing();
    const buyer = await register(server, "buyer");
    await fund(server, buyer, "5");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    // A dispute without a reason is not a dispute a moderator can act on.
    expect((await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "disputed" })).status).toBe(400);
    const disputed = await buyer.post(`/api/market/orders/${order.body.id}/status`, {
      status: "disputed",
      reason: "Nothing was delivered after two weeks of waiting.",
    });
    expect(disputed.status).toBe(200);

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

/**
 * The guarantee is escrow, and escrow only exists for an order placed here (ADR-0068,
 * ADR-0069). Nothing can read the chat, so the enforcement lives in the two places that are
 * public: what a listing may say, and what a seller's standing is worth in the catalogue.
 */
describe("staying on the platform is the only thing that pays", () => {
  // These scenarios need several accounts (two sellers, a buyer, and the moderator each
  // approval creates), which is more registrations than the shipped limit allows in one
  // window. The limit itself is tested in `limits.test.ts`.
  beforeEach(async () => {
    await server.close();
    server = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, register: { burst: 50, perMinute: 50 } },
    });
    await register(server, "root");
  });

  async function seller(name: string, displayName: string) {
    const client = await register(server, name);
    await approveSeller(server, client, displayName);
    return client;
  }

  const listing = (title: string, description: string, priceXmr = "0.5") => ({
    title,
    description,
    category: "software",
    kind: "digital_good" as const,
    priceXmr,
  });

  it("refuses a listing that carries a wallet address or an off-platform contact", async () => {
    const shop = await seller("evader", "Evader Ltd");
    const refusals = [
      listing(
        "Fast delivery",
        `Send payment straight to 8${"A".repeat(94)} and I will deliver within the hour.`,
      ),
      listing("Fast delivery", "Write to me on Telegram before ordering, it is much quicker."),
      listing("Fast delivery", "Pay directly and skip the fee, message me for the details here."),
      listing("Fast delivery", "Пиши напрямую, оплата мимо площадки — так дешевле для нас обоих."),
      listing("Fast delivery", "Reach me at seller@example.com for anything you need quickly."),
    ];
    for (const body of refusals) {
      const refused = await shop.post("/api/market/listings", body);
      expect(refused.status).toBe(400);
      expect((refused.body as { error?: string }).error).toBe("off_platform_offer");
    }
    // The rule is narrow on purpose: an honest listing still publishes.
    const allowed = await shop.post("/api/market/listings", listing(
      "Fast delivery",
      "Delivered through this platform within the hour, with the price held in escrow until you confirm.",
    ));
    expect(allowed.status).toBe(200);

    // And it applies to an edit, not only to the first version.
    const edited = await shop.patch(`/api/market/listings/${(allowed.body as { id: string }).id}`, {
      description: "Actually, write to me on Telegram and we will settle it there, much faster.",
    });
    expect(edited.status).toBe(400);
  });

  it("raises a seller's level, and their place in the catalogue, only on settled orders", async () => {
    const veteran = await seller("veteran", "Veteran Works");
    const newcomer = await seller("newcomer", "Newcomer Works");
    const first = await veteran.post<{ id: string }>(
      "/api/market/listings",
      listing("Veteran service", "Work delivered through this platform, honestly described.", "0.2"),
    );

    const buyer = await register(server, "levelbuyer");
    await fund(server, buyer, "3");
    // Three completed orders and half an XMR of earnings is level 1 (lib/reputation.ts).
    for (let index = 0; index < 3; index += 1) {
      const extra = await veteran.post<{ id: string }>(
        "/api/market/listings",
        listing(`Veteran service ${index}`, "Work delivered through this platform, described.", "0.2"),
      );
      const order = await buyer.post<{ id: string }>("/api/market/orders", {
        listingId: extra.body.id,
      });
      await veteran.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
      await veteran.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
      const done = await buyer.post(`/api/market/orders/${order.body.id}/status`, {
        status: "completed",
      });
      expect(done.status).toBe(200);
    }

    // The newcomer's listing is the newest, and would be first under a purely chronological
    // catalogue. It is not, because the veteran earned their place with on-platform trade.
    const newest = await newcomer.post<{ id: string }>(
      "/api/market/listings",
      listing("Newcomer service", "Also work delivered through this platform, honestly described."),
    );
    expect(newest.status).toBe(200);
    const page = await buyer.get<{ listings: Array<{ id: string; seller: { level: number } }> }>(
      "/api/market/listings?limit=10",
    );
    const listings = page.body.listings;
    expect(listings[0]?.seller.level).toBe(1);
    expect(listings.at(-1)?.id).toBe(newest.body.id);
    // The seller's own page publishes the level and never the volume behind it.
    const profile = await buyer.get<{ seller: { level: number } }>("/api/market/sellers/veteran");
    expect(profile.body.seller.level).toBe(1);
    expect(JSON.stringify(profile.body)).not.toContain("settled");
    // The first listing, published before the promotion, was re-keyed with the rest.
    const ranked = await server.db.get<{ rank_key: number }>(
      "SELECT rank_key FROM listings WHERE id = ?",
      [first.body.id],
    );
    expect(ranked!.rank_key).toBeGreaterThan(100_000);
  });
});
