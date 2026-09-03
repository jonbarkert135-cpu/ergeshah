/**
 * Categories: folded on the way in, discoverable on the way out (MKT-3, ADR-0082).
 *
 * A category here is the seller's own word, not an entry in an enum this project would have
 * to defend. The price of that is spelling: "Consulting", "consulting " and "CONSULTING" were
 * three categories, each with a partial page of results, and a buyer had no way to learn that
 * any of them existed. These tests are about both halves — the folding, and the list.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, register, startTestServer, type TestServer } from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";

let server: TestServer;

beforeEach(async () => {
  // Several sellers per scenario, which is more registrations than the default bucket allows.
  server = await startTestServer({
    rateLimits: { ...DEFAULT_LIMITS, register: { burst: 50, perMinute: 50 } },
  });
  await register(server, "root");
});
afterEach(async () => {
  await server.close();
});

describe("categories, folded and discoverable (MKT-3, ADR-0082)", () => {
  it("folds three spellings into one category and publishes it with a count", async () => {
    const seller = await sellerWith([
      ["Brand identity work", "Consulting"],
      ["Logo and type", " consulting "],
      ["Pitch deck review", "CONSULTING"],
      ["A small utility", "Software Tools"],
    ]);
    expect(seller).toBeTruthy();

    const stored = await server.db.all<{ category: string }>(
      "SELECT DISTINCT category FROM listings ORDER BY category",
    );
    // One category, not three, and lowercase because that is what was stored.
    expect(stored.map((row) => row.category)).toEqual(["consulting", "software tools"]);

    const browse = await server.app.inject({ method: "GET", url: "/api/market/categories" });
    expect(browse.statusCode).toBe(200);
    expect(browse.json()).toEqual({
      categories: [
        { category: "consulting", listings: 3 },
        { category: "software tools", listings: 1 },
      ],
    });
  });

  it("filters on the folded name, however the link was capitalised", async () => {
    await sellerWith([
      ["Brand identity work", "Consulting"],
      ["A small utility", "software"],
    ]);
    for (const asked of ["consulting", "Consulting", "  CONSULTING  "]) {
      const page = await server.app.inject({
        method: "GET",
        url: `/api/market/listings?category=${encodeURIComponent(asked)}`,
      });
      expect(page.statusCode, asked).toBe(200);
      expect((page.json() as { listings: unknown[] }).listings, asked).toHaveLength(1);
    }
  });

  it("counts only what a stranger can see", async () => {
    const seller = await sellerWith([["Brand identity work", "consulting"]]);
    // A removed listing and a suspended seller both leave the count, because both leave the
    // catalogue: a category page that promises three listings and shows one is worse than
    // no category page.
    await server.db.run("UPDATE listings SET status = 'removed'");
    expect((await categoryNames()).length).toBe(0);
    await server.db.run("UPDATE listings SET status = 'active'");
    expect(await categoryNames()).toEqual(["consulting"]);
    await server.db.run("UPDATE sellers SET status = 'suspended' WHERE user_id = ?", [seller]);
    expect((await categoryNames()).length).toBe(0);
  });

  it("refuses a category that folds away to nothing", async () => {
    const seller = await register(server, "punctuationseller");
    await approveSeller(server, seller, "Punctuation Works");
    const refused = await seller.post<{ error: string }>("/api/market/listings", {
      title: "A listing with a nonsense category",
      description: "A description long enough to satisfy the validator on this route, honestly.",
      category: "!!! ??",
      kind: "service",
      priceXmr: "0.1",
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("bad_category");
  });
});

async function categoryNames(): Promise<string[]> {
  const response = await server.app.inject({ method: "GET", url: "/api/market/categories" });
  return (response.json() as { categories: Array<{ category: string }> }).categories.map(
    (row) => row.category,
  );
}

/** A seller with one listing per (title, category) pair. Returns their user id. */
async function sellerWith(listings: Array<[title: string, category: string]>): Promise<string> {
  const seller = await register(server, `catseller${listings.length}`);
  await approveSeller(server, seller, `Category Works ${listings.length}`);
  for (const [title, category] of listings) {
    const created = await seller.post("/api/market/listings", {
      title,
      description: "A description long enough to satisfy the validator on this route, honestly.",
      category,
      kind: "service",
      priceXmr: "0.1",
    });
    expect(created.status, `${title} / ${category}`).toBe(200);
  }
  const row = await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
    seller.username,
  ]);
  return row!.id;
}
