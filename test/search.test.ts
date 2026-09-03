/**
 * Point 47: search that is indexed, bounded, paginated and unimpressed by hostile input.
 *
 * The interesting assertion is the query plan one: it fails if anybody reintroduces a
 * `LIKE '%term%'` over the listings table, which is the thing this point removed.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { approveSeller, register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";
import { backfillSearchIndex, queryTerms, tokenize } from "../src/server/lib/search.ts";
import { TEST_DIALECT } from "./database.ts";

let server: TestServer;
let seller: TestClient;

interface Page {
  listings: Array<{ id: string; title: string }>;
  nextCursor: string | null;
}

async function list(client: TestClient, query = "") {
  return client.get<Page>(`/api/market/listings${query}`);
}

async function publish(title: string, description: string, category = "software"): Promise<string> {
  const response = await seller.post<{ id: string }>("/api/market/listings", {
    title,
    description,
    category,
    kind: "digital_good",
    priceMinor: 1000,
    currency: "USD",
  });
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return response.body.id;
}

beforeAll(async () => {
  server = await startTestServer();
  seller = await register(server, "searchseller");
  await approveSeller(server, seller, "Search Seller");
  await publish("Hand-built Ambient Synthesizer", "A soft synthesizer for slow ambient music.");
  await publish("Mixing and Mastering Service", "I master your record in a treated room.", "audio");
  await publish("Gitárok tabulatúra pack", "Guitar tablature for classical pieces.", "music");
});

afterAll(async () => {
  await server.close();
});

describe("tokenising", () => {
  it("keeps words, drops punctuation, folds accents and case", () => {
    expect(tokenize("Gitárok, TABS & things!")).toEqual(["gitarok", "tabs", "things"]);
  });

  it("cannot produce a wildcard, a quote or a one-letter term", () => {
    expect(tokenize("a % _ ' \" -- ; DROP")).toEqual(["drop"]);
  });

  it("caps how many terms one query may ask for", () => {
    expect(queryTerms("one two three four five six seven eight").length).toBe(6);
  });
});

describe("searching", () => {
  it("finds a listing by a word in its title, its description or its category", async () => {
    for (const [term, title] of [
      ["synthesizer", "Hand-built Ambient Synthesizer"],
      ["treated", "Mixing and Mastering Service"],
      ["audio", "Mixing and Mastering Service"],
    ] as const) {
      const page = await list(seller, `?q=${term}`);
      expect(page.body.listings.map((row) => row.title), term).toContain(title);
    }
  });

  it("matches a prefix, and accent-folds the query the same way as the index", async () => {
    const page = await list(seller, "?q=gitar");
    expect(page.body.listings.map((row) => row.title)).toEqual(["Gitárok tabulatúra pack"]);
  });

  it("narrows on two words instead of widening", async () => {
    const both = await list(seller, "?q=ambient%20synthesizer");
    expect(both.body.listings).toHaveLength(1);
    const neither = await list(seller, "?q=ambient%20tablature");
    expect(neither.body.listings).toHaveLength(0);
  });

  it("refuses a query with no usable term rather than answering with everything", async () => {
    const response = await list(seller, "?q=%25%20_%20-");
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ error: "query_too_vague" });
  });

  it("treats SQL and LIKE metacharacters as text, not as syntax", async () => {
    for (const hostile of ["%25", "synthesizer%27%3B--", "_ynthesizer", "%22%20OR%201%3D1"]) {
      const response = await list(seller, `?q=${hostile}`);
      expect([200, 400], hostile).toContain(response.status);
      if (response.status === 200) {
        expect(response.body.listings.length, hostile).toBeLessThanOrEqual(1);
      }
    }
    // The catalogue is still there afterwards: nothing was dropped or truncated.
    expect((await list(seller)).body.listings.length).toBeGreaterThanOrEqual(3);
  });

  it("reindexes an edited listing, and stops finding it by the old words", async () => {
    const id = await publish("Temporary Widget Name", "A placeholder description for a widget.");
    expect((await list(seller, "?q=widget")).body.listings.map((row) => row.id)).toContain(id);
    await seller.patch(`/api/market/listings/${id}`, { title: "Permanent Sculpture Name" });
    expect((await list(seller, "?q=widget")).body.listings.map((row) => row.id)).toContain(id);
    expect((await list(seller, "?q=sculpture")).body.listings.map((row) => row.id)).toContain(id);
    await server.db.run("DELETE FROM listings WHERE id = ?", [id]);
  });

  it("drops index rows with the listing they describe", async () => {
    const id = await publish("Disposable Kaleidoscope", "Something to delete in a moment.");
    await server.db.run("DELETE FROM listings WHERE id = ?", [id]);
    const left = await server.db.all("SELECT term FROM listing_terms WHERE listing_id = ?", [id]);
    expect(left).toEqual([]);
  });

  it("backfills listings that predate the index, and does nothing on the second run", async () => {
    await server.db.run("DELETE FROM listing_terms");
    expect(await backfillSearchIndex(server.db)).toBeGreaterThanOrEqual(3);
    expect(await backfillSearchIndex(server.db)).toBe(0);
    expect((await list(seller, "?q=synthesizer")).body.listings).toHaveLength(1);
  });
});

describe("pagination", () => {
  it("pages by cursor, never repeats a row, and stops", async () => {
    const seen: string[] = [];
    let cursor: string | null = null;
    for (let page = 0; page < 10; page += 1) {
      const query: string = `?limit=1${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const response = await list(seller, query);
      expect(response.status, JSON.stringify(response.body)).toBe(200);
      expect(response.body.listings.length).toBeLessThanOrEqual(1);
      seen.push(...response.body.listings.map((row) => row.id));
      cursor = response.body.nextCursor;
      if (!cursor) break;
    }
    expect(cursor).toBeNull();
    expect(new Set(seen).size).toBe(seen.length);
    expect(seen.length).toBeGreaterThanOrEqual(3);
  });

  it("caps the page size and rejects a forged cursor", async () => {
    expect((await list(seller, "?limit=500")).status).toBe(400);
    expect((await list(seller, "?cursor=1%20OR%201%3D1")).status).toBe(400);
    expect((await list(seller, "?cursor=99999999.abc")).status).toBe(400);
  });
});

describe("the query plan", () => {
  // SQLite only, and not for lack of trying: PostgreSQL's planner chooses a sequential scan
  // on a table of five rows whatever the indexes say, so the same assertion there would
  // measure the size of the fixture rather than the shape of the query. The indexes exist in
  // both (one schema, `test/migrations.test.ts`); what is checked here is that the query the
  // marketplace runs can use them.
  it.skipIf(TEST_DIALECT === "postgres")("uses an index for a search and never scans the listings table", async () => {
    const plan = await server.db.all<{ detail: string }>(
      `EXPLAIN QUERY PLAN
       SELECT l.id FROM listings l
         JOIN sellers s ON s.user_id = l.seller_user_id
         JOIN users u ON u.id = l.seller_user_id
        WHERE l.status = 'active' AND s.status = 'active'
          AND l.id IN (SELECT listing_id FROM listing_terms
                        WHERE term >= ? AND term < ? AND term LIKE ?)
        ORDER BY l.created_day DESC, l.id DESC LIMIT ?`,
      ["synth", "synth\uFFFF", "synth%", 21],
    );
    const details = plan.map((row) => row.detail).join("\n");
    expect(details, details).toMatch(/(SEARCH|SCAN) listing_terms USING (COVERING )?(PRIMARY KEY|INDEX)/);
    expect(details, details).not.toMatch(/SCAN listings/);
  });

  it("has no LIKE '%…' pattern left in the marketplace routes", async () => {
    const source = await import("node:fs").then(({ readFileSync }) =>
      readFileSync(new URL("../src/server/routes/market.ts", import.meta.url), "utf8"),
    );
    expect(source).not.toMatch(/LIKE \?/);
    expect(source).not.toContain("%${");
  });
});
