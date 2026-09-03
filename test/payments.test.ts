/**
 * Points 81 and 82: what the marketplace discloses about the two parties, and the payment
 * architecture asserted before the feature exists.
 *
 * A test for a feature that has not been built sounds odd until the alternative is
 * considered: the moment someone adds a `card_number` column under delivery pressure, this
 * is what fails, with the reason attached.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { approveSeller, register, startTestServer, type TestServer } from "./helpers.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

/** A completed order with a review on it, which is the state most of these tests need. */
async function soldAndReviewed() {
  const seller = await register(server, "seller");
  const buyer = await register(server, "buyer");
  await approveSeller(server, seller, "Seller Co");
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: "A typeface, licensed properly",
    description: "Five weights, and the licence text is the short kind a person can read.",
    category: "design",
    kind: "digital_good",
    priceMinor: 4900,
    currency: "EUR",
  });
  const order = await buyer.post<{ id: string }>("/api/market/orders", {
    listingId: listing.body.id,
  });
  await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
  await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
  await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
  await buyer.post(`/api/market/orders/${order.body.id}/review`, {
    rating: 5,
    body: "Exactly as described, and delivered the same day.",
  });
  return { seller, buyer, listingId: listing.body.id, orderId: order.body.id };
}

describe("what the marketplace discloses (point 81)", () => {
  it("publishes a review without naming the buyer", async () => {
    const { buyer, listingId } = await soldAndReviewed();
    const detail = await buyer.get<{
      reviews: Array<Record<string, unknown>>;
      listing: { distinctReviewers: number; averageRating: number };
    }>(`/api/market/listings/${listingId}`);

    expect(detail.body.reviews).toHaveLength(1);
    expect(Object.keys(detail.body.reviews[0]!).sort()).toEqual(["body", "postedOn", "rating"]);
    expect(JSON.stringify(detail.body)).not.toContain("buyer");
    // The signal a reader actually needs survives: an average, and how many people it is from.
    expect(detail.body.listing.distinctReviewers).toBe(1);
    expect(detail.body.listing.averageRating).toBe(5);
  });

  it("still enforces one review per order, which is what the author column is for", async () => {
    const { buyer, orderId } = await soldAndReviewed();
    const second = await buyer.post(`/api/market/orders/${orderId}/review`, { rating: 1, body: null });
    expect(second.status).toBe(409);
    const row = await server.db.get<{ author_user_id: string }>(
      "SELECT author_user_id FROM reviews LIMIT 1",
    );
    expect(row!.author_user_id).toBeTruthy();
  });

  it("tells each party only what the transaction needs about the other", async () => {
    const { seller, buyer } = await soldAndReviewed();
    const asSeller = await seller.get<{ orders: Array<Record<string, unknown>> }>(
      "/api/market/orders?role=seller",
    );
    const fields = Object.keys(asSeller.body.orders[0]!).sort();
    // A username (the encrypted order chat is opened by name) and the commercial facts.
    // No email, no address, no payment identity, no account age, no device.
    expect(fields).toEqual([
      "channel",
      "counterparty",
      "currency",
      "id",
      "kind",
      "listingId",
      "placedOn",
      "priceMinor",
      "status",
      "title",
    ]);
    const asBuyer = await buyer.get<{ orders: Array<Record<string, unknown>> }>(
      "/api/market/orders?role=buyer",
    );
    expect(Object.keys(asBuyer.body.orders[0]!).sort()).toEqual(fields);
  });

  it("asks for nothing a seller application does not need", async () => {
    const applicant = await register(server, "applicant");
    const response = await applicant.post("/api/market/seller-applications", {
      displayName: "Studio Quiet",
      statement: "I make small tools and I would like to sell them here, honestly priced.",
      legalName: "A. Person",
      taxId: "GB123456789",
    });
    // Identity documents, company details and tax numbers are not optional-but-accepted:
    // there is no field for them at all.
    expect(response.status).toBe(400);
    expect((response.body as { error: string }).error).toBeTruthy();
  });
});

describe("payments are absent, and the shape they must take is fixed (point 82)", () => {
  it("has no card-shaped column anywhere in the schema", async () => {
    const tables = await server.db.all<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    );
    const columns: string[] = [];
    for (const { name } of tables) {
      const info = await server.db.all<{ name: string }>(`PRAGMA table_info(${name})`);
      columns.push(...info.map((column) => `${name}.${column.name}`));
    }
    const forbidden =
      /(card|pan|cvv|cvc|iban|sort_code|account_number|routing|expiry_month|billing|paypal|stripe)/i;
    expect(columns.filter((column) => forbidden.test(column))).toEqual([]);
  });

  it("has no route that would accept payment details", async () => {
    const routes = server.app.routeInventory.map((route) => route.url);
    expect(routes.filter((url) => /pay|card|checkout|invoice|wallet|balance/i.test(url))).toEqual([]);
  });

  it("has no payment field in any request validator or route module", () => {
    const modules = readdirSync(new URL("../src/server/routes", import.meta.url)).map(String);
    for (const name of modules) {
      const source = read(`src/server/routes/${name}`);
      expect(source, name).not.toMatch(/cardNumber|cvv|iban|billingAddress|paymentToken/i);
    }
  });

  it("refuses the browser's payment API at the header level", async () => {
    const response = await server.app.inject({ method: "GET", url: "/" });
    expect(response.headers["permissions-policy"]).toContain("payment=()");
  });

  it("writes the architecture down before the feature exists", () => {
    const doc = read("docs/PAYMENTS.md");
    expect(doc).toMatch(/PAYMENT STATE|payment state/i);
    expect(doc).toContain("Never stored");
    for (const rule of ["separate", "processor", "escrow"]) {
      expect(doc.toLowerCase(), rule).toContain(rule);
    }
  });
});
