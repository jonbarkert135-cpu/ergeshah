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
import { approveSeller, fund, register, startTestServer, type TestServer } from "./helpers.ts";
import { listColumns, listTables } from "./database.ts";
import {
  MAX_PRICE_PICO,
  MIN_PRICE_PICO,
  PICO_PER_XMR,
  parseXmr,
  xmrString,
} from "../src/shared/money.ts";

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
  await fund(server, buyer, "5");
  await approveSeller(server, seller, "Seller Co");
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: "A typeface, licensed properly",
    description: "Five weights, and the licence text is the short kind a person can read.",
    category: "design",
    kind: "digital_good",
    priceXmr: "0.049",
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
      "id",
      "kind",
      "listingId",
      "placedOn",
      "priceXmr",
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

describe("the payment shape, now that payments exist (point 82, ADR-0066)", () => {
  it("has no card-shaped column anywhere in the schema", async () => {
    const columns: string[] = [];
    for (const name of await listTables(server.db)) {
      columns.push(...(await listColumns(server.db, name)).map((column) => `${name}.${column}`));
    }
    const forbidden =
      /(card|pan|cvv|cvc|iban|sort_code|account_number|routing|expiry_month|billing|paypal|stripe)/i;
    expect(columns.filter((column) => forbidden.test(column))).toEqual([]);
  });

  it("has no route that would accept payment details", async () => {
    const routes = server.app.routeInventory.map((route) => route.url);
    // There is a wallet now, and it is the point: money moves in Monero, held by this
    // marketplace (ADR-0066). What must never appear is the *other* kind of payment route —
    // a card, a checkout, a processor's invoice — because that is the one that brings a PAN,
    // a billing address and a compliance surface with it.
    expect(routes.filter((url) => /card|checkout|invoice|paypal|stripe|iban/i.test(url))).toEqual([]);
    // And the wallet routes that do exist take an amount and a destination, nothing else.
    const wallet = routes.filter((url) => url.startsWith("/api/wallet"));
    expect(wallet.sort()).toEqual([
      "/api/wallet",
      "/api/wallet/entries",
      "/api/wallet/withdrawals",
      "/api/wallet/withdrawals",
      "/api/wallet/withdrawals/:id/cancel",
    ]);
  });

  it("keeps the spend key out of the application entirely", () => {
    // The web application may see money arrive and may write a payout row. It may not sign a
    // transaction, and this is what says so: no spend key, no seed, no signing call anywhere
    // in the server or the client (docs/PAYMENTS.md §Keys).
    const root = new URL("../src/", import.meta.url);
    const files: string[] = [];
    (function walk(directory: URL) {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (entry.isDirectory()) walk(new URL(`${entry.name}/`, directory));
        else if (entry.name.endsWith(".ts")) files.push(`${directory.pathname}${entry.name}`);
      }
    })(root);
    expect(files.length).toBeGreaterThan(30);
    for (const path of files) {
      const source = readFileSync(path, "utf8");
      expect(source, path).not.toMatch(/spend_key|spendKey|wallet_seed|walletSeed|sweep_all|transfer_split/i);
    }
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

  it("writes the architecture down, including the parts that are not built yet", () => {
    const doc = read("docs/PAYMENTS.md");
    expect(doc).toMatch(/PAYMENT STATE|payment state/i);
    expect(doc).toContain("Never stored");
    for (const rule of ["view key", "subaddress", "escrow", "confirmations", "cold"]) {
      expect(doc.toLowerCase(), rule).toContain(rule);
    }
  });
});

/**
 * Prices are Monero, in piconero, as integers. The tests below are the three ways that
 * stops being true by accident: a float in the wire format, a second currency in the
 * schema, and an exchange rate fetched from somewhere.
 */
describe("prices are XMR-native (ADR-0064)", () => {
  it("converts decimal XMR to piconero exactly, and refuses what it cannot", () => {
    expect(parseXmr("0.045")).toBe(45_000_000_000);
    expect(parseXmr("1")).toBe(PICO_PER_XMR);
    // The classic float error: 0.045 * 1e12 is 45000000000.00001 in binary floating point,
    // and a price one piconero out is a payment that never matches.
    expect(parseXmr("0.000000000001")).toBe(1);
    expect(xmrString(45_000_000_000)).toBe("0.045");
    expect(xmrString(PICO_PER_XMR)).toBe("1");
    for (const bad of ["", "-1", "1e-3", "0,045", "0.0000000000001", "12345", " 0.1 x", "Infinity"]) {
      expect(parseXmr(bad), bad).toBeNull();
    }
  });

  it("stores a price as an integer of piconero and returns the string it was given", async () => {
    const seller = await register(server, "seller");
    await approveSeller(server, seller, "Seller Co");
    const created = await seller.post<{ id: string }>("/api/market/listings", {
      title: "A font licence with twelve decimals",
      description: "Priced to the piconero, because the payment will be matched to it.",
      category: "design",
      kind: "digital_good",
      priceXmr: "0.045000000001",
    });
    expect(created.status).toBe(200);
    const row = await server.db.get<{ price_pico: number }>(
      "SELECT price_pico FROM listings WHERE id = ?",
      [created.body.id],
    );
    expect(row!.price_pico).toBe(45_000_000_001);
    const detail = await seller.get<{ listing: { priceXmr: string } }>(
      `/api/market/listings/${created.body.id}`,
    );
    expect(detail.body.listing.priceXmr).toBe("0.045000000001");
  });

  it("refuses a float, a currency, a price under the dust floor and one over the ceiling", async () => {
    const seller = await register(server, "seller2");
    await approveSeller(server, seller, "Seller Two");
    const listing = {
      title: "A perfectly ordinary listing",
      description: "The description is long enough to pass validation, which is all it does.",
      category: "misc",
      kind: "service",
    };
    // A JSON number is refused outright: it is a double, and a double cannot hold every
    // piconero. The field is a string or it is nothing.
    const asNumber = await seller.post("/api/market/listings", { ...listing, priceXmr: 0.045 });
    expect(asNumber.status).toBe(400);
    // Below the fee it would cost to move it.
    const dust = await seller.post("/api/market/listings", {
      ...listing,
      priceXmr: xmrString(MIN_PRICE_PICO - 1),
    });
    expect(dust.status).toBe(400);
    // Past the point where JavaScript integers stop being exact.
    const huge = await seller.post("/api/market/listings", {
      ...listing,
      priceXmr: xmrString(MAX_PRICE_PICO + PICO_PER_XMR),
    });
    expect(huge.status).toBe(400);
    // Free is a price. Zero is allowed, and needs no transfer at all.
    const free = await seller.post("/api/market/listings", { ...listing, priceXmr: "0" });
    expect(free.status).toBe(200);
  });

  it("has no fiat currency and no second currency anywhere in the schema", async () => {
    const columns: string[] = [];
    for (const name of await listTables(server.db)) {
      columns.push(...(await listColumns(server.db, name)).map((column) => `${name}.${column}`));
    }
    expect(columns.filter((column) => /currency|price_minor|amount_usd|fiat/i.test(column))).toEqual([]);
  });

  it("asks nobody for an exchange rate", () => {
    // A rate needs egress, and the application tier has none by design
    // (docs/NETWORK.md). A price oracle in this codebase would be a network dependency
    // hidden inside a display detail — so there is not one, and this is what says so.
    for (const path of [
      "src/server/routes/market.ts",
      "src/server/routes/moderation.ts",
      "src/shared/money.ts",
      "src/client/views/market.ts",
      "src/client/views/orders.ts",
    ]) {
      const source = read(path);
      expect(source, path).not.toMatch(/coingecko|binance|kraken|coinmarketcap|exchange[ _-]?rate/i);
      expect(source, path).not.toMatch(/USD|EUR/);
    }
  });
});
