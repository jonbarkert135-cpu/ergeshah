import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";
import { decryptFile, encryptFile, MAX_FILE_BYTES } from "../src/shared/crypto/file.ts";
import { fromBase64Url, toBase64Url, utf8 } from "../src/shared/encoding.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import { listTables } from "./database.ts";

let server: TestServer;

beforeEach(async () => {
  await sodiumReady();
  server = await startTestServer();
  await register(server, "root");
});
afterEach(async () => {
  await server.close();
});

/** A seller, a buyer, and an order the seller has already accepted. */
async function acceptedOrder(): Promise<{
  seller: TestClient;
  buyer: TestClient;
  orderId: string;
}> {
  const seller = await register(server, "seller");
  await approveSeller(server, seller, "Quiet Works");
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: "Field guide (PDF)",
    description: "A long enough description of a perfectly ordinary digital good.",
    category: "books",
    kind: "digital_good",
    priceXmr: "0.009",
  });
  const buyer = await register(server, "buyer");
  const order = await buyer.post<{ id: string }>("/api/market/orders", {
    listingId: listing.body.id,
  });
  await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
  return { seller, buyer, orderId: order.body.id };
}

describe("file encryption", () => {
  it("round-trips, hides the exact length, and is useless with the wrong key", () => {
    const plaintext = utf8("the actual product, delivered");
    const { key, nonce, ciphertext } = encryptFile("order-1", plaintext);

    expect(decryptFile("order-1", key, nonce, ciphertext)).toEqual(plaintext);
    // Padded to a bucket: 29 bytes of content are indistinguishable from 40.
    expect(ciphertext.length).toBe(64 + 16);
    expect(encryptFile("order-1", utf8("x")).ciphertext.length).toBe(64 + 16);

    const wrongKey = encryptFile("order-1", plaintext).key;
    expect(() => decryptFile("order-1", wrongKey, nonce, ciphertext)).toThrow();
    // The order id is associated data: a blob served for another order fails loudly.
    expect(() => decryptFile("order-2", key, nonce, ciphertext)).toThrow();
  });

  it("refuses empty and oversized files rather than truncating them", () => {
    expect(() => encryptFile("order-1", new Uint8Array(0))).toThrow(/empty/);
    expect(() => encryptFile("order-1", new Uint8Array(MAX_FILE_BYTES + 1))).toThrow(/larger/);
  });
});

describe("delivering a digital good", () => {
  it("stores ciphertext the buyer can fetch and the server cannot read", async () => {
    const { seller, buyer, orderId } = await acceptedOrder();
    const secret = utf8("chapter one: how not to collect data");
    const { key, nonce, ciphertext } = encryptFile(orderId, secret);

    const upload = await seller.post<{ status: string }>(
      `/api/market/orders/${orderId}/delivery`,
      { ciphertext: toBase64Url(ciphertext) },
    );
    expect(upload.status).toBe(200);
    expect(upload.body.status).toBe("delivered");

    const orders = await buyer.get<{ orders: Array<{ status: string }> }>("/api/market/orders");
    expect(orders.body.orders[0]?.status).toBe("delivered");

    const fetched = await buyer.get<{ ciphertext: string }>(
      `/api/market/orders/${orderId}/delivery`,
    );
    expect(fetched.status).toBe(200);
    expect(decryptFile(orderId, key, nonce, fromBase64Url(fetched.body.ciphertext))).toEqual(secret);

    // Nothing in the row helps the operator: no key, no filename, no plaintext.
    const row = await server.db.get<Record<string, unknown>>("SELECT * FROM deliveries");
    expect(Object.keys(row ?? {})).toEqual([
      "id",
      "order_id",
      "ciphertext",
      "created_at",
      "expires_at",
    ]);
    const dump = JSON.stringify(row);
    expect(dump).not.toContain(toBase64Url(key));
    expect(dump).not.toContain("chapter one");
  });

  it("lets only the seller deliver, only once, and only from an accepted order", async () => {
    const { seller, buyer, orderId } = await acceptedOrder();
    const payload = { ciphertext: toBase64Url(encryptFile(orderId, utf8("file")).ciphertext) };

    expect((await buyer.post(`/api/market/orders/${orderId}/delivery`, payload)).status).toBe(403);
    const stranger = await register(server, "stranger");
    expect((await stranger.post(`/api/market/orders/${orderId}/delivery`, payload)).status).toBe(404);
    expect((await stranger.get(`/api/market/orders/${orderId}/delivery`)).status).toBe(404);

    expect((await seller.post(`/api/market/orders/${orderId}/delivery`, payload)).status).toBe(200);
    // Second upload: the order is no longer 'accepted', so it is refused before the
    // duplicate check even matters.
    expect((await seller.post(`/api/market/orders/${orderId}/delivery`, payload)).status).toBe(403);
    // The seller is not served the blob back — they have the file.
    expect((await seller.get(`/api/market/orders/${orderId}/delivery`)).status).toBe(403);
  });

  it("forgets the file when the buyer acknowledges it, and when the order ends", async () => {
    const first = await acceptedOrder();
    const payload = {
      ciphertext: toBase64Url(encryptFile(first.orderId, utf8("file")).ciphertext),
    };
    await first.seller.post(`/api/market/orders/${first.orderId}/delivery`, payload);
    expect((await first.buyer.del(`/api/market/orders/${first.orderId}/delivery`)).status).toBe(200);
    expect((await first.buyer.get(`/api/market/orders/${first.orderId}/delivery`)).status).toBe(404);
    expect(await server.db.all("SELECT id FROM deliveries")).toHaveLength(0);

    await server.close();
    server = await startTestServer();
    await register(server, "root");
    const second = await acceptedOrder();
    await second.seller.post(`/api/market/orders/${second.orderId}/delivery`, {
      ciphertext: toBase64Url(encryptFile(second.orderId, utf8("file")).ciphertext),
    });
    await second.buyer.post(`/api/market/orders/${second.orderId}/status`, { status: "completed" });
    expect(await server.db.all("SELECT id FROM deliveries")).toHaveLength(0);
  });

  it("expires a blob nobody collected", async () => {
    const { seller, buyer, orderId } = await acceptedOrder();
    await seller.post(`/api/market/orders/${orderId}/delivery`, {
      ciphertext: toBase64Url(encryptFile(orderId, utf8("file")).ciphertext),
    });
    await server.db.run("UPDATE deliveries SET expires_at = ?", [Date.now() - 1]);
    expect((await buyer.get(`/api/market/orders/${orderId}/delivery`)).status).toBe(404);
    expect(await server.db.all("SELECT id FROM deliveries")).toHaveLength(0);
  });

  it("rejects malformed ciphertext and anything over the cap", async () => {
    await server.close();
    server = await startTestServer({ maxDeliveryBytes: 4096 });
    await register(server, "root");
    const { seller, orderId } = await acceptedOrder();
    const send = (ciphertext: string) =>
      seller.post(`/api/market/orders/${orderId}/delivery`, { ciphertext });

    expect((await send("not base64!!")).status).toBe(400);
    expect((await send("A".repeat(20_000))).status).toBe(400); // over the cap, under the body limit
    const huge = await send("A".repeat(400_000)); // over the body limit: refused before parsing
    expect(huge.status).toBe(413);
    expect(await server.db.all("SELECT id FROM deliveries")).toHaveLength(0);
  });
});

/**
 * Physical orders (MKT-4). The delivery address is the most dangerous field a marketplace
 * can have, so this system does not have it: it travels as an ordinary encrypted message
 * in the order channel, and these tests assert the absence rather than describing it.
 */
describe("shipping details for a physical order", () => {
  it("has no route and no column that would accept an address", async () => {
    const seller = await register(server, "physicalseller");
    await approveSeller(server, seller, "Paper Goods");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "Letterpress notebook",
      description: "A description of a physical object, long enough to pass validation.",
      category: "stationery",
      kind: "physical_good",
      priceXmr: "0.025",
    });
    expect(listing.status).toBe(200);

    const buyer = await register(server, "physicalbuyer");
    const address = "12 Rue des Lilas, 75011 Paris";
    // A naive (or hostile) client sends the address anyway. The route refuses the request
    // rather than dropping the field quietly: silently accepting it would leave a buyer
    // believing their parcel has somewhere to go, and would let the next version of that
    // client depend on a field this server will never store (point 81, ADR-0045).
    const refused = await buyer.post<{ error: string }>("/api/market/orders", {
      listingId: listing.body.id,
      shippingAddress: address,
      note: address,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("unexpected_field");

    const order = await buyer.post<{ id: string }>("/api/market/orders", {
      listingId: listing.body.id,
    });
    expect(order.status).toBe(200);

    const tables = await listTables(server.db);
    const dump: string[] = [];
    for (const name of tables) {
      // audit:allow — table names come from the schema itself; this test dumps it whole
      dump.push(JSON.stringify(await server.db.all(`SELECT * FROM ${name}`)));
    }
    expect(dump.join()).not.toContain("Rue des Lilas");
    expect(dump.join()).not.toContain("shippingAddress");
    // And no column anywhere is named after one, either.
    expect(dump.join().toLowerCase()).not.toContain("address");
  });
});
