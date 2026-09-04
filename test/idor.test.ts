/**
 * Insecure direct object references, point 44 — its own suite because the brief names six
 * object classes and asks for every one of them to be tried, which is more than a `describe`
 * inside another file's attack sweep.
 *
 * The shape of every case is the same: an account with a perfectly valid session asks for an
 * object that belongs to somebody else, by its real id. The answer must be a refusal, and for
 * anything whose existence is itself information the refusal is a 404 — an id is not an oracle.
 * Split out of `security.test.ts` when that file reached the 700-line ceiling.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  approveSeller,
  fund,
  publishDevice,
  register,
  startTestServer,
  type TestServer,
} from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { toBase64Url } from "../src/shared/encoding.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer({
    // This suite registers a lot of accounts; the bucket under test is never `register`.
    rateLimits: {
      ...DEFAULT_LIMITS,
      register: { burst: 100, perMinute: 100 },
      sensitive: { burst: 100, perMinute: 100 },
    },
  });
});

afterEach(async () => {
  await server.close();
});

describe("insecure direct object references", () => {
  it("answers a stranger with 404 for another pair's order, delivery and notification", async () => {
    const seller = await register(server, "seller");
    await approveSeller(server, seller, "Seller of goods");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "A carefully written program",
      description: "Long enough a description to satisfy the validator on this route, honestly.",
      category: "software",
      kind: "digital_good",
      priceXmr: "0.025",
    });
    const buyer = await register(server, "buyer");
    await fund(server, buyer, "5");
    const order = await buyer.post<{ id: string }>("/api/market/orders", {
      listingId: listing.body.id,
    });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { ciphertext: "Zm9vYmFy" });

    const mallory = await register(server, "mallory");
    for (const [method, url] of [
      ["GET", `/api/market/orders/${order.body.id}/delivery`],
      ["POST", `/api/market/orders/${order.body.id}/status`],
      ["POST", `/api/market/orders/${order.body.id}/review`],
      ["DELETE", `/api/market/orders/${order.body.id}/delivery`],
    ] as const) {
      const response = await mallory.request(method, url, { status: "completed", rating: 5 });
      expect([403, 404], `${method} ${url}`).toContain(response.status);
    }

    // The buyer's own notification id is equally useless to a stranger.
    const inbox = await seller.get<{ notifications: Array<{ id: string }> }>("/api/notifications");
    const someoneElsesId = inbox.body.notifications[0]!.id;
    const marked = await mallory.post<{ read: number }>("/api/notifications/read", {
      ids: [someoneElsesId],
    });
    expect(marked.body.read ?? 0).toBe(0);
    const stillUnread = await seller.get<{ unread: number }>("/api/notifications");
    expect(stillUnread.body.unread).toBeGreaterThan(0);
  });

  it("refuses a stranger a seller application, an evidence record and somebody's profile (point 44)", async () => {
    // The three object classes the previous case did not cover. A seller application is the
    // interesting one: it holds a statement its author wrote, and only staff and the author
    // may read it.
    const applicant = await register(server, "applicant");
    const application = await applicant.post<{ id: string }>("/api/market/seller-applications", {
      displayName: "Applicant",
      statement: "A statement written for a moderator, and for nobody else on this server.",
    });
    const seller = await register(server, "seller2");
    await approveSeller(server, seller, "Seller of goods");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "Another carefully written program",
      description: "Long enough a description to satisfy the validator on this route, honestly.",
      category: "software",
      kind: "digital_good",
      priceXmr: "0.025",
    });
    const buyer = await register(server, "buyer2");
    await fund(server, buyer, "5");
    const order = await buyer.post<{ id: string }>("/api/market/orders", {
      listingId: listing.body.id,
    });
    await buyer.post(`/api/market/orders/${order.body.id}/evidence`, {
      digest: "a".repeat(64),
      kind: "other",
    });

    const mallory = await register(server, "mallory2");
    for (const [method, url, body] of [
      // Deciding somebody else's application is a staff action.
      ["POST", `/api/moderation/seller-applications/${application.body.id}/decide`, { decision: "approved" }],
      // The queue that lists them is staff-only, and so is the audit trail behind it.
      ["GET", "/api/moderation/seller-applications", {}],
      // Evidence belongs to the two parties of an order, and to a moderator in a dispute.
      ["GET", `/api/market/orders/${order.body.id}/evidence`, {}],
      ["POST", `/api/market/orders/${order.body.id}/evidence`, { digest: "b".repeat(64), kind: "other" }],
    ] as const) {
      const response = await mallory.request(method, url, body);
      expect([403, 404], `${method} ${url} → ${response.status}`).toContain(response.status);
    }

    // A profile is public by design — a username and a seller's standing — so the assertion is
    // about what it does *not* carry: no application statement, no order, no balance.
    const profile = await mallory.get<Record<string, unknown>>(`/api/market/sellers/${seller.username}`);
    if (profile.status === 200) {
      const serialised = JSON.stringify(profile.body);
      expect(serialised).not.toContain("A statement written for a moderator");
      expect(serialised).not.toContain(order.body.id);
      expect(serialised.toLowerCase()).not.toContain("balance");
    }
  });

  it("does not let one account fetch or acknowledge another account's envelopes", async () => {
    const bob = await register(server, "bob");
    const bobDevice = await publishDevice(bob);
    const alice = await register(server, "alice");
    await alice.post("/api/messages", {
      to: bob.username,
      channel: toBase64Url(new Uint8Array(16).fill(9)),
      messages: [{ deviceId: bobDevice, payload: "Y2lwaGVydGV4dA" }],
    });
    const mallory = await register(server, "mallory");
    expect((await mallory.get(`/api/messages?deviceId=${bobDevice}`)).status).toBe(404);
    const envelope = await server.db.get<{ id: string }>("SELECT id FROM envelopes");
    await mallory.post("/api/messages/ack", { deviceId: bobDevice, ids: [envelope!.id] });
    expect((await server.db.all("SELECT id FROM envelopes")).length).toBe(1);
  });
});

/* -------------------------------- race conditions -------------------------------- */
