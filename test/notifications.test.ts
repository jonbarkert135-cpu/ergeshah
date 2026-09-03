/**
 * Point 48: an inbox that tells you something happened without telling the server what.
 *
 * The privacy assertions are the point of this file: a message notification must carry no
 * sender, no channel and no per-message row, and no notification anywhere may contain text a
 * user typed.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  approveSeller,
  promote,
  publishDevice,
  register,
  startTestServer,
  type TestClient,
  type TestServer,
} from "./helpers.ts";
import { pruneNotifications } from "../src/server/lib/notify.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { listColumns } from "./database.ts";

let server: TestServer;

interface Item {
  id: string;
  kind: string;
  subjectType: string | null;
  subjectId: string | null;
  detail: string | null;
  at: number;
  read: boolean;
}
interface Inbox {
  notifications: Item[];
  unread: number;
  nextCursor: string | null;
}

const inbox = (client: TestClient, query = "") => client.get<Inbox>(`/api/notifications${query}`);

async function listingFor(seller: TestClient, title: string): Promise<string> {
  const response = await seller.post<{ id: string }>("/api/market/listings", {
    title,
    description: "A carefully written thing, sold with care and delivered by hand.",
    category: "software",
    kind: "service",
    priceMinor: 2500,
    currency: "USD",
  });
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return response.body.id;
}

beforeAll(async () => {
  // This file registers a couple of dozen accounts; the registration bucket is the product,
  // not the subject here (test/limits.test.ts owns it).
  server = await startTestServer({
    rateLimits: { ...DEFAULT_LIMITS, register: { burst: 100, perMinute: 100 } },
  });
});

afterAll(async () => {
  await server.close();
});

describe("what an inbox holds", () => {
  it("tells the seller about an order, its status changes, and the review", async () => {
    const seller = await register(server, "notifyseller");
    await approveSeller(server, seller, "Notify Seller");
    const listing = await listingFor(seller, "Bookbinding Workshop");
    const buyer = await register(server, "notifybuyer");

    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId: listing });
    expect(order.status).toBe(200);
    let sellerInbox = await inbox(seller);
    expect(sellerInbox.body.notifications[0]).toMatchObject({
      kind: "order",
      subjectType: "order",
      subjectId: order.body.id,
      detail: "placed",
      read: false,
    });
    expect(sellerInbox.body.unread).toBeGreaterThanOrEqual(1);

    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    // The buyer hears about the seller's move, and the seller is not told about their own.
    const buyerInbox = await inbox(buyer);
    expect(buyerInbox.body.notifications[0]).toMatchObject({ kind: "order", detail: "accepted" });
    sellerInbox = await inbox(seller);
    expect(sellerInbox.body.notifications.filter((row) => row.detail === "accepted")).toEqual([]);

    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
    await buyer.post(`/api/market/orders/${order.body.id}/review`, { rating: 5, body: "Superb." });
    const afterReview = await inbox(seller);
    // Looked up by kind rather than by position: the completion and the review can land in
    // the same millisecond, and two rows with the same timestamp have no true order.
    const review = afterReview.body.notifications.find((row) => row.kind === "review");
    expect(review).toMatchObject({ kind: "review", subjectType: "listing", subjectId: listing });
    // The stars and the words are not in the inbox: only that a review exists.
    expect(JSON.stringify(afterReview.body)).not.toContain("Superb");
    // Neither the stars nor the words: the rating appears nowhere in the inbox payload.
    expect(review!.detail).toBeNull();
  });

  it("tells a buyer's counterparty about a dispute, with the kind but not the reason", async () => {
    const seller = await register(server, "disputeseller");
    await approveSeller(server, seller, "Dispute Seller");
    const listing = await listingFor(seller, "Emergency Locksmithing");
    const buyer = await register(server, "disputebuyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId: listing });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    const reason = "The lock was never opened and the phone was never answered.";
    await buyer.post(`/api/market/orders/${order.body.id}/status`, {
      status: "disputed",
      reason,
    });
    const sellerInbox = await inbox(seller);
    expect(sellerInbox.body.notifications[0]).toMatchObject({
      kind: "dispute",
      subjectType: "order",
      subjectId: order.body.id,
    });
    expect(JSON.stringify(sellerInbox.body)).not.toContain("never opened");
  });

  it("tells an applicant about the decision, and a seller about a moderation action", async () => {
    const applicant = await register(server, "applicantone");
    const application = await applicant.post<{ id: string }>("/api/market/seller-applications", {
      displayName: "Applicant One",
      statement: "I would like to sell hand-written fonts and lettering work.",
    });
    const moderator = await register(server, "notifymod");
    await promote(server, moderator.username, "moderator");
    await moderator.post(`/api/moderation/seller-applications/${application.body.id}/decide`, {
      decision: "approved",
      note: "a private note for the record",
    });
    let applicantInbox = await inbox(applicant);
    expect(applicantInbox.body.notifications[0]).toMatchObject({
      kind: "seller_application",
      detail: "approved",
    });
    expect(JSON.stringify(applicantInbox.body)).not.toContain("private note");

    const listing = await listingFor(applicant, "Hand-lettered Wedding Fonts");
    await moderator.post(`/api/moderation/listings/${listing}/remove`, { note: "duplicate" });
    applicantInbox = await inbox(applicant);
    expect(applicantInbox.body.notifications[0]).toMatchObject({
      kind: "moderation",
      subjectType: "listing",
      subjectId: listing,
      detail: "removed",
    });
  });
});

describe("a message notification is a hint, not metadata", () => {
  it("carries no sender, no channel and no subject", async () => {
    const alice = await register(server, "notifyalice");
    const bob = await register(server, "notifybob");
    const bobDevice = await publishDevice(bob);
    const send = await alice.post("/api/messages", {
      to: bob.username,
      channel: "Y2hhbm5lbC1zZWNyZXQtdmFsdWU",
      messages: [{ deviceId: bobDevice, payload: "opaque-ciphertext" }],
    });
    expect(send.status, JSON.stringify(send.body)).toBe(200);
    const bobInbox = await inbox(bob);
    const hint = bobInbox.body.notifications.find((row) => row.kind === "message");
    expect(hint).toMatchObject({ subjectType: null, subjectId: null, detail: null });
    const serialised = JSON.stringify(bobInbox.body);
    expect(serialised).not.toContain("notifyalice");
    expect(serialised).not.toContain("Y2hhbm5lbC1zZWNyZXQtdmFsdWU");
    expect(serialised).not.toContain(bobDevice);
  });

  it("does not count messages: ten of them are one unread row", async () => {
    const alice = await register(server, "counteralice");
    const bob = await register(server, "counterbob");
    const bobDevice = await publishDevice(bob);
    for (let i = 0; i < 10; i += 1) {
      await alice.post("/api/messages", {
        to: bob.username,
        channel: "Y2hhbm5lbC1zZWNyZXQtdmFsdWU",
        messages: [{ deviceId: bobDevice, payload: `ciphertext-${i}` }],
      });
    }
    const rows = await server.db.all<{ n: number }>(
      "SELECT COUNT(*) AS n FROM notifications WHERE kind = 'message' AND user_id = (SELECT id FROM users WHERE username = ?)",
      [bob.username],
    );
    expect(rows[0]!.n).toBe(1);
  });

  it("keeps no free-text column at all", async () => {
    const columns = await listColumns(server.db, "notifications");
    expect([...columns].sort()).toEqual([
      "created_at",
      "detail",
      "id",
      "kind",
      "read_at",
      "subject_id",
      "subject_type",
      "user_id",
    ]);
    // `detail` is short by constraint, so nobody can smuggle a message into it later.
    const insert = server.db.run(
      `INSERT INTO notifications (id, user_id, kind, subject_type, subject_id, detail, created_at)
       VALUES ('overlongdetail', (SELECT id FROM users LIMIT 1), 'order', 'order', 'x', ?, 1)`,
      ["a".repeat(200)],
    );
    await expect(insert).rejects.toThrow();
  });
});

describe("reading, paging and forgetting", () => {
  it("marks one notification read, then the whole inbox", async () => {
    const seller = await register(server, "readseller");
    await approveSeller(server, seller, "Read Seller");
    const listing = await listingFor(seller, "Typesetting for Zines");
    // The seller's own approval notification is already in there; start from a clean slate.
    await seller.post("/api/notifications/read", { all: true });
    const first = await register(server, "readbuyerone");
    const second = await register(server, "readbuyertwo");
    await first.post("/api/market/orders", { listingId: listing });
    await second.post("/api/market/orders", { listingId: listing });

    let page = await inbox(seller);
    expect(page.body.unread).toBe(2);
    await seller.post("/api/notifications/read", { ids: [page.body.notifications[0]!.id] });
    page = await inbox(seller);
    expect(page.body.unread).toBe(1);
    await seller.post("/api/notifications/read", { all: true });
    page = await inbox(seller);
    expect(page.body.unread).toBe(0);
  });

  it("cannot mark someone else's notification read", async () => {
    const seller = await register(server, "privseller");
    await approveSeller(server, seller, "Priv Seller");
    const listing = await listingFor(seller, "Letterpress Business Cards");
    const buyer = await register(server, "privbuyer");
    await buyer.post("/api/market/orders", { listingId: listing });
    const theirs = (await inbox(seller)).body.notifications[0]!;
    const stranger = await register(server, "privstranger");
    const attempt = await stranger.post("/api/notifications/read", { ids: [theirs.id] });
    expect(attempt.status).toBe(200); // nothing to say: the id matches nothing of theirs
    expect((await inbox(seller)).body.notifications[0]!.read).toBe(false);
  });

  it("requires a session, pages by cursor, and rejects a forged one", async () => {
    const anonymous = await server.app.inject({ method: "GET", url: "/api/notifications" });
    expect(anonymous.statusCode).toBe(401);

    const seller = await register(server, "pageseller");
    await approveSeller(server, seller, "Page Seller");
    const listing = await listingFor(seller, "Slow Coffee Subscription");
    for (const name of ["pagebuyerone", "pagebuyertwo", "pagebuyerthree"]) {
      const buyer = await register(server, name);
      await buyer.post("/api/market/orders", { listingId: listing });
    }
    const seen: string[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < 6; i += 1) {
      const query: string = `?limit=1${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const page = await inbox(seller, query);
      expect(page.status, JSON.stringify(page.body)).toBe(200);
      seen.push(...page.body.notifications.map((row) => row.id));
      cursor = page.body.nextCursor;
      if (!cursor) break;
    }
    expect(new Set(seen).size).toBe(seen.length);
    expect(seen.length).toBeGreaterThanOrEqual(3);
    expect((await inbox(seller, "?cursor=nonsense")).status).toBe(400);
    expect((await inbox(seller, "?limit=900")).status).toBe(400);
  });

  it("forgets notifications past the retention window, read or not", async () => {
    const seller = await register(server, "oldseller");
    await approveSeller(server, seller, "Old Seller");
    const listing = await listingFor(seller, "Archival Photo Scanning");
    const buyer = await register(server, "oldbuyer");
    await buyer.post("/api/market/orders", { listingId: listing });
    await server.db.run("UPDATE notifications SET created_at = 1 WHERE created_at > 0");
    await pruneNotifications(server.db, 90 * 24 * 60 * 60 * 1000);
    expect(await server.db.all("SELECT id FROM notifications")).toEqual([]);
  });

  it("goes with the account when the account is deleted", async () => {
    const seller = await register(server, "cascadeseller");
    await approveSeller(server, seller, "Cascade Seller");
    const listing = await listingFor(seller, "Sourdough Starter Coaching");
    const buyer = await register(server, "cascadebuyer");
    await buyer.post("/api/market/orders", { listingId: listing });
    const before = await server.db.all("SELECT id FROM notifications WHERE detail = 'placed'");
    expect(before.length).toBeGreaterThan(0);
    await server.db.run("DELETE FROM users WHERE username = ?", [seller.username]);
    const after = await server.db.all(
      "SELECT n.id FROM notifications n LEFT JOIN users u ON u.id = n.user_id WHERE u.id IS NULL",
    );
    expect(after).toEqual([]);
  });
});
