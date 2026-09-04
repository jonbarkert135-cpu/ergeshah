import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, fund, promote, register, startTestServer, type TestServer } from "./helpers.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root");
});
afterEach(async () => {
  await server.close();
});

describe("moderation powers and their limits", () => {
  it("keeps the moderation queue away from ordinary users", async () => {
    const user = await register(server, "curious");
    expect((await user.get("/api/moderation/queue")).status).toBe(403);
    expect((await user.get("/api/moderation/audit")).status).toBe(403);
    expect((await user.post("/api/admin/users/root/role", { role: "admin" })).status).toBe(403);
  });

  it("records every moderator action in the audit log", async () => {
    const moderator = await register(server, "mod");
    await promote(server, "mod", "moderator");
    const seller = await register(server, "vendor");
    const application = await seller.post<{ id: string }>("/api/market/seller-applications", {
      displayName: "Vendor",
      statement: "Selling handmade software for people who read the source first.",
    });
    await moderator.post(`/api/moderation/seller-applications/${application.body.id}/decide`, {
      decision: "approved",
      note: "looks fine",
    });
    const audit = await moderator.get<{ entries: Array<{ action: string; note: string }> }>(
      "/api/moderation/audit",
    );
    expect(audit.body.entries[0]?.action).toBe("seller_application.decided");
    expect(audit.body.entries[0]?.note).toBe("approved");
  });

  it("removes a reported listing and hides it from the market", async () => {
    const seller = await register(server, "vendor");
    await approveSeller(server, seller, "Vendor");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "Definitely not allowed",
      description: "Something a moderator is going to take down within the minute.",
      category: "misc",
      kind: "digital_good",
      priceXmr: "0.005",
    });
    const reporter = await register(server, "reporter");
    const report = await reporter.post<{ id: string }>("/api/moderation/reports", {
      targetType: "listing",
      targetId: listing.body.id,
      reason: "prohibited_goods",
      details: "This breaks the rules.",
    });

    const moderator = await register(server, "mod");
    await promote(server, "mod", "moderator");
    const queue = await moderator.get<{ reports: Array<{ id: string }> }>("/api/moderation/queue");
    expect(queue.body.reports.map((entry) => entry.id)).toContain(report.body.id);

    await moderator.post(`/api/moderation/listings/${listing.body.id}/remove`, { note: "rules" });
    await moderator.post(`/api/moderation/reports/${report.body.id}/resolve`, {
      outcome: "actioned",
      note: "listing removed",
    });

    const market = await reporter.get<{ listings: Array<{ id: string }> }>("/api/market/listings");
    expect(market.body.listings.map((entry) => entry.id)).not.toContain(listing.body.id);
    expect((await reporter.get(`/api/market/listings/${listing.body.id}`)).status).toBe(404);
    // A removed listing is not editable back into existence by its seller.
    expect((await seller.patch(`/api/market/listings/${listing.body.id}`, { status: "active" })).status).toBe(403);
    const resolved = await moderator.get<{ reports: unknown[] }>("/api/moderation/queue");
    expect(resolved.body.reports).toHaveLength(0);
  });

  it("suspends a seller and takes their listings out of the market", async () => {
    const seller = await register(server, "vendor");
    await approveSeller(server, seller, "Vendor");
    await seller.post("/api/market/listings", {
      title: "A listing that will vanish",
      description: "It disappears when its seller is suspended, without being deleted.",
      category: "misc",
      kind: "service",
      priceXmr: "0.001",
    });
    const moderator = await register(server, "mod");
    await promote(server, "mod", "moderator");
    await moderator.post("/api/moderation/users/vendor/status", {
      status: "suspended",
      reason: "fraud reports",
    });

    const shopper = await register(server, "shopper");
    const market = await shopper.get<{ listings: unknown[] }>("/api/market/listings");
    expect(market.body.listings).toHaveLength(0);

    await moderator.post("/api/moderation/users/vendor/status", { status: "active" });
    const restored = await shopper.get<{ listings: unknown[] }>("/api/market/listings");
    expect(restored.body.listings).toHaveLength(1);
  });

  it("does not let a moderator touch an admin, or promote anyone", async () => {
    const moderator = await register(server, "mod");
    await promote(server, "mod", "moderator");
    expect((await moderator.post("/api/moderation/users/root/status", { status: "suspended" })).status).toBe(400);
    expect((await moderator.post("/api/admin/users/mod/role", { role: "admin" })).status).toBe(403);
  });

  it("has no endpoint that exposes message contents to staff", async () => {
    const admin = await register(server, "boss");
    await promote(server, "boss", "admin");
    for (const url of ["/api/messages", "/api/messages?deviceId=any", "/api/moderation/messages"]) {
      const response = await admin.get(url);
      expect(response.status).not.toBe(200);
    }
    const source = await import("node:fs/promises");
    const routes = await source.readdir("src/server/routes");
    for (const file of routes) {
      const text = await source.readFile(`src/server/routes/${file}`, "utf8");
      // The only table that holds ciphertext must never be read by moderation code.
      if (file === "moderation.ts") expect(text).not.toContain("envelopes");
    }
  });
});

describe("the audit log holds actions, never content (point 41)", () => {
  it("records the action and refuses to carry the words anybody typed", async () => {
    const moderator = await register(server, "mod");
    await promote(server, "mod", "moderator");
    const seller = await register(server, "vendor");
    // Every free-text field a privileged action can be given, filled with something that
    // must not end up in the log: a statement, a note, a report's details.
    const application = await seller.post<{ id: string }>("/api/market/seller-applications", {
      displayName: "Vendor",
      statement: "My wallet is 44AFFq5kSiGBoZ and I live at 12 Bank Street, ask for Jane.",
    });
    await moderator.post(`/api/moderation/seller-applications/${application.body.id}/decide`, {
      decision: "approved",
      note: "call her on 555-0134 about the address",
    });
    // And a refusal, which is audited too.
    await seller.get("/api/moderation/queue");

    const rows = await server.db.all<Record<string, unknown>>("SELECT * FROM audit_log");
    expect(rows.length).toBeGreaterThan(1);
    const serialised = JSON.stringify(rows);
    for (const secret of [
      "44AFFq5kSiGBoZ",
      "Bank Street",
      "555-0134",
      "call her",
      "ask for Jane",
    ]) {
      expect(serialised, secret).not.toContain(secret);
    }
    // `note` is a controlled vocabulary, not a text field: short, and one of a known set.
    for (const row of rows) {
      const note = String(row.note ?? "");
      expect(note.length, `note: ${note}`).toBeLessThanOrEqual(64);
      expect(note, `note: ${note}`).toMatch(/^[a-z0-9_.:\/ -]*$/i);
    }
    // No column holds anything that looks like key material or a long opaque blob.
    for (const row of rows) {
      for (const [column, value] of Object.entries(row)) {
        if (typeof value !== "string") continue;
        expect(value, `${column} = ${value}`).not.toMatch(/[A-Za-z0-9_-]{80,}/);
      }
    }
  });
});

describe("what a moderator sees about both sides of a dispute (ADR-0083)", () => {
  it("shows the buyer's record beside the seller's, and no verdict", async () => {
    const moderator = await register(server, "referee2");
    await promote(server, "referee2", "moderator");
    const seller = await register(server, "vendor2");
    await approveSeller(server, seller, "Vendor Two");
    const listings: string[] = [];
    for (const title of ["A thing that will be argued about", "Another thing, same story"]) {
      const created = await seller.post<{ id: string }>("/api/market/listings", {
        title,
        description: "A description long enough to satisfy the validator on this route, honestly.",
        category: "software",
        kind: "digital_good",
        priceXmr: "0.1",
      });
      listings.push(created.body.id);
    }
    const buyer = await register(server, "serialdisputer");
    await fund(server, buyer, "1");

    // Two orders, both disputed: the pattern the seller's record alone cannot show.
    for (const listingId of listings) {
      const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
      await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
      await buyer.post(`/api/market/orders/${order.body.id}/status`, {
        status: "disputed",
        reason: "Nothing was delivered and the seller has stopped answering me entirely.",
      });
    }

    const queue = await moderator.get<{
      reports: Array<{
        order: {
          buyerRecord: { orders: number; completedOrders: number; disputedOrders: number; disputeRate: number };
          sellerRecord: { completedOrders: number };
        } | null;
      }>;
    }>("/api/moderation/queue");
    expect(queue.status).toBe(200);
    const entry = queue.body.reports.find((report) => report.order !== null);
    expect(entry?.order?.buyerRecord).toEqual({
      orders: 2,
      completedOrders: 0,
      disputedOrders: 2,
      disputeRate: 100,
    });
    // And the seller's record is still there: the queue gained a second column, not a score
    // that decides anything.
    expect(entry?.order?.sellerRecord.completedOrders).toBe(0);
  });
});
