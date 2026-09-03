import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { approveSeller, promote, register, startTestServer, type TestServer } from "./helpers.ts";

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
