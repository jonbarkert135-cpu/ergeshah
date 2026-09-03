/**
 * Authorization, checked against the route table rather than against memory.
 *
 * The rule this file enforces: an endpoint is private unless it is on the list below.
 * Adding a route to the server and forgetting the session check does not produce a subtle
 * hole discovered later — it produces a failing test naming the route, because the test
 * walks `app.routeInventory` instead of a list somebody has to maintain in parallel.
 *
 * It also covers the two failures that authorization tests usually miss: a valid session
 * belonging to *someone else* (ownership), and a valid session with the wrong role, which
 * must be refused by the server no matter what the client renders.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { approveSeller, register, startTestServer, TestClient, type TestServer } from "./helpers.ts";

/**
 * Routes that must work without a session, each with the reason it is public. Anything
 * not listed here is expected to reject an anonymous request.
 */
const PUBLIC: Array<{ method: string; url: string; why: string }> = [
  { method: "GET", url: "/", why: "the app shell" },
  { method: "GET", url: "/healthz", why: "liveness probe for the proxy" },
  { method: "GET", url: "/favicon.svg", why: "static asset" },
  { method: "GET", url: "/build.txt", why: "published build digests (docs/AUDIT.md)" },
  { method: "POST", url: "/api/auth/register", why: "creating the first account" },
  { method: "POST", url: "/api/auth/login", why: "the login itself" },
  { method: "POST", url: "/api/auth/recover", why: "login for someone who lost their password" },
  // The other ways in (routes/recovery.ts). Each one *is* an authentication step, so it
  // cannot require the session it is about to create; each proves something instead — a
  // link secret, a signature over a challenge — and answers identically for a username
  // that does not exist. Until 2026-09 these four passed this sweep only because they were
  // registered before any route that mints a CSRF cookie, which is luck, not a control.
  { method: "POST", url: "/api/auth/link/claim", why: "a new device redeems a one-time link secret" },
  { method: "POST", url: "/api/auth/recovery/challenge", why: "the challenge precedes the session" },
  { method: "POST", url: "/api/auth/recovery/complete", why: "the recovery signature is the login" },
  { method: "POST", url: "/api/auth/pgp/complete", why: "the PGP signature is the second factor of a login" },
  { method: "GET", url: "/api/market/listings", why: "browsing is public by design" },
  { method: "GET", url: "/api/market/listings/:id", why: "browsing is public by design" },
  { method: "GET", url: "/api/market/sellers/:username", why: "a public seller profile" },
];

const isPublic = (method: string, url: string) =>
  // Built assets are content-addressed, so their names change with every build; the
  // pattern is the allowlist entry, and everything under it is a public static file.
  (method === "GET" && /^\/assets\/[A-Za-z0-9._-]+$/.test(url)) ||
  PUBLIC.some((route) => route.method === method && route.url === url);

/** A concrete value for every `:param`, so the request reaches the auth check. */
const concrete = (url: string) => url.replace(/:[a-zA-Z]+/g, "does-not-exist");

let server: TestServer;

beforeAll(async () => {
  server = await startTestServer();
});

afterAll(async () => {
  await server.close();
});

describe("every private route refuses an anonymous caller", () => {
  it("has an inventory to check", () => {
    expect(server.app.routeInventory.length).toBeGreaterThan(20);
  });

  it("answers 401 without a session", async () => {
    const anonymous = new TestClient(server);
    const leaked: string[] = [];

    for (const route of server.app.routeInventory) {
      if (isPublic(route.method, route.url)) continue;
      const response = await anonymous.request(route.method, concrete(route.url), {});
      // 401 is the expected answer. 403 is accepted only for the CSRF layer, which sits
      // in front of authentication and is itself a refusal; anything else — including a
      // 404 that proves the handler ran, or a 500 — means the check is missing or late.
      if (response.status !== 401 && response.status !== 403) {
        leaked.push(`${route.method} ${route.url} -> ${response.status}`);
      }
    }

    expect(leaked).toEqual([]);
  });

  it("the public list is honest: each entry really is reachable anonymously", async () => {
    const anonymous = new TestClient(server);
    for (const route of PUBLIC) {
      if (route.method !== "GET") continue;
      const response = await anonymous.request(route.method, concrete(route.url), {});
      expect([200, 404], `${route.url} (${route.why})`).toContain(response.status);
    }
  });
});

describe("a session is not a licence to touch someone else's data", () => {
  it("refuses a foreign order, and says nothing about whether it exists", async () => {
    const seller = await register(server, "owner-seller");
    const buyer = await register(server, "owner-buyer");
    const stranger = await register(server, "owner-stranger");
    await approveSeller(server, seller, "Ownership Works");

    const listing = await seller.request<{ id: string }>("POST", "/api/market/listings", {
      title: "Ownership probe",
      description: "A listing that exists only so that a stranger can fail to read its order.",
      category: "consulting",
      kind: "service",
      priceXmr: "0.01",
    });
    const order = await buyer.request<{ id: string }>("POST", "/api/market/orders", {
      listingId: listing.body.id,
    });
    expect([200, 201]).toContain(order.status);

    // The order exists and belongs to two people. A third account with a perfectly valid
    // session is not one of them, and the server — not the interface — is what says so.
    const strangerTouches = await stranger.request(
      "POST",
      `/api/market/orders/${order.body.id}/status`,
      { status: "cancelled" },
    );
    expect([403, 404]).toContain(strangerTouches.status);

    const strangerList = await stranger.request<{ orders: Array<{ id: string }> }>(
      "GET",
      "/api/market/orders?role=buyer",
    );
    expect(strangerList.body.orders.map((row) => row.id)).not.toContain(order.body.id);

    // The buyer's own order is visible to the buyer: the check is ownership, not blanket denial.
    const buyerList = await buyer.request<{ orders: Array<{ id: string }> }>(
      "GET",
      "/api/market/orders?role=buyer",
    );
    expect(buyerList.body.orders.map((row) => row.id)).toContain(order.body.id);
  });
});

describe("role checks live on the server", () => {
  it("refuses a normal account on every staff route and records the refusal", async () => {
    const user = await register(server, "role-probe");

    const staffRoutes = server.app.routeInventory.filter((route) =>
      route.url.startsWith("/api/moderation/"),
    );
    expect(staffRoutes.length).toBeGreaterThan(3);

    for (const route of staffRoutes) {
      if (route.url === "/api/moderation/reports" && route.method === "POST") continue; // anyone may report
      const response = await user.request(route.method, concrete(route.url), {});
      expect(response.status, `${route.method} ${route.url}`).toBe(403);
    }

    const denials = await server.db.all<{ action: string; result: string; subject_id: string }>(
      "SELECT action, result, subject_id FROM audit_log WHERE action = 'privileged.denied'",
    );
    expect(denials.length).toBeGreaterThan(0);
    expect(denials.every((row) => row.result === "denied")).toBe(true);
    // The route pattern, not the concrete URL: the log must not become a record of which
    // object a user poked at.
    expect(denials.every((row) => row.subject_id.startsWith("/api/moderation/"))).toBe(true);
    expect(denials.some((row) => row.subject_id.includes("does-not-exist"))).toBe(false);
  });
});
