/**
 * Authorization fuzzing, points 162, 163 and 164.
 *
 * `test/authorization.test.ts` proves the first row of the matrix — every private route
 * refuses an anonymous caller — and `test/idor.test.ts` walks six object classes by hand.
 * This suite is the rest of the matrix, and it is generated from `app.routeInventory` rather
 * than from a list, so a route added next month is fuzzed without anybody remembering to add
 * it here:
 *
 *   | credential state | expected |
 *   | --- | --- |
 *   | a session that expired | 401 |
 *   | a session that was revoked (signed out everywhere) | 401 |
 *   | a valid session on a suspended account | 403 |
 *   | a valid session with the wrong role | 403, or 404 where existence is itself a secret |
 *   | a malformed identifier | a 4xx that is not 200 and not 500 |
 *   | a real identifier belonging to another account | 401/403/404, never the object |
 *   | a body carrying privileged fields | no privileged column moves |
 *
 * The last two are points 163 and 164. Both are checked *behaviourally* — the sweep reads
 * the database before and after — because "the handler ignores unknown fields" is a property
 * of today's handlers, and the assertion that survives a rewrite is the one about state.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {
  approveSeller,
  fund,
  promote,
  publishDevice,
  register,
  startTestServer,
  type TestServer,
  TestClient,
} from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";

/** This suite registers dozens of accounts and sends thousands of requests; the buckets are not what it tests. */
const LOOSE = Object.fromEntries(
  Object.keys(DEFAULT_LIMITS).map((name) => [name, { burst: 100_000, perMinute: 100_000 }]),
) as typeof DEFAULT_LIMITS;

/**
 * Routes that answer a stranger on purpose, with the reason. Everything else is expected to
 * refuse one, which is what makes this sweep a test rather than a snapshot.
 */
const OPEN_TO_STRANGERS: Array<{ url: string; why: string }> = [
  { url: "/", why: "the app shell" },
  { url: "/healthz", why: "liveness" },
  { url: "/favicon.svg", why: "static asset" },
  { url: "/build.txt", why: "published build digests" },
  { url: "/api/canary", why: "the operator's signed statement (ADR-0099)" },
  { url: "/api/market/listings", why: "browsing is public" },
  { url: "/api/market/listings/:id", why: "browsing is public" },
  { url: "/api/market/categories", why: "browsing is public" },
  { url: "/api/market/sellers/:username", why: "a public seller profile" },
  { url: "/api/keys/bundle/:username", why: "a prekey bundle is how a stranger starts a conversation" },
  { url: "/api/keys/identity/:username", why: "the same identity keys the bundle publishes, minus the prekey it would spend (ADR-0112)" },
];

/** Registration, login and the other ways in cannot require the session they create. */
const UNAUTHENTICATED_ENTRY = /^\/api\/auth\/(register|login|recover|link\/claim|recovery\/(challenge|complete)|pgp\/complete)$/;

/** The payout queue is the worker's, and it authenticates with a bearer token, not a session. */
const WORKER = /^\/api\/payouts\//;

/**
 * Two exceptions that are design, not holes, and each is written here rather than papered
 * over in an assertion (point 153: a suppression carries its reason).
 *
 * `POST /api/moderation/reports` sits under the staff prefix and is *not* staff-only: filing
 * a report is what an ordinary user does, and the moderators are who reads it. The path is a
 * naming trap and is recorded as SEC-2026-004 in `docs/SECURITY_FINDINGS.md`.
 *
 * `DELETE /api/attachments/:id` has no owner column on purpose (ADR-0043): a blind blob's id
 * *is* the capability, so any authenticated caller may present one, and an id that matches
 * nothing answers `{deleted: 0}` rather than 404. What must stay true is that presenting
 * somebody else's *other* identifier — an order id, a session id — deletes nothing, which is
 * asserted below instead.
 */
const USER_FACING_UNDER_STAFF_PREFIX = new Set(["/api/moderation/reports"]);
const CAPABILITY_BY_ID = new Set(["/api/attachments/:id"]);

const isOpen = (url: string) =>
  OPEN_TO_STRANGERS.some((route) => route.url === url) || /^\/assets\//.test(url);

const concrete = (url: string, value = "does-not-exist") => url.replace(/:[a-zA-Z]+/g, value);

let server: TestServer;
/** The first account of a deployment is its administrator (ADR-0104), so it is created first. */
let owner: TestClient;

beforeAll(async () => {
  server = await startTestServer({ rateLimits: LOOSE, powBits: 0 });
  owner = await register(server, "authzowner");
}, 120_000);

afterAll(async () => {
  await server.close();
});

describe("a session in the wrong state is refused everywhere (point 162)", () => {
  it("refuses an expired session with 401 on every private route", async () => {
    const client = await register(server, "expiredsession");
    await server.db.run("UPDATE sessions SET expires_at = 1 WHERE user_id = (SELECT id FROM users WHERE username = ?)", [
      "expiredsession",
    ]);
    const wrong: string[] = [];
    for (const route of server.app.routeInventory) {
      if (isOpen(route.url) || UNAUTHENTICATED_ENTRY.test(route.url) || WORKER.test(route.url)) continue;
      const response = await client.request(route.method, concrete(route.url), {});
      // 403 is allowed only for the CSRF layer, which sits in front of authentication.
      if (response.status !== 401 && response.status !== 403) {
        wrong.push(`${route.method} ${route.url} -> ${response.status}`);
      }
    }
    expect(wrong).toEqual([]);
  }, 120_000);

  it("refuses a revoked session, and does not resurrect it through the rotation path", async () => {
    const client = await register(server, "revokedsession");
    const token = client.cookie("session");
    await client.post("/api/auth/logout-everywhere", {});
    const after = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `session=${token}` },
    });
    expect(after.statusCode).toBe(401);
    // A session row deleted underneath a live cookie is the same answer.
    const other = await register(server, "deletedsession");
    const otherToken = other.cookie("session");
    await server.db.run("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", [
      "deletedsession",
    ]);
    const gone = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `session=${otherToken}` },
    });
    expect(gone.statusCode).toBe(401);
  }, 60_000);

  it("refuses a suspended account with 403, on reads as well as writes", async () => {
    const client = await register(server, "suspendedacct");
    await server.db.run("UPDATE users SET status = 'suspended' WHERE username = ?", ["suspendedacct"]);
    const wrong: string[] = [];
    for (const route of server.app.routeInventory) {
      if (isOpen(route.url) || UNAUTHENTICATED_ENTRY.test(route.url) || WORKER.test(route.url)) continue;
      const response = await client.request(route.method, concrete(route.url), {});
      if (response.status !== 403) wrong.push(`${route.method} ${route.url} -> ${response.status}`);
    }
    expect(wrong).toEqual([]);
  }, 120_000);

  it("refuses an ordinary account on every staff route, and audits the refusal", async () => {
    const client = await register(server, "notstaff");
    const staffRoutes = server.app.routeInventory.filter((route) =>
      /^\/api\/(moderation|admin)\/|^\/api\/market\/moderation\//.test(route.url),
    );
    expect(staffRoutes.length).toBeGreaterThan(10);
    const wrong: string[] = [];
    for (const route of staffRoutes) {
      if (USER_FACING_UNDER_STAFF_PREFIX.has(route.url)) continue;
      const response = await client.request(route.method, concrete(route.url), {});
      if (response.status !== 403 && response.status !== 404) {
        wrong.push(`${route.method} ${route.url} -> ${response.status}`);
      }
    }
    expect(wrong).toEqual([]);
    const denials = await server.db.get<{ count: number }>(
      "SELECT COUNT(*) AS count FROM audit_log WHERE action = 'privileged.denied'",
    );
    expect(Number(denials?.count ?? 0)).toBeGreaterThan(0);
  }, 120_000);

  it("refuses a moderator on the routes reserved for an administrator", async () => {
    const client = await register(server, "justamoderator");
    await promote(server, "justamoderator", "moderator");
    const adminOnly = [
      { method: "GET", url: "/api/admin/health" },
      { method: "GET", url: "/api/admin/treasury" },
      { method: "POST", url: "/api/admin/canary" },
      { method: "POST", url: "/api/admin/users/someone/role" },
      { method: "POST", url: "/api/admin/users/someone/payout-limit" },
    ];
    for (const route of adminOnly) {
      const response = await client.request(route.method, route.url, { role: "admin", limitXmr: "100" });
      expect([403, 404]).toContain(response.status);
    }
  }, 60_000);

  it("refuses the payout queue without the worker token, and does not accept a session instead", async () => {
    for (const route of server.app.routeInventory.filter((r) => WORKER.test(r.url))) {
      const withSession = await owner.request(route.method, concrete(route.url), { amountXmr: "1", txid: "x" });
      expect(withSession.status).toBe(401);
      const withBadToken = await server.app.inject({
        method: route.method as "POST",
        url: concrete(route.url),
        headers: {
          authorization: "Bearer not-the-token",
          host: "localhost",
          origin: "http://localhost",
          "content-type": "application/json",
        },
        payload: "{}",
      });
      expect([401, 403]).toContain(withBadToken.statusCode);
    }
  }, 60_000);
});

describe("a malformed identifier is refused, never guessed (point 163)", () => {
  it("answers a 4xx for every shape of identifier on every parameterised route", async () => {
    const client = await register(server, "malformedids");
    const identifiers = [
      "",
      " ",
      "-1",
      "0",
      "null",
      "undefined",
      "%00",
      "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..",
      "a".repeat(300),
      "' OR '1'='1",
      "1 OR 1=1",
      "*",
      "%25",
      "\uFEFFid",
      "00000000-0000-0000-0000-000000000000",
    ];
    const wrong: string[] = [];
    for (const route of server.app.routeInventory) {
      if (!route.url.includes(":") || isOpen(route.url) || WORKER.test(route.url)) continue;
      for (const identifier of identifiers) {
        const url = route.url.replace(/:[a-zA-Z]+/g, () => encodeURIComponent(identifier));
        const response = await client.request(route.method, url, {});
        if (CAPABILITY_BY_ID.has(route.url) && response.status === 200) {
          expect(response.body).toEqual({ deleted: 0 });
          continue;
        }
        if (response.status < 400 || response.status >= 500) {
          wrong.push(`${route.method} ${route.url} [${JSON.stringify(identifier).slice(0, 20)}] -> ${response.status}`);
        }
      }
    }
    expect(wrong).toEqual([]);
  }, 180_000);
});

describe("an identifier belonging to somebody else is not an authorisation (point 163)", () => {
  it("refuses a stranger every real identifier this deployment holds", async () => {
    // One account with something of every kind: a seller with a listing, a buyer with an
    // order and a delivery, a device, an attachment, a notification, a session, a withdrawal.
    const seller = await register(server, "idorseller");
    await approveSeller(server, seller, "IDOR seller of goods");
    await publishDevice(seller);
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "A carefully written program",
      description: "Long enough a description to satisfy the validator on this route, honestly.",
      category: "software",
      kind: "digital_good",
      priceXmr: "0.025",
    });
    const buyer = await register(server, "idorbuyer");
    await publishDevice(buyer);
    await fund(server, buyer, "5");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId: listing.body.id });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { ciphertext: "Zm9vYmFy" });
    await buyer.post("/api/wallet/withdrawals", { amountXmr: "0.5", address: "4".padEnd(95, "1") }).catch(() => undefined);

    // Every identifier the deployment now holds, harvested from the tables themselves so a
    // new object class is swept the day its table appears.
    const harvest: Array<[string, string]> = [];
    for (const [table, column] of [
      ["listings", "id"],
      ["orders", "id"],
      ["deliveries", "id"],
      ["notifications", "id"],
      ["sessions", "id"],
      ["devices", "id"],
      ["attachments", "id"],
      ["withdrawals", "id"],
      ["reports", "id"],
      ["seller_applications", "id"],
    ] as Array<[string, string]>) {
      // audit:allow — the table and column are literals from the array above, not input.
      const rows = await server.db.all<Record<string, string>>(`SELECT ${column} AS value FROM ${table} LIMIT 5`, []);
      for (const row of rows) harvest.push([table, String(row.value)]);
    }
    expect(harvest.length).toBeGreaterThan(5);

    const mallory = await register(server, "idormallory");
    await publishDevice(mallory);
    const blobsBefore = await server.db.all("SELECT id FROM attachments ORDER BY id", []);
    const leaked: string[] = [];
    for (const route of server.app.routeInventory) {
      if (!route.url.includes(":id") || isOpen(route.url) || WORKER.test(route.url)) continue;
      for (const [table, identifier] of harvest) {
        const response = await mallory.request(route.method, route.url.replace(":id", identifier), {
          status: "accepted",
          ciphertext: "Zm9vYmFy",
          rating: 5,
          body: "A review written by somebody who never bought it.",
          decision: "approved",
          reason: "spam",
        });
        // 401/403/404 are refusals; 400 and 409 mean the request never became an action.
        // A 200 means a stranger reached an object by knowing its id, which is point 163.
        if (response.status === 200 && CAPABILITY_BY_ID.has(route.url)) {
          // The blind-blob route: allowed to answer, not allowed to have done anything.
          expect(response.body).toEqual({ deleted: 0 });
        } else if (response.status === 200) {
          leaked.push(`${route.method} ${route.url} with ${table}.${identifier}`);
        }
        if (response.status >= 500) leaked.push(`${route.method} ${route.url} -> ${response.status}`);
      }
    }
    expect(leaked).toEqual([]);
    // And nothing was destroyed on the way past.
    expect(await server.db.all("SELECT id FROM attachments ORDER BY id", [])).toEqual(blobsBefore);
  }, 240_000);
});

describe("mass assignment: a privileged field in a body changes nothing (point 164)", () => {
  /** Every name a client might hope the server assigns straight from the body. */
  const PRIVILEGED = {
    role: "admin",
    isAdmin: true,
    admin: true,
    permissions: ["admin"],
    status: "active",
    sellerStatus: "approved",
    seller_status: "approved",
    verified: true,
    isVerified: true,
    ownerId: "somebody-else",
    owner_id: "somebody-else",
    userId: "somebody-else",
    user_id: "somebody-else",
    sellerId: "somebody-else",
    balancePico: 999_999_999,
    balance_pico: 999_999_999,
    availablePico: 999_999_999,
    available_pico: 999_999_999,
    heldPico: 0,
    settledPico: 999_999_999,
    penaltyLevels: 0,
    level: 9,
    bondPico: 999_999_999,
    payoutLimitPico: 999_999_999,
    moderationState: "approved",
    createdDay: 1,
    id: "chosen-by-the-client",
  };

  const snapshot = async () => ({
    users: await server.db.all("SELECT id, username, role, status FROM users ORDER BY username", []),
    sellers: await server.db.all("SELECT * FROM sellers ORDER BY user_id", []),
    balances: await server.db.all("SELECT * FROM balances ORDER BY account_id", []),
  });

  it("sweeps every write route with a privileged body and moves no privileged column", async () => {
    const mallory = await register(server, "massassignment");
    const before = await snapshot();
    const writes = server.app.routeInventory.filter((route) => route.method !== "GET");
    expect(writes.length).toBeGreaterThan(30);
    for (const route of writes) {
      const url = concrete(route.url);
      await mallory.request(route.method, url, PRIVILEGED);
      // The same body with a polluted prototype: `{"__proto__": {...}}` from JSON.parse is a
      // real key, and a handler that copies keys would copy it.
      await mallory.request(route.method, url, {
        ...PRIVILEGED,
        ...(JSON.parse('{"__proto__":{"role":"admin"},"constructor":{"role":"admin"}}') as object),
      });
    }
    const after = await snapshot();
    expect(after).toEqual(before);
    // Nothing polluted the prototype of every object in the process, either.
    expect(({} as Record<string, unknown>).role).toBeUndefined();
    // The sweeping account in particular is still an ordinary user with no seller row.
    const swept = await server.db.get<{ role: string; status: string }>(
      "SELECT role, status FROM users WHERE username = ?",
      ["massassignment"],
    );
    expect(swept).toEqual({ role: "user", status: "active" });
  }, 240_000);

  it("refuses a client-chosen id where the server assigns one", async () => {
    const seller = await register(server, "chosenid");
    await approveSeller(server, seller, "Seller who chooses ids");
    const created = await seller.post<{ id: string }>("/api/market/listings", {
      id: "id-chosen-by-the-client",
      title: "A listing with an id it should not get",
      description: "Long enough a description to satisfy the validator on this route, honestly.",
      category: "software",
      kind: "digital_good",
      priceXmr: "0.025",
    });
    // Either the field is refused outright (an upload-style allowlist) or it is ignored — but
    // the row must not carry the client's id.
    if (created.status === 200) expect(created.body.id).not.toBe("id-chosen-by-the-client");
    const row = await server.db.get("SELECT id FROM listings WHERE id = ?", ["id-chosen-by-the-client"]);
    expect(row ?? null).toBeNull();
  }, 60_000);
});

describe("the first administrator is claimed by one statement (finding SEC-2026-002)", () => {
  it("gives the role to exactly one of two registrations racing on an empty deployment", async () => {
    // A deployment of its own, because the claim is once per database.
    const fresh = await startTestServer({ rateLimits: LOOSE, powBits: 0 });
    try {
      const alice = new TestClient(fresh);
      const bob = new TestClient(fresh);
      await Promise.all([alice.get("/"), bob.get("/")]);
      const { authSecretFor } = await import("./helpers.ts");
      const [first, second] = await Promise.all([
        alice.post("/api/auth/register", { username: "racealice", authSecret: authSecretFor("racealice", "one") }),
        bob.post("/api/auth/register", { username: "racebob", authSecret: authSecretFor("racebob", "two") }),
      ]);
      expect([first.status, second.status]).toEqual([200, 200]);
      const admins = await fresh.db.all<{ username: string }>("SELECT username FROM users WHERE role = 'admin'", []);
      expect(admins.length).toBe(1);
      // And the claim row is the reason, so a third registration cannot become one either.
      const claim = await fresh.db.get<{ id: string }>("SELECT id FROM bootstrap_claims", []);
      expect(claim?.id).toBe("admin");
      const carol = new TestClient(fresh);
      await carol.get("/");
      await carol.post("/api/auth/register", { username: "racecarol", authSecret: authSecretFor("racecarol", "three") });
      const stillOne = await fresh.db.all<{ username: string }>("SELECT username FROM users WHERE role = 'admin'", []);
      expect(stillOne.length).toBe(1);
    } finally {
      await fresh.close();
    }
  }, 120_000);

  it("does not spend the claim on a registration that fails", async () => {
    const fresh = await startTestServer({ rateLimits: LOOSE, powBits: 0 });
    try {
      const client = new TestClient(fresh);
      await client.get("/");
      const { authSecretFor } = await import("./helpers.ts");
      // A body that fails validation after the claim would be a claim spent for nothing; a
      // body that fails inside the transaction rolls the claim back with it.
      const refused = await client.post("/api/auth/register", { username: "no", authSecret: "!!!" });
      expect(refused.status).toBe(400);
      const claimed = await fresh.db.get("SELECT id FROM bootstrap_claims", []);
      expect(claimed ?? null).toBeNull();
      const ok = await client.post<{ role: string }>("/api/auth/register", {
        username: "firstproperly",
        authSecret: authSecretFor("firstproperly", "password enough"),
      });
      expect(ok.status).toBe(200);
      expect(ok.body.role).toBe("admin");
    } finally {
      await fresh.close();
    }
  }, 120_000);
});
