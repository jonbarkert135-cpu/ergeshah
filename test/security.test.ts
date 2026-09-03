/**
 * Point 53: one file per attack class, run against the real server.
 *
 * The classes the brief names are covered across this repository — authentication in
 * `auth.test.ts`, the route table in `authorization.test.ts`, buckets in `limits.test.ts`,
 * the protocol in `protocol.test.ts`, concurrency in `integrity.test.ts`. This file is the
 * adversarial layer on top of those: the attacks that cross two of them, the sweeps that
 * cannot be written by hand for one route at a time, and the regressions found by the
 * review passes in `docs/SECURITY_REVIEW.md`. The map from class to file is in
 * `docs/TESTING.md`; each `describe` below names its class so the two can be compared.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  approveSeller,
  authSecretFor,
  promote,
  publishDevice,
  register,
  startTestServer,
  TestClient,
  type TestServer,
} from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { createDeviceIdentity, signSignedPreKey } from "../src/shared/crypto/identity.ts";
import { openSession } from "../src/shared/crypto/session.ts";
import { fromBase64Url, toBase64Url } from "../src/shared/encoding.ts";
import { listColumns, listTables } from "./database.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer({
    // These suites register a lot of accounts; the bucket under test is named per test.
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

/* ------------------------------- authentication ------------------------------- */

describe("authentication", () => {
  it("refuses a forged, truncated or edited session token", async () => {
    const alice = await register(server, "alice");
    const real = alice.cookie("session")!;
    const anonymous = new TestClient(server);
    for (const token of [
      "not-a-token",
      real.slice(0, -1),
      `${real}x`,
      Buffer.from(real, "base64url").toString("hex"),
    ]) {
      const response = await server.app.inject({
        method: "GET",
        url: "/api/auth/me",
        headers: { cookie: `session=${token}` },
      });
      expect(response.statusCode, token.slice(0, 8)).toBe(401);
    }
    expect((await anonymous.get("/api/auth/me")).status).toBe(401);
  });

  it("stops accepting a session the moment its row expires", async () => {
    const alice = await register(server, "alice");
    expect((await alice.get("/api/auth/me")).status).toBe(200);
    await server.db.run("UPDATE sessions SET expires_at = ? WHERE 1 = 1", [Date.now() - 1]);
    expect((await alice.get("/api/auth/me")).status).toBe(401);
    // And the expired row is not left behind to be resurrected by a clock change.
    expect(await server.db.all("SELECT id FROM sessions")).toEqual([]);
  });

  it("does not let a deleted account's cookie survive its account", async () => {
    const alice = await register(server, "alice");
    await alice.post("/api/auth/delete", { authSecret: authSecretFor("alice", "correct horse battery staple") });
    expect((await alice.get("/api/auth/me")).status).toBe(401);
  });
});

/* -------------------------------- authorization -------------------------------- */

describe("authorization", () => {
  it("re-reads the role on every request, so a demotion takes effect immediately", async () => {
    const mod = await register(server, "mod");
    await promote(server, "mod", "moderator");
    expect((await mod.get("/api/moderation/queue")).status).toBe(200);
    await server.db.run("UPDATE users SET role = 'user' WHERE username = 'mod'");
    // No session invalidation is needed: the role is not carried in the cookie.
    expect((await mod.get("/api/moderation/queue")).status).toBe(403);
  });

  it("refuses a moderator on the admin-only role route and records the refusal", async () => {
    const mod = await register(server, "mod");
    await promote(server, "mod", "moderator");
    const victim = await register(server, "victim");
    const response = await mod.post(`/api/admin/users/${victim.username}/role`, {
      role: "admin",
    });
    expect(response.status).toBe(403);
    const row = await server.db.get<{ action: string; result: string }>(
      "SELECT action, result FROM audit_log ORDER BY created_at DESC LIMIT 1",
    );
    expect(row?.action).toBe("privileged.denied");
    expect(row?.result).toBe("denied");
    const stillUser = await server.db.get<{ role: string }>(
      "SELECT role FROM users WHERE username = ?",
      [victim.username],
    );
    expect(stillUser?.role).toBe("user");
  });
});

/* ------------------------------------ E2EE ------------------------------------ */

describe("end-to-end encryption", () => {
  it("refuses a session when the directory hands out a prekey the identity did not sign", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    await publishDevice(bob);

    // A hostile operator swaps the signed prekey for one of their own. They cannot sign it
    // with Bob's identity key, so the substitution is what the client must catch.
    const attacker = createDeviceIdentity(1);
    await server.db.run("UPDATE devices SET signed_prekey = ?, signed_prekey_signature = ?", [
      toBase64Url(attacker.signedPreKey.keyPair.publicKey),
      toBase64Url(signSignedPreKey(attacker.identity, attacker.signedPreKey)),
    ]);

    const { body } = await alice.get<{
      bundles: Array<{
        identityKey: string;
        signedPreKeyId: number;
        signedPreKey: string;
        signedPreKeySignature: string;
      }>;
    }>(`/api/keys/bundle/${bob.username}`);
    const bundle = body.bundles[0]!;
    expect(() =>
      openSession(createDeviceIdentity(1).identity, {
        identityKey: fromBase64Url(bundle.identityKey),
        signedPreKeyId: bundle.signedPreKeyId,
        signedPreKey: fromBase64Url(bundle.signedPreKey),
        signedPreKeySignature: fromBase64Url(bundle.signedPreKeySignature),
      }),
    ).toThrow(/signature is invalid/);
  });

  it("keeps no column anywhere that holds a message plaintext", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const bobDevice = await publishDevice(bob);
    const secret = "meet-me-at-the-usual-place";
    await alice.post("/api/messages", {
      to: bob.username,
      channel: toBase64Url(new Uint8Array(16).fill(7)),
      messages: [{ deviceId: bobDevice, payload: Buffer.from(secret).toString("base64url") }],
    });
    // The payload is opaque to the server by construction; what this asserts is that no
    // *other* column copied it, and that nothing recorded who sent it.
    const tables = await listTables(server.db);
    for (const name of tables) {
      // The table name comes from the schema itself, never from a request. audit:allow
      const rows = await server.db.all<Record<string, unknown>>(`SELECT * FROM ${name}`);
      for (const row of rows) {
        for (const [column, value] of Object.entries(row)) {
          if (name === "envelopes" && column === "payload") continue;
          expect(String(value ?? ""), `${name}.${column}`).not.toContain(secret);
        }
      }
    }
    // And no column names a sender: the envelope knows a recipient device and nothing else.
    expect(await listColumns(server.db, "envelopes")).not.toContain("sender_user_id");
  });
});

/* ----------------------------------- replay ----------------------------------- */

describe("replay", () => {
  it("kills a captured cookie when the password it authorised is changed", async () => {
    const alice = await register(server, "alice");
    const stolen = alice.cookie("session")!;
    const thief = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `session=${stolen}` },
    });
    expect(thief.statusCode).toBe(200);

    await alice.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("alice", "correct horse battery staple"),
      newAuthSecret: authSecretFor("alice", "a completely different passphrase"),
    });

    const afterwards = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `session=${stolen}` },
    });
    expect(afterwards.statusCode).toBe(401);
  });

  it("cannot replay a device-link claim, even one second after it worked", async () => {
    const alice = await register(server, "alice");
    const secret = toBase64Url(new Uint8Array(32).fill(3));
    const linkHash = toBase64Url(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", Buffer.from(secret, "base64url")),
      ),
    );
    await alice.post("/api/auth/link", { linkHash });
    const anonymous = new TestClient(server);
    await anonymous.get("/");
    expect((await anonymous.post("/api/auth/link/claim", { linkSecret: secret })).status).toBe(200);
    const replayed = new TestClient(server);
    await replayed.get("/");
    expect((await replayed.post("/api/auth/link/claim", { linkSecret: secret })).status).toBe(401);
  });
});

/* --------------------------------- key rotation --------------------------------- */

describe("key rotation", () => {
  it("hands out the rotated signed prekey and forgets the previous one", async () => {
    const bob = await register(server, "bob");
    const alice = await register(server, "alice");
    const identity = createDeviceIdentity(2);
    const publish = (spk: Uint8Array, keyId: number, signature: Uint8Array) =>
      bob.post("/api/keys/device", {
        identityKey: toBase64Url(identity.identity.publicKey),
        signedPreKeyId: keyId,
        signedPreKey: toBase64Url(spk),
        signedPreKeySignature: toBase64Url(signature),
        oneTimePreKeys: [],
      });
    await publish(
      identity.signedPreKey.keyPair.publicKey,
      identity.signedPreKey.keyId,
      identity.signedPreKeySignature,
    );
    const rotated = createDeviceIdentity(1);
    await publish(
      rotated.signedPreKey.keyPair.publicKey,
      rotated.signedPreKey.keyId,
      signSignedPreKey(identity.identity, rotated.signedPreKey),
    );

    const { body } = await alice.get<{ bundles: Array<{ signedPreKey: string }> }>(
      `/api/keys/bundle/${bob.username}`,
    );
    expect(body.bundles).toHaveLength(1);
    expect(body.bundles[0]!.signedPreKey).toBe(toBase64Url(rotated.signedPreKey.keyPair.publicKey));
  });

  it("never resurrects a revoked device, even for the account that owns it", async () => {
    const bob = await register(server, "bob");
    const identity = createDeviceIdentity(2);
    const body = {
      identityKey: toBase64Url(identity.identity.publicKey),
      signedPreKeyId: identity.signedPreKey.keyId,
      signedPreKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64Url(identity.signedPreKeySignature),
      oneTimePreKeys: [],
    };
    const first = await bob.post<{ deviceId: string }>("/api/keys/device", body);
    await bob.post("/api/keys/revoke", { deviceId: first.body.deviceId });

    // The stolen-device case: whoever holds the identity private key may not undo this.
    const again = await bob.post<{ error: string }>("/api/keys/device", body);
    expect(again.status).toBe(409);
    expect(again.body.error).toBe("device_revoked");
    const row = await server.db.get<{ revoked_at: number | null }>(
      "SELECT revoked_at FROM devices WHERE id = ?",
      [first.body.deviceId],
    );
    expect(row?.revoked_at).not.toBeNull();
  });
});

/* ----------------------------- session invalidation ----------------------------- */

describe("session invalidation", () => {
  it("revokes one session from another without touching the rest", async () => {
    const first = await register(server, "alice");
    const second = new TestClient(server);
    await second.get("/");
    await second.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", "correct horse battery staple"),
    });
    const sessions = await first.get<{ sessions: Array<{ id: string; current: boolean }> }>(
      "/api/auth/sessions",
    );
    const other = sessions.body.sessions.find((session) => !session.current)!;
    expect((await first.del(`/api/auth/sessions/${other.id}`)).status).toBe(200);
    expect((await second.get("/api/auth/me")).status).toBe(401);
    expect((await first.get("/api/auth/me")).status).toBe(200);
  });

  it("cannot revoke a session that belongs to somebody else", async () => {
    const alice = await register(server, "alice");
    const mallory = await register(server, "mallory");
    const sessions = await alice.get<{ sessions: Array<{ id: string }> }>("/api/auth/sessions");
    const target = sessions.body.sessions[0]!.id;
    expect((await mallory.del(`/api/auth/sessions/${target}`)).status).toBe(400);
    expect((await alice.get("/api/auth/me")).status).toBe(200);
  });

  it("ends every session of the account when one of them signs out everywhere", async () => {
    const first = await register(server, "alice");
    const second = new TestClient(server);
    await second.get("/");
    await second.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", "correct horse battery staple"),
    });
    expect((await second.post("/api/auth/logout-everywhere")).status).toBe(200);
    expect((await first.get("/api/auth/me")).status).toBe(401);
    expect(await server.db.all("SELECT id FROM sessions")).toEqual([]);
  });
});

/* ------------------------------------- XSS ------------------------------------- */

describe("cross-site scripting", () => {
  it("stores markup as text and never reflects it into a document", async () => {
    const seller = await register(server, "seller");
    await approveSeller(server, seller, "Sellers of things");
    const payload = "<script>alert(document.cookie)</script>";
    const created = await seller.post<{ id: string }>("/api/market/listings", {
      title: `Audit ${payload}`,
      description: `A description with ${payload} and a javascript:alert(1) link, long enough to pass.`,
      category: "consulting",
      kind: "service",
      priceXmr: "0.01",
    });
    expect(created.status).toBe(200);

    const anonymous = new TestClient(server);
    const listing = await server.app.inject({
      method: "GET",
      url: `/api/market/listings/${created.body.id}`,
    });
    // It comes back as JSON — a string in a data field, never a document the browser parses.
    expect(listing.headers["content-type"]).toMatch(/application\/json/);
    expect(listing.headers["x-content-type-options"]).toBe("nosniff");
    expect(JSON.parse(listing.body).listing.title).toContain(payload);

    // And the HTML shell — the only document this server emits — reflects no input at all.
    const shell = await anonymous.get<string>(`/${payload}?q=${encodeURIComponent(payload)}`);
    expect(String(shell.body)).not.toContain("<script>alert");
  });

  it("sends a policy that forbids inline script on every response, error pages included", async () => {
    for (const url of ["/", "/api/auth/me", "/does-not-exist"]) {
      const response = await server.app.inject({ method: "GET", url });
      const csp = String(response.headers["content-security-policy"]);
      expect(csp, url).toContain("default-src 'self'");
      expect(csp, url).not.toContain("unsafe-inline");
      expect(csp, url).toContain("require-trusted-types-for 'script'");
    }
  });
});

/* ------------------------------------ CSRF ------------------------------------ */

describe("cross-site request forgery", () => {
  it("refuses every state-changing route when the token is missing", async () => {
    const alice = await register(server, "alice");
    const unsafe = server.app.routeInventory.filter(
      (route) => route.method !== "GET" && route.url.startsWith("/api/"),
    );
    expect(unsafe.length).toBeGreaterThan(15);
    const accepted: string[] = [];
    for (const route of unsafe) {
      const url = route.url.replace(/:[a-zA-Z]+/g, "does-not-exist");
      const response = await alice.request(route.method, url, {}, { csrf: null });
      if (response.status !== 403) accepted.push(`${route.method} ${route.url} -> ${response.status}`);
    }
    expect(accepted, "these accepted a request with no CSRF token").toEqual([]);
  });

  it("refuses a token that came from another browser", async () => {
    const alice = await register(server, "alice");
    const other = new TestClient(server);
    await other.get("/");
    const response = await alice.request(
      "POST",
      "/api/auth/logout",
      {},
      { csrf: other.cookie("csrf")! },
    );
    expect(response.status).toBe(403);
  });
});

/* ---------------------------------- injection ---------------------------------- */

describe("injection", () => {
  it("treats SQL in a username, an id and a query as data", async () => {
    const alice = await register(server, "alice");
    const injections = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "admin'--",
      "1; DELETE FROM sessions WHERE 1=1; --",
    ];
    for (const value of injections) {
      const login = await new TestClient(server).post("/api/auth/login", {
        username: value,
        authSecret: "AAAA",
      });
      expect([400, 401, 403]).toContain(login.status);
      const listing = await alice.get(`/api/market/listings/${encodeURIComponent(value)}`);
      expect([400, 404]).toContain(listing.status);
      const search = await alice.get(`/api/market/listings?q=${encodeURIComponent(value)}`);
      expect([200, 400]).toContain(search.status);
    }
    // The tables are still there and still populated: nothing was interpreted as syntax.
    expect((await server.db.all("SELECT id FROM users")).length).toBeGreaterThan(0);
    expect((await server.db.all("SELECT id FROM sessions")).length).toBeGreaterThan(0);
  });

  it("does not let a request body pollute the prototype of every object", async () => {
    await register(server, "root"); // the first account is the administrator by design
    const alice = await register(server, "alice");
    await alice.post("/api/auth/link", {
      linkHash: toBase64Url(new Uint8Array(32).fill(1)),
      __proto__: { role: "admin", polluted: "yes" },
    });
    await alice.post("/api/moderation/reports", {
      target: "user",
      targetId: "someone",
      reason: "spam",
      constructor: { prototype: { polluted: "yes" } },
    });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).role).toBeUndefined();
    const me = await alice.get<{ role: string }>("/api/auth/me");
    expect(me.body.role).toBe("user");
  });

  it("refuses a line break in a single-line field, and keeps prose fields prose", async () => {
    const alice = await register(server, "alice");
    const response = await alice.post<{ error: string }>("/api/auth/link", {
      linkHash: toBase64Url(new Uint8Array(32).fill(2)),
      label: "device\r\nSet-Cookie: session=stolen",
    });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe("invalid_characters");

    // A description is prose and keeps its paragraphs, with CRLF normalised to LF.
    const seller = await register(server, "prose");
    await approveSeller(server, seller, "Writer of descriptions");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "A listing with a real description",
      description: "First paragraph, long enough to pass.\r\n\r\nSecond paragraph.",
      category: "writing",
      kind: "service",
      priceXmr: "0.01",
    });
    expect(listing.status).toBe(200);
    const stored = await server.db.get<{ description: string }>(
      "SELECT description FROM listings WHERE id = ?",
      [listing.body.id],
    );
    expect(stored?.description).toContain("\n\nSecond paragraph.");
    expect(stored?.description).not.toContain("\r");
    const raw = await server.app.inject({
      method: "GET",
      url: "/api/auth/sessions",
      headers: { cookie: `session=${alice.cookie("session")}` },
    });
    expect(String(raw.headers["set-cookie"] ?? "")).not.toContain("stolen");
  });
});

/* ------------------------------------- IDOR ------------------------------------- */

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

describe("race conditions", () => {
  it("gives one of five simultaneous registrations of the same name the account", async () => {
    const clients = await Promise.all(
      Array.from({ length: 5 }, async () => {
        const client = new TestClient(server);
        await client.get("/");
        return client;
      }),
    );
    const responses = await Promise.all(
      clients.map((client) =>
        client.post("/api/auth/register", {
          username: "contested",
          authSecret: authSecretFor("contested", "correct horse battery staple"),
        }),
      ),
    );
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    const rows = await server.db.all("SELECT id FROM users WHERE username = 'contested'");
    expect(rows).toHaveLength(1);
  });

  it("never hands the same one-time prekey to two callers at once", async () => {
    const bob = await register(server, "bob");
    const identity = createDeviceIdentity(4);
    await bob.post("/api/keys/device", {
      identityKey: toBase64Url(identity.identity.publicKey),
      signedPreKeyId: identity.signedPreKey.keyId,
      signedPreKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64Url(identity.signedPreKeySignature),
      oneTimePreKeys: identity.oneTimePreKeys.map((key) => ({
        keyId: key.keyId,
        publicKey: toBase64Url(key.keyPair.publicKey),
      })),
    });
    const callers = await Promise.all(
      Array.from({ length: 4 }, (_, index) => register(server, `caller${index}`)),
    );
    const bundles = await Promise.all(
      callers.map((caller) =>
        caller.get<{ bundles: Array<{ oneTimePreKeyId: number | null }> }>(
          `/api/keys/bundle/${bob.username}`,
        ),
      ),
    );
    // Every one of them answered: concurrent requests on one SQLite handle used to nest
    // their transactions and answer 500 (`docs/SECURITY_REVIEW.md`, PASS 4).
    expect(bundles.map((response) => response.status)).toEqual([200, 200, 200, 200]);
    const claimed = bundles
      .map((response) => response.body.bundles[0]!.oneTimePreKeyId)
      .filter((id): id is number => id !== null);
    expect(claimed.length).toBeGreaterThan(0);
    expect(new Set(claimed).size).toBe(claimed.length);
  });
});

/* ---------------------------------- rate limits ---------------------------------- */

describe("rate limits", () => {
  it("stops one account draining another account's one-time prekeys", async () => {
    const bob = await register(server, "bob");
    const identity = createDeviceIdentity(60);
    await bob.post("/api/keys/device", {
      identityKey: toBase64Url(identity.identity.publicKey),
      signedPreKeyId: identity.signedPreKey.keyId,
      signedPreKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64Url(identity.signedPreKeySignature),
      oneTimePreKeys: identity.oneTimePreKeys.map((key) => ({
        keyId: key.keyId,
        publicKey: toBase64Url(key.keyPair.publicKey),
      })),
    });
    const mallory = await register(server, "mallory");
    let throttled = 0;
    for (let attempt = 0; attempt < DEFAULT_LIMITS.key_bundle.burst + 5; attempt += 1) {
      const response = await mallory.get(`/api/keys/bundle/${bob.username}`);
      if (response.status === 429) throttled += 1;
    }
    expect(throttled).toBeGreaterThan(0);
    // Some prekeys survive the attempt, so a real conversation still gets one.
    const left = await server.db.all("SELECT id FROM one_time_prekeys");
    expect(left.length).toBeGreaterThan(0);
  });
});

/* ------------------------------ privilege escalation ------------------------------ */

describe("privilege escalation", () => {
  it("ignores a role, a status or an id supplied by the account creating itself", async () => {
    const client = new TestClient(server);
    await client.get("/");
    // The first account of an empty deployment is the administrator by design, so this
    // test needs one to exist already before it asks for privileges.
    await register(server, "root");
    const response = await client.post("/api/auth/register", {
      username: "climber",
      authSecret: authSecretFor("climber", "correct horse battery staple"),
      role: "admin",
      status: "active",
      id: "chosen-by-the-client",
    });
    expect(response.status).toBe(200);
    const row = await server.db.get<{ id: string; role: string }>(
      "SELECT id, role FROM users WHERE username = 'climber'",
    );
    expect(row?.role).toBe("user");
    expect(row?.id).not.toBe("chosen-by-the-client");
  });

  it("does not let a suspended account act, even with a live cookie", async () => {
    const alice = await register(server, "alice");
    await server.db.run("UPDATE users SET status = 'suspended' WHERE username = 'alice'");
    const response = await alice.get("/api/auth/me");
    expect(response.status).toBe(403);
    const write = await alice.post("/api/moderation/reports", {
      target: "user",
      targetId: "someone",
      reason: "spam",
    });
    expect(write.status).toBe(403);
  });

  it("keeps staff out of the one place staff must never reach: a message", async () => {
    const admin = await register(server, "root");
    await promote(server, "root", "admin");
    const bob = await register(server, "bob");
    const bobDevice = await publishDevice(bob);
    const alice = await register(server, "alice");
    await alice.post("/api/messages", {
      to: bob.username,
      channel: toBase64Url(new Uint8Array(16).fill(4)),
      messages: [{ deviceId: bobDevice, payload: "Y2lwaGVydGV4dA" }],
    });
    // An admin session is still just a session: there is no route that reads an envelope
    // it does not own, and the route table is the proof.
    expect((await admin.get(`/api/messages?deviceId=${bobDevice}`)).status).toBe(404);
    const messageRoutes = server.app.routeInventory.filter((route) =>
      route.url.startsWith("/api/moderation"),
    );
    for (const route of messageRoutes) {
      expect(route.url).not.toMatch(/message|envelope|vault/);
    }
  });
});
