/**
 * Rate limiting, DoS resilience and what an error is allowed to say.
 *
 * The interesting properties are not "a limit exists" — `auth.test.ts` already shows a
 * login flood getting a 429 — but the three that make limits useful: they are per
 * operation, they are counted against the account rather than the address, and they can be
 * changed by an operator without changing the code.
 */
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import { DEFAULT_LIMITS, consume, resolveLimits } from "../src/server/lib/rate_limit.ts";
import type { Db } from "../src/server/db/index.ts";
import { asString, asUsername } from "../src/server/lib/validate.ts";

let server: TestServer;

beforeAll(async () => {
  server = await startTestServer();
});

afterAll(async () => {
  await server.close();
});

describe("limits are configurable", () => {
  it("keeps the defaults when nothing is set", () => {
    expect(resolveLimits(undefined)).toEqual(DEFAULT_LIMITS);
    expect(resolveLimits("  ")).toEqual(DEFAULT_LIMITS);
  });

  it("overrides one scope and leaves the rest alone", () => {
    const limits = resolveLimits('{"login":{"burst":2,"perMinute":0.1}}');
    expect(limits.login).toEqual({ burst: 2, perMinute: 0.1 });
    expect(limits.search).toEqual(DEFAULT_LIMITS.search);
  });

  it("refuses configuration that would silently do nothing", () => {
    expect(() => resolveLimits("not json")).toThrow(/must be JSON/);
    expect(() => resolveLimits('{"lgoin":{"burst":2,"perMinute":1}}')).toThrow(/unknown scope/);
    expect(() => resolveLimits('{"login":{"burst":0,"perMinute":1}}')).toThrow(/burst/);
    expect(() => resolveLimits('{"login":{"burst":5,"perMinute":0}}')).toThrow(/perMinute/);
    expect(() => resolveLimits("[1,2,3]")).toThrow(/JSON object/);
  });

  it("covers every operation the brief asks for", () => {
    for (const scope of [
      "register",
      "login",
      "recovery",
      "sensitive",
      "message_send",
      "seller_application",
      "listing_write",
      "order_write",
      "review",
      "moderation",
      "search",
      // Asking the server to move money has its own, tight bucket (ADR-0066).
      "wallet_write",
    ]) {
      expect(Object.keys(DEFAULT_LIMITS)).toContain(scope);
    }
  });
});

describe("one exhausted bucket does not disable another", () => {
  it("lets a throttled search still send a message", async () => {
    const tight = await startTestServer({
      rateLimits: {
        ...DEFAULT_LIMITS,
        search: { burst: 2, perMinute: 0.01 },
      },
    });
    try {
      const user = await register(tight, "bucket-probe");

      const searches: number[] = [];
      for (let i = 0; i < 5; i += 1) {
        searches.push((await user.get("/api/market/listings?q=thing")).status);
      }
      expect(searches).toContain(429);

      // A different operation, same account, same instant: unaffected.
      const keys = await user.get("/api/keys/bundle/bucket-probe");
      expect(keys.status).not.toBe(429);
    } finally {
      await tight.close();
    }
  });
});

describe("limits are counted against the account, not only the address", () => {
  it("does not let one greedy account spend everyone else's allowance", async () => {
    // Every request in a test — and every request on an onion service — comes from the
    // same address. If buckets were keyed on the address alone, the second account below
    // would already be throttled by the first one's flood.
    const tight = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, search: { burst: 3, perMinute: 0.01 } },
    });
    try {
      const greedy = await register(tight, "greedy-account");
      const bystander = await register(tight, "quiet-account");

      let throttled = false;
      for (let i = 0; i < 8; i += 1) {
        if ((await greedy.get("/api/market/listings?q=xylophone")).status === 429) throttled = true;
      }
      expect(throttled).toBe(true);

      const forTheBystander = await bystander.get("/api/market/listings?q=xylophone");
      expect(forTheBystander.status).toBe(200);
    } finally {
      await tight.close();
    }
  });

  it("still limits anonymous callers, who have no account to be counted as", async () => {
    const tight = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, search: { burst: 2, perMinute: 0.01 } },
    });
    try {
      const anonymous = new TestClient(tight);
      const statuses: number[] = [];
      for (let i = 0; i < 5; i += 1) {
        statuses.push((await anonymous.get("/api/market/listings")).status);
      }
      expect(statuses).toContain(429);
    } finally {
      await tight.close();
    }
  });
});

describe("expensive things have a bucket, and oversized things are refused", () => {
  it("rate-limits the only query that scans", async () => {
    const route = server.app.routeInventory.find(
      (entry) => entry.url === "/api/market/listings" && entry.method === "GET",
    );
    expect(route).toBeDefined();
    const first = await new TestClient(server).get("/api/market/listings?q=anything");
    expect(first.status).toBe(200);
  });

  it("refuses a body larger than the configured cap without running the handler", async () => {
    const client = await register(server, "oversize-probe");
    const response = await client.post("/api/messages", {
      recipient: "someone",
      envelope: "A".repeat(server.config.maxEnvelopeBytes * 8),
    });
    expect([400, 413]).toContain(response.status);
    if (response.status === 413) {
      expect(JSON.stringify(response.body)).toContain("too_large");
    }
  });
});

describe("errors say enough to debug and nothing to exploit", () => {
  it("returns a reference instead of internals when the server breaks", async () => {
    // A route that throws something that is not an HttpError: the generic 500 path.
    const broken = await startTestServer({}, (app) => {
      app.get("/api/__boom", async () => {
        throw new Error("secret detail: /srv/symvolon/data/symvolon.sqlite, pepper=abc123");
      });
    });
    const client = await register(broken, "boom-probe");
    const response = await client.get<{ error: string; message: string; ref?: string }>(
      "/api/__boom",
    );

    expect(response.status).toBe(500);
    expect(response.body.error).toBe("internal_error");
    expect(response.body.message).toBe("internal error");
    expect(response.body.ref).toMatch(/^[A-Za-z0-9_-]+$/);

    const serialized = JSON.stringify(response.body);
    for (const leak of ["secret detail", "/srv/", "sqlite", "pepper", "Error:", "at Object"]) {
      expect(serialized).not.toContain(leak);
    }
    await broken.close();
  });

  it("does not leak which accounts exist", async () => {
    const client = new TestClient(server);
    await client.get("/");
    const missing = await client.post("/api/auth/login", {
      username: "nobody-here",
      authSecret: "A".repeat(43),
    });
    await register(server, "existing-probe");
    const wrong = await client.post("/api/auth/login", {
      username: "existing-probe",
      authSecret: "B".repeat(43),
    });
    expect(missing.status).toBe(wrong.status);
    expect(JSON.stringify(missing.body)).toBe(JSON.stringify(wrong.body));
  });
});

describe("client data is canonicalised before it is trusted", () => {
  it("normalises to NFC, so a length limit measures one string", () => {
    // "é" written as e + combining acute: two code points in, one out.
    const combined = asString("e\u0301clair", "title", 10);
    expect(combined).toBe("éclair");
    expect(combined.length).toBe(6);
  });

  it("refuses invisible and direction-reversing characters", () => {
    for (const nasty of [
      "Alice\u202E",       // right-to-left override: renders as something else entirely
      "Ali\u200Bce",       // zero-width space: two different names that look identical
      "name\u0000",        // NUL
      "line\u001Fbreak",   // control character
      "\uFEFFname",        // byte-order mark
    ]) {
      expect(() => asString(nasty, "displayName", 40), JSON.stringify(nasty)).toThrow(
        /not allowed/,
      );
    }
  });

  it("folds usernames to one canonical form", () => {
    expect(asUsername("Alice.Smith")).toBe("alice.smith");
    // NFKC: fullwidth characters are not a second way to spell an existing account.
    expect(asUsername("\uFF41\uFF4C\uFF49\uFF43\uFF45")).toBe("alice");
    expect(() => asUsername("alice smith")).toThrow();
    expect(() => asUsername("-alice")).toThrow();
  });
});

/**
 * ADR-0093: the same uploads, charged in bytes.
 *
 * The `attachment` bucket bounds how *often* a blob may be posted; this one bounds how much
 * disk an account may turn into rows, which is what the operator pays for. It is still a
 * rate-limit bucket — an HMAC of the account under a daily pepper — so nothing here links
 * an account to a blob it uploaded.
 */
describe("uploads are charged in bytes, not only in requests", () => {
  it("refuses the upload that would spend more than the account has left, and says when to retry", async () => {
    const tight = await startTestServer({
      // Room for two 4 kB blobs and not a third, refilling slowly enough to observe.
      rateLimits: { ...DEFAULT_LIMITS, upload_bytes: { burst: 12_000, perMinute: 60 } },
    });
    try {
      const user = await register(tight, "byte-budget");
      const blob = Buffer.alloc(4096, 3).toString("base64url");
      const id = () => Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString("base64url");

      expect((await user.post("/api/attachments", { id: id(), ciphertext: blob })).status).toBe(200);
      expect((await user.post("/api/attachments", { id: id(), ciphertext: blob })).status).toBe(200);

      const refused = await user.post<{ error: string; retryAfterSeconds: number }>(
        "/api/attachments",
        { id: id(), ciphertext: blob },
      );
      expect(refused.status).toBe(429);
      expect(refused.body.error).toBe("rate_limited");
      expect(refused.body.retryAfterSeconds).toBeGreaterThan(0);

      // A different account is unaffected, and reads are unaffected for both.
      const bystander = await register(tight, "byte-bystander");
      expect((await bystander.post("/api/attachments", { id: id(), ciphertext: blob })).status).toBe(200);
      expect((await user.get("/api/market/listings")).status).toBe(200);
    } finally {
      await tight.close();
    }
  });

  it("charges an order delivery from the same budget", async () => {
    const tight = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, upload_bytes: { burst: 1_000, perMinute: 1 } },
    });
    try {
      const seller = await register(tight, "byte-seller");
      const refused = await seller.post("/api/attachments", {
        id: Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString("base64url"),
        ciphertext: Buffer.alloc(4096, 1).toString("base64url"),
      });
      expect(refused.status).toBe(429);
      // The delivery route reaches the same bucket: one budget for every byte an account stores.
      expect(readFileSync(new URL("../src/server/routes/deliveries.ts", import.meta.url), "utf8"))
        .toContain('app.limit(request, "upload_bytes", ciphertext.length)');
    } finally {
      await tight.close();
    }
  });
});

/**
 * SEC-2026-011. On PostgreSQL under READ COMMITTED, k requests arriving together each read
 * the same bucket level and each wrote `level - 1`, so a burst cost one token. SQLite hides
 * the race, so this stages its symptom instead: a database whose *reads* of the bucket are
 * always a stale, full snapshot, while writes go to the real table. A limiter that decides
 * from what it read is fooled forever; one that decides in the statement is not.
 */
describe("the limiter spends in one statement (SEC-2026-011)", () => {
  function staleBucketReads(db: Db, burst: number): Db {
    const wrap = (inner: Db): Db => ({
      dialect: inner.dialect,
      all: (sql, params) => inner.all(sql, params),
      get: async <T>(sql: string, params?: unknown[]) =>
        sql.startsWith("SELECT tokens, updated_at FROM rate_limits")
          ? ({ tokens: burst, updated_at: Date.now() } as unknown as T)
          : inner.get<T>(sql, params),
      run: (sql, params) => inner.run(sql, params),
      transaction: (fn) => inner.transaction((tx) => fn(wrap(tx))),
      close: () => inner.close(),
    });
    return wrap(db);
  }

  it("refuses the request after the burst even when every read says the bucket is full", async () => {
    const limits = { ...DEFAULT_LIMITS, sensitive: { burst: 3, perMinute: 1 } };
    const db = staleBucketReads(server.db, 3);
    const now = Date.now();
    for (let i = 0; i < 3; i += 1) {
      await consume(db, "pepper", "sensitive", "user:stale", limits, now);
    }
    await expect(consume(db, "pepper", "sensitive", "user:stale", limits, now)).rejects.toMatchObject({
      statusCode: 429,
    });
    // And the real row says the same thing.
    const row = await server.db.get<{ tokens: number }>(
      "SELECT tokens FROM rate_limits ORDER BY tokens ASC LIMIT 1",
    );
    expect(Number(row!.tokens)).toBe(0);
  });
});

/**
 * SEC-2026-019. Sixteen routes — logout, the session list, the vault download, envelope
 * acknowledgement, device revocation, the bond claim, the role change, the three payout-worker
 * routes — charged no bucket, while `docs/API.md` said which bucket each of them used. The
 * convention is now asserted over the route table, with the exceptions written down here.
 */
describe("every route charges a bucket (SEC-2026-019)", () => {
  /** Routes that are not metered, and why. */
  const UNMETERED: Record<string, string> = {
    "GET /": "the application shell: a static file, served by a content-addressed route",
    "GET /healthz": "two words for the container health check; it reads nothing",
  };

  it("has an app.limit call in the handler of every route not listed as unmetered", () => {
    const missing: string[] = [];
    for (const path of readdirSync(new URL("../src/server/routes/", import.meta.url))) {
      const source = readFileSync(new URL(`../src/server/routes/${path}`, import.meta.url), "utf8");
      const parts = source.split(/app\.(get|post|put|delete|patch)\(\s*"([^"]+)"/);
      // [preamble, method, url, body, method, url, body, ...]
      for (let index = 1; index < parts.length; index += 3) {
        const route = `${parts[index]!.toUpperCase()} ${parts[index + 1]}`;
        const body = parts[index + 2] ?? "";
        if (route in UNMETERED) continue;
        if (!body.includes("app.limit(")) missing.push(`${path}: ${route}`);
      }
    }
    expect(missing, "routes with no rate-limit bucket").toEqual([]);
  });

  it("does charge: the payout worker's routes answer 429 once the bucket is empty", async () => {
    const tight = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, payout_worker: { burst: 2, perMinute: 0.01 } },
    });
    try {
      const attempt = () =>
        tight.app.inject({
          method: "POST",
          url: "/api/payouts/claim",
          headers: { authorization: "Bearer wrong-token-wrong-token-wrong-token-x", cookie: "csrf=x", "x-csrf-token": "x" },
        });
      expect((await attempt()).statusCode).toBe(401);
      expect((await attempt()).statusCode).toBe(401);
      expect((await attempt()).statusCode).toBe(429);
    } finally {
      await tight.close();
    }
  });
});
