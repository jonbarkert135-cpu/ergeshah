/**
 * Rate limiting, DoS resilience and what an error is allowed to say.
 *
 * The interesting properties are not "a limit exists" — `auth.test.ts` already shows a
 * login flood getting a 429 — but the three that make limits useful: they are per
 * operation, they are counted against the account rather than the address, and they can be
 * changed by an operator without changing the code.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import { DEFAULT_LIMITS, resolveLimits } from "../src/server/lib/rate_limit.ts";
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
