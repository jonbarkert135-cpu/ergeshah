/**
 * Point 86: what stops one visitor from spending the whole VPS.
 *
 * The rate limiter (test/limits.test.ts) counts requests that arrive. These are the ceilings
 * that hold when the request never completes, when the body is enormous, or when a query
 * decides to run forever — the resources a token bucket cannot bill anyone for.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { register, startTestServer, type TestServer } from "./helpers.ts";
import { positiveInteger } from "../src/server/config.ts";
import { poolOptions } from "../src/server/db/postgres.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";

let server: TestServer;

beforeAll(async () => {
  server = await startTestServer();
});

afterAll(async () => {
  await server.close();
});

describe("connections", () => {
  it("caps how many the process will hold at once", () => {
    expect(server.config.maxConnections).toBeGreaterThan(0);
    expect(server.app.server.maxConnections).toBe(server.config.maxConnections);
  });

  it("gives a slow client a deadline", () => {
    // Fastify leaves these unset, which means "wait forever" — one socket per attacker.
    expect(server.app.initialConfig.connectionTimeout).toBeGreaterThan(0);
    expect(server.app.initialConfig.keepAliveTimeout).toBeGreaterThan(0);
    expect(server.app.server.requestTimeout).toBeGreaterThan(0);
  });
});

describe("bodies and messages", () => {
  it("caps the request body below anything a handler would allocate", () => {
    expect(server.app.initialConfig.bodyLimit).toBeGreaterThan(server.config.maxEnvelopeBytes);
    expect(server.app.initialConfig.bodyLimit).toBeLessThan(64 * 1024 * 1024);
  });

  it("refuses an envelope larger than the message cap", async () => {
    const client = await register(server, "resource-probe");
    const response = await client.post("/api/messages", {
      recipient: "resource-probe",
      envelope: "A".repeat(server.config.maxEnvelopeBytes + 1_000),
    });
    expect([400, 413]).toContain(response.status);
  });

  it("meters uploads, which are megabytes with no owner to charge", () => {
    expect(DEFAULT_LIMITS.attachment.perMinute).toBeLessThanOrEqual(10);
    expect(server.config.maxDeliveryBytes).toBeLessThanOrEqual(16 * 1024 * 1024);
  });
});

describe("database query cost", () => {
  it("bounds a statement, an idle transaction and the wait for a connection", () => {
    const options = poolOptions("postgres://example/db", 5_000);
    expect(options.statement_timeout).toBe(5_000);
    expect(options.idle_in_transaction_session_timeout).toBe(5_000);
    expect(options.connectionTimeoutMillis).toBeGreaterThan(0);
    expect(options.max).toBeGreaterThan(0);
  });

  it("refuses a limit that would parse as nothing", () => {
    expect(positiveInteger("MAX_CONNECTIONS", undefined, 512)).toBe(512);
    expect(positiveInteger("MAX_CONNECTIONS", "  ", 512)).toBe(512);
    expect(positiveInteger("MAX_CONNECTIONS", "64", 512)).toBe(64);
    for (const nonsense of ["many", "0", "-1", "1.5"]) {
      expect(() => positiveInteger("MAX_CONNECTIONS", nonsense, 512), nonsense).toThrow(
        /whole number/,
      );
    }
  });
});
