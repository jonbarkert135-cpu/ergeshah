/**
 * Point 85: a production system has to be monitorable, and monitoring is where a private
 * service quietly stops being one. The properties worth a test are therefore not "the
 * endpoint returns 200" but: only an administrator can read it, everything in it is a
 * number, and the counters behind it cannot hold anything but numbers either.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { promote, register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import { recordRequest, requestMetrics, resetMetrics } from "../src/server/lib/metrics.ts";

let server: TestServer;
/** The first account of an instance is its administrator (routes/auth.ts). */
let admin: TestClient;
let user: TestClient;
let moderator: TestClient;

beforeAll(async () => {
  server = await startTestServer();
  admin = await register(server, "health-admin");
  user = await register(server, "health-curious");
  moderator = await register(server, "health-mod");
  await promote(server, "health-mod", "moderator");
});

afterAll(async () => {
  await server.close();
});

const ALLOWED_WORDS = new Set(["ok", "degraded", "sqlite", "postgres"]);

/** Every leaf of the health document: a number, a boolean, or one of four fixed words. */
function leaves(value: unknown, path = ""): Array<[string, unknown]> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return Object.entries(value).flatMap(([key, child]) =>
      leaves(child, path ? `${path}.${key}` : key),
    );
  }
  return [[path, value]];
}

describe("health is for the operator, not for the internet", () => {
  it("is refused to anonymous callers and to ordinary accounts", async () => {
    expect((await new TestClient(server).get("/api/admin/health")).status).toBe(401);
    expect((await user.get("/api/admin/health")).status).toBe(403);
  });

  it("is refused to a moderator, whose job does not include the machine", async () => {
    expect((await moderator.get("/api/admin/health")).status).toBe(403);
  });

  it("answers an administrator with uptime, resources, database and traffic", async () => {
    const response = await admin.get<Record<string, unknown>>("/api/admin/health");

    expect(response.status).toBe(200);
    const body = response.body;
    expect(body.status).toBe("ok");
    expect(body.uptimeSeconds).toBeGreaterThanOrEqual(0);

    const paths = leaves(body).map(([path]) => path);
    for (const expected of [
      "uptimeSeconds",
      "process.cpuPercent",
      "process.rssBytes",
      "system.memoryTotalBytes",
      "system.memoryFreeBytes",
      "disk.totalBytes",
      "disk.availableBytes",
      "database.ok",
      "database.latencyMs",
      "requests.total",
      "requests.errorRate",
      "requests.latencyMsP95",
    ]) {
      expect(paths, expected).toContain(expected);
    }
  });

  it("contains nothing but numbers, booleans and fixed words", async () => {
    const response = await admin.get<Record<string, unknown>>("/api/admin/health");
    for (const [path, value] of leaves(response.body)) {
      if (typeof value === "number" || typeof value === "boolean") continue;
      expect(ALLOWED_WORDS, `${path} = ${JSON.stringify(value)}`).toContain(value);
    }
  });

  it("names no user, route, address or content", async () => {
    await admin.get("/api/notifications");
    const response = await admin.get<Record<string, unknown>>("/api/admin/health");
    const serialized = JSON.stringify(response.body);
    for (const leak of ["health-admin", "/api/", "127.0.0.1", "session", "user"]) {
      expect(serialized, leak).not.toContain(leak);
    }
  });
});

describe("the counters behind it", () => {
  it("classifies by status and computes an error rate over server faults only", () => {
    resetMetrics();
    recordRequest(200, 1);
    recordRequest(404, 2);
    recordRequest(500, 3);
    recordRequest(500, 4);
    const metrics = requestMetrics();
    expect(metrics.total).toBe(4);
    expect(metrics.byClass).toEqual({ "2xx": 1, "3xx": 0, "4xx": 1, "5xx": 2 });
    // A 404 is the client being wrong, not the service being broken.
    expect(metrics.errorRate).toBe(0.5);
    expect(metrics.latencyMsMax).toBe(4);
    expect(metrics.latencyMsP95).toBeGreaterThanOrEqual(metrics.latencyMsP50);
  });

  it("keeps a fixed amount of memory no matter how much traffic arrives", () => {
    resetMetrics();
    for (let i = 0; i < 5_000; i += 1) recordRequest(200, i % 50);
    const metrics = requestMetrics();
    expect(metrics.total).toBe(5_000);
    expect(metrics.latencyMsP50).toBeLessThanOrEqual(50);
    expect(metrics.errorRate).toBe(0);
  });

  it("takes a status and a duration, and has nowhere to put anything else", () => {
    // The signature is the privacy control: two numbers in, numbers out. If this ever
    // grows a route, an account or a body, this line stops compiling and the reviewer
    // gets to ask why monitoring needs it.
    expect(recordRequest.length).toBe(2);
    const metrics: Record<string, unknown> = { ...requestMetrics() };
    for (const value of Object.values(metrics)) {
      const kind = typeof value === "object" ? Object.values(value as object) : [value];
      for (const leaf of kind) expect(typeof leaf).toBe("number");
    }
  });
});
