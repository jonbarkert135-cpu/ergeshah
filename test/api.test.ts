/**
 * Points 87, 88 and 89: the shape of the interface rather than what it does.
 *
 * An API is versioned, typed, validated, authenticated, authorised, rate-limited and
 * documented — the middle four are asserted all over this suite, so what is left here is
 * the version, the documentation of every error code, and the promise that an error tells
 * a client what to do without telling it what the database looks like. The WebSocket
 * section is the honest answer to point 87: there is no socket, and this test is what keeps
 * that true.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import { API_VERSION } from "../src/server/app.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { listTables } from "./database.ts";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (path: string) => readFileSync(`${root}${path}`, "utf8");

let server: TestServer;

beforeAll(async () => {
  server = await startTestServer();
  // The first account of an instance is its administrator (routes/auth.ts); the probes
  // below have to be ordinary users, so somebody else takes that role first.
  await register(server, "api-root");
});

afterAll(async () => {
  await server.close();
});

describe(`the API says which one it is (point 88)`, () => {
  it("answers the same endpoint through the versioned path", async () => {
    const client = new TestClient(server);
    const plain = await client.get<{ listings: unknown[] }>("/api/market/listings");
    const versioned = await client.get<{ listings: unknown[] }>(
      `/api/v${API_VERSION}/market/listings`,
    );
    expect(plain.status).toBe(200);
    expect(versioned.status).toBe(200);
    expect(versioned.body).toEqual(plain.body);
  });

  it("keeps the query string when it strips the prefix", async () => {
    const response = await new TestClient(server).get(
      `/api/v${API_VERSION}/market/listings?limit=1`,
    );
    expect(response.status).toBe(200);
  });

  it("refuses a version that does not exist rather than guessing", async () => {
    const response = await new TestClient(server).get("/api/v2/market/listings");
    expect(response.status).toBe(404);
  });

  it("states the version in every API response", async () => {
    const response = await server.app.inject({ method: "GET", url: "/api/market/listings" });
    expect(response.headers["x-api-version"]).toBe(String(API_VERSION));
    const page = await server.app.inject({ method: "GET", url: "/" });
    // Not on the HTML, which is not the API.
    expect(page.headers["x-api-version"]).toBeUndefined();
  });

  it("documents the policy", () => {
    const doc = read("docs/API.md");
    expect(doc).toContain("## Versioning");
    expect(doc).toContain(`/api/v${API_VERSION}/`);
  });
});

/**
 * Every code this server can answer with, taken from the source rather than from memory:
 * the argument of the error helpers, `new HttpError`, and the literals the error handler
 * writes itself.
 */
function errorCodesInSource(): Set<string> {
  const files: string[] = [];
  (function walk(directory: string) {
    for (const entry of readdirSync(directory)) {
      const path = `${directory}/${entry}`;
      if (statSync(path).isDirectory()) walk(path);
      else if (path.endsWith(".ts")) files.push(path);
    }
  })(`${root}src/server`);

  const shaped = /^[a-z][a-z0-9_]*$/;
  const codes = new Set<string>();
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(
      /\b(?:badRequest|conflict|tooManyRequests|notFound|forbidden|unauthorized)\(/g,
    )) {
      // Scan to the matching parenthesis, then take the last identifier-shaped literal in
      // the arguments: the helpers put the code last, and a message always has spaces.
      const start = (match.index ?? 0) + match[0].length - 1;
      let depth = 0;
      let args = "";
      for (let i = start; i < source.length; i += 1) {
        if (source[i] === "(") depth += 1;
        else if (source[i] === ")") {
          depth -= 1;
          if (depth === 0) {
            args = source.slice(start, i);
            break;
          }
        }
      }
      const literals = [...args.matchAll(/"([^"\\]*)"/g)]
        .map((literal) => literal[1] as string)
        .filter((literal) => shaped.test(literal));
      const code = literals.at(-1);
      if (code) codes.add(code);
    }
    for (const match of source.matchAll(/new HttpError\(\s*\d+,\s*"([a-z_]+)"/g)) {
      codes.add(match[1] as string);
    }
    for (const match of source.matchAll(
      /\berror:\s*(?:[^,;]*\?\s*)?"([a-z_]+)"(?:\s*:\s*"([a-z_]+)")?/g,
    )) {
      codes.add(match[1] as string);
      if (match[2]) codes.add(match[2]);
    }
    for (const match of source.matchAll(/\bcode = "([a-z_]+)"/g)) codes.add(match[1] as string);
  }
  return codes;
}

function documentedCodes(): Set<string> {
  const doc = read("docs/API.md");
  const table = doc.slice(doc.indexOf("## Error codes"));
  const codes = new Set<string>();
  for (const row of table.matchAll(/^\|([^|]+)\|/gm)) {
    // One row may list the family that shares a status and a meaning; each code counts.
    for (const code of (row[1] as string).matchAll(/`([a-z][a-z0-9_]*)`/g)) {
      codes.add(code[1] as string);
    }
  }
  return codes;
}

describe("errors are documented, consistent and machine-readable (point 89)", () => {
  it("documents every code the server can answer with", () => {
    const undocumented = [...errorCodesInSource()]
      .filter((code) => !documentedCodes().has(code))
      .sort();
    expect(undocumented, "add these to the error table in docs/API.md").toEqual([]);
  });

  it("documents no code that no longer exists", () => {
    const live = errorCodesInSource();
    const stale = [...documentedCodes()].filter((code) => !live.has(code)).sort();
    expect(stale, "remove these from docs/API.md").toEqual([]);
  });

  it("answers every failure with the same envelope", async () => {
    const client = await register(server, "envelope-probe");
    const failures = [
      await new TestClient(server).get("/api/notifications"),
      await client.get("/api/market/listings/does-not-exist"),
      await client.post("/api/market/listings", { title: "" }),
      await client.get("/api/moderation/queue"),
      await client.get("/api/nothing-here"),
    ];
    for (const failure of failures) {
      const body = failure.body as { error?: unknown; message?: unknown };
      expect(failure.status, JSON.stringify(body)).toBeGreaterThanOrEqual(400);
      expect(typeof body.error, JSON.stringify(body)).toBe("string");
      expect(typeof body.message, JSON.stringify(body)).toBe("string");
      expect(String(body.error)).toMatch(/^[a-z][a-z0-9_]*$/);
    }
  });

  it("says when to come back instead of leaving a client to guess", async () => {
    const tight = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, search: { burst: 1, perMinute: 0.5 } },
    });
    try {
      const client = new TestClient(tight);
      let throttled: { status: number; body: Record<string, unknown> } | undefined;
      for (let i = 0; i < 4 && !throttled; i += 1) {
        const response = await client.get<Record<string, unknown>>("/api/market/listings");
        if (response.status === 429) throttled = response;
      }
      expect(throttled?.body.error).toBe("rate_limited");
      expect(throttled?.body.retryAfterSeconds).toBeGreaterThan(0);

      // And in the header, for anything that is not this client.
      const raw = await tight.app.inject({ method: "GET", url: "/api/market/listings" });
      expect(raw.statusCode).toBe(429);
      expect(Number(raw.headers["retry-after"])).toBeGreaterThan(0);
    } finally {
      await tight.close();
    }
  });

  it("never describes the database in an error", async () => {
    const client = await register(server, "leak-probe");
    const tables = await listTables(server.db);
    expect(tables.length).toBeGreaterThan(10);

    const responses = [
      await client.post("/api/market/orders", { listingId: "nope" }),
      await client.post("/api/market/listings", { title: "x".repeat(500) }),
      await client.post("/api/messages", { recipient: "nobody", envelope: "!!!" }),
      await client.post("/api/moderation/reports", { subjectType: "listing" }),
      await client.get("/api/keys/bundle/nobody-at-all"),
    ];
    for (const response of responses) {
      const serialized = JSON.stringify(response.body).toLowerCase();
      for (const table of tables) {
        expect(serialized, `${table} named in ${serialized}`).not.toContain(table);
      }
      for (const internal of ["select ", "insert ", "constraint", "sqlite", "postgres", "/srv/"]) {
        expect(serialized, internal).not.toContain(internal);
      }
    }
  });
});

describe("the transport this API does not have (point 87)", () => {
  it("opens no WebSocket, on either side", () => {
    const files: string[] = [];
    (function walk(directory: string) {
      for (const entry of readdirSync(directory)) {
        const path = `${directory}/${entry}`;
        if (statSync(path).isDirectory()) walk(path);
        else if (path.endsWith(".ts")) files.push(path);
      }
    })(`${root}src`);

    const socket = /\bnew WebSocket\b|\bwss?:\/\/|socket\.io|@fastify\/websocket|\bfrom "ws"/;
    const offenders = files.filter((file) => socket.test(readFileSync(file, "utf8")));
    expect(
      offenders.map((file) => file.slice(root.length)),
      "a socket needs the checklist in docs/NETWORK.md before it needs code",
    ).toEqual([]);
  });

  it("has no socket dependency to reach for", () => {
    const manifest = JSON.parse(read("package.json")) as {
      dependencies: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    const names = [...Object.keys(manifest.dependencies), ...Object.keys(manifest.devDependencies)];
    for (const name of names) expect(name).not.toMatch(/^(ws|socket\.io|@fastify\/websocket)$/);
  });

  it("does not let the page open one either", async () => {
    const response = await server.app.inject({ method: "GET", url: "/" });
    const csp = String(response.headers["content-security-policy"]);
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toContain("ws:");
    expect(csp).not.toContain("wss:");
  });

  it("writes down what a socket would have to do, for the day someone wants one", () => {
    const doc = read("docs/NETWORK.md");
    const section = doc.slice(doc.indexOf("## WebSockets"));
    expect(section.length).toBeGreaterThan(200);
    for (const requirement of [
      "authentication",
      "authorisation",
      "origin",
      "rate",
      "connection",
      "heartbeat",
      "timeout",
      "message size",
      "reconnect",
    ]) {
      expect(section.toLowerCase(), requirement).toContain(requirement);
    }
  });
});
