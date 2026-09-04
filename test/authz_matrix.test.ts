/**
 * The authorisation matrix as data (point 132, OPS-11).
 *
 * `docs/AUTHZ_MATRIX.json` says, for every route, who may reach it: `public`, any `account`,
 * `staff`, `admin`, or the payout `worker`. `authorization.test.ts` proves that nothing is
 * *missing* a check; this file proves that nothing has *widened* — that a moderator has not
 * quietly gained an admin action, that an admin-only route has not slipped to staff, that a
 * private route has not become public — and it does so by sending four real callers to every
 * route and comparing what happened with the table, in both directions:
 *
 *   - a caller the row admits must get past the authentication and role gate (any answer
 *     but the gate's own 401 / "insufficient privileges" 403 — the handler may then say 400
 *     or 404, which is its business and `idor.test.ts`'s);
 *   - a caller the row excludes must be stopped *by the gate*, not by a later validation
 *     step, because a 400 for the wrong role means the handler already ran.
 *
 * The table is also kept honest against the route inventory: a new route without a row, or a
 * row without a route, fails here with its name.
 */
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { promote, register, startTestServer, TestClient, type TestServer } from "./helpers.ts";

type Who = "public" | "account" | "staff" | "admin" | "worker";
type Row = { method: string; url: string; who: Who; resource: string; action: string; scope?: string };
type Caller = "anonymous" | "user" | "moderator" | "admin";

const MATRIX = JSON.parse(readFileSync(new URL("../docs/AUTHZ_MATRIX.json", import.meta.url), "utf8")) as {
  who: Record<Who, string>;
  routes: Row[];
};

/** Which session roles each `who` admits past the gate. */
const ADMITS: Record<Who, Caller[]> = {
  public: ["anonymous", "user", "moderator", "admin"],
  account: ["user", "moderator", "admin"],
  staff: ["moderator", "admin"],
  admin: ["admin"],
  worker: [],
};

/** Routes that end the calling session; they are probed with a fresh account each. */
const ENDS_SESSION = new Set(["/api/auth/logout", "/api/auth/logout-everywhere", "/api/auth/delete"]);

const LOOSE = Object.fromEntries(
  Object.keys(DEFAULT_LIMITS).map((name) => [name, { burst: 100_000, perMinute: 100_000 }]),
) as typeof DEFAULT_LIMITS;

const concrete = (url: string) => url.replace(/:[a-zA-Z]+/g, "does-not-exist");
const key = (method: string, url: string) =>
  `${method} ${/^\/assets\/[A-Za-z0-9._-]+$/.test(url) ? "/assets/*" : url}`;

/** True when the answer came from the authentication or role gate rather than the handler. */
function stoppedByGate(status: number, body: unknown): boolean {
  if (status === 401) return true;
  const message = (body as { message?: string } | null)?.message ?? "";
  return status === 403 && message === "insufficient privileges";
}

let server: TestServer;
let sequence = 0;

async function callers(): Promise<Record<Caller, TestClient>> {
  const n = ++sequence;
  const anonymous = new TestClient(server);
  await anonymous.get("/"); // a CSRF cookie, so the only thing standing between it and the route is the session
  const user = await register(server, `mx-user-${n}`);
  const moderator = await register(server, `mx-mod-${n}`);
  await promote(server, moderator.username, "moderator");
  const admin = await register(server, `mx-admin-${n}`);
  await promote(server, admin.username, "admin");
  return { anonymous, user, moderator, admin };
}

beforeAll(async () => {
  server = await startTestServer({ rateLimits: LOOSE, powBits: 0 });
  // The first account of a deployment is its administrator; take that seat so `user` below
  // really is a user.
  await register(server, "mx-first");
}, 120_000);

afterAll(async () => {
  await server.close();
});

describe("docs/AUTHZ_MATRIX.json describes the route table that exists", () => {
  it("has one row for every route, and no row for a route that is gone", () => {
    const live = new Set(server.app.routeInventory.map((route) => key(route.method, route.url)));
    const listed = MATRIX.routes.map((row) => `${row.method} ${row.url}`);

    const duplicates = listed.filter((entry, index) => listed.indexOf(entry) !== index);
    expect(duplicates, "each route is decided once").toEqual([]);

    const missing = [...live].filter((entry) => !listed.includes(entry)).sort();
    expect(missing, "add a row to docs/AUTHZ_MATRIX.json and decide who may call it").toEqual([]);

    const stale = listed.filter((entry) => !live.has(entry)).sort();
    expect(stale, "remove these from docs/AUTHZ_MATRIX.json").toEqual([]);
  });

  it("uses only the vocabulary it defines", () => {
    for (const row of MATRIX.routes) {
      expect(Object.keys(MATRIX.who), `${row.method} ${row.url}`).toContain(row.who);
      expect(row.resource, `${row.method} ${row.url} names a resource`).toMatch(/^[a-z][a-z-]*$/);
      expect(row.action, `${row.method} ${row.url} names an action`).toMatch(/^[a-z][a-z/-]*$/);
    }
  });

  it("the public rows agree with authorization.test.ts's allowlist in spirit: no API write is public except the login steps", () => {
    const publicWrites = MATRIX.routes
      .filter((row) => row.who === "public" && row.method !== "GET")
      .map((row) => row.url);
    for (const url of publicWrites) expect(url, "a public write must be an authentication step").toMatch(/^\/api\/auth\//);
  });
});

describe("every route admits exactly the callers its row says (widening fails, narrowing fails)", () => {
  it("matches for all four callers", async () => {
    const shared = await callers();
    const rows = [...MATRIX.routes].sort(
      (a, b) => Number(ENDS_SESSION.has(a.url)) - Number(ENDS_SESSION.has(b.url)),
    );
    const disagreements: string[] = [];

    for (const row of rows) {
      const url = row.url === "/assets/*" ? assetUrl() : concrete(row.url);
      const clients = ENDS_SESSION.has(row.url) ? await callers() : shared;
      for (const caller of ["anonymous", "user", "moderator", "admin"] as const) {
        const response = await clients[caller].request(row.method, url, {});
        const gated = stoppedByGate(response.status, response.body);
        const admitted = ADMITS[row.who].includes(caller);
        if (admitted && gated) {
          disagreements.push(`${row.method} ${row.url}: the matrix admits ${caller}, the server refused (${response.status})`);
        }
        if (!admitted && !gated) {
          disagreements.push(
            `${row.method} ${row.url}: the matrix excludes ${caller}, the server let the request reach the handler (${response.status}) — widening`,
          );
        }
      }
    }

    expect(disagreements).toEqual([]);
  }, 120_000);

  it("a demotion narrows the matrix on the next request, not the next login", async () => {
    const { admin } = await callers();
    const before = await admin.request("GET", "/api/admin/treasury");
    expect(before.status).toBe(200);
    await server.db.run("UPDATE users SET role = 'moderator' WHERE username = ?", [admin.username]);
    const after = await admin.request("GET", "/api/admin/treasury");
    expect(stoppedByGate(after.status, after.body), "a moderator must not keep an admin's reach").toBe(true);
  });
});

function assetUrl(): string {
  const asset = server.app.routeInventory.find((route) => route.url.startsWith("/assets/"));
  if (!asset) throw new Error("the build has no assets to probe");
  return asset.url;
}
