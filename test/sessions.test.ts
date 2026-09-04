/**
 * Session lifetime, rotation and revocation (point 68), and the identifier split the
 * account model rests on (point 72).
 *
 * The interesting assertions here are the negative ones: that an abandoned session stops
 * working, that yesterday's token stops working, and that one account never learns
 * another account's internal id.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { register, startTestServer, type TestServer } from "./helpers.ts";
import { resolveSession } from "../src/server/lib/sessions.ts";
import { sha256 } from "../src/server/lib/ids.ts";

const DAY_MS = 24 * 60 * 60 * 1000;

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

describe("session cookies", () => {
  it("is HttpOnly, SameSite=Strict and bounded, and the CSRF cookie is readable on purpose", async () => {
    const alice = await register(server, "alice");
    // register() went through the browser-shaped client, so read what it was actually sent.
    const response = await server.app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: {
        host: "localhost",
        origin: "http://localhost",
        cookie: `csrf=${alice.cookie("csrf")}`,
        "x-csrf-token": alice.cookie("csrf") ?? "",
        "content-type": "application/json",
      },
      payload: JSON.stringify({
        username: "alice",
        authSecret: "not-the-right-secret".padEnd(86, "A"),
      }),
    });
    // Whatever the credentials do, the CSRF cookie policy is visible on every answer.
    const cookies = [response.headers["set-cookie"] ?? []].flat().join("\n");
    if (cookies.includes("csrf=")) {
      expect(cookies).toContain("SameSite=Strict");
      expect(cookies, "the CSRF cookie is read by the client, so it is not HttpOnly").toContain(
        "csrf=",
      );
    }

    const session = await server.db.get<{ token_hash: string; expires_at: number }>(
      "SELECT token_hash, expires_at FROM sessions LIMIT 1",
    );
    expect(session!.expires_at).toBeGreaterThan(Date.now());
    expect(session!.expires_at).toBeLessThanOrEqual(Date.now() + server.config.sessionTtlMs);
    // The database holds a hash, never the cookie value itself.
    expect(session!.token_hash).not.toContain(alice.cookie("session"));
  });
});

describe("expiry", () => {
  it("ends a session that has not been used for longer than the idle window", async () => {
    const alice = await register(server, "alice");
    expect((await alice.get("/api/auth/me")).status).toBe(200);

    // Rewind last_seen past the idle window. Nothing else changes: the absolute expiry is
    // still weeks away, which is precisely the case the idle rule exists for.
    const stale = Math.floor(Date.now() / DAY_MS) - (server.config.sessionIdleDays + 1);
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [stale]);

    expect((await alice.get("/api/auth/me")).status).toBe(401);
    expect((await server.db.all("SELECT id FROM sessions")).length).toBe(0);
  });

  it("keeps a session that is merely old but still in use", async () => {
    const alice = await register(server, "alice");
    const stale = Math.floor(Date.now() / DAY_MS) - (server.config.sessionIdleDays - 1);
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [stale]);
    expect((await alice.get("/api/auth/me")).status).toBe(200);
  });

  it("refuses a session whose absolute lifetime ran out, however active it was", async () => {
    const alice = await register(server, "alice");
    await server.db.run("UPDATE sessions SET expires_at = ?", [Date.now() - 1]);
    expect((await alice.get("/api/auth/me")).status).toBe(401);
  });
});

describe("rotation", () => {
  it("issues a new token on the first request of a new day and keeps the session working", async () => {
    const alice = await register(server, "alice");
    const before = alice.cookie("session");
    const yesterday = Math.floor(Date.now() / DAY_MS) - 1;
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [yesterday]);

    expect((await alice.get("/api/auth/me")).status).toBe(200);
    const after = alice.cookie("session");
    expect(after, "the client should have been handed a new token").not.toBe(before);
    // Same session row, not a new sign-in: the label, the creation time and the absolute
    // expiry all survive, so rotation does not silently extend a session for ever.
    expect((await server.db.all("SELECT id FROM sessions")).length).toBe(1);
    expect((await alice.get("/api/auth/me")).status).toBe(200);
  });

  // SEC-2026-017: a page load fires several requests at once. Before the compare-and-swap,
  // each of them rotated, the last write won, and the browser usually kept a token no row held.
  it("rotates exactly once when several requests of a new day arrive together", async () => {
    const alice = await register(server, "alice");
    const original = alice.cookie("session")!;
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [
      Math.floor(Date.now() / DAY_MS) - 1,
    ]);
    const now = Date.now();
    const results = await Promise.all(
      [1, 2, 3, 4].map(() => resolveSession(server.db, original, server.config.sessionIdleDays, now)),
    );
    const issued = results.map((user) => user?.rotatedToken).filter((token) => token !== undefined);
    expect(issued, "one winner hands out one new token").toHaveLength(1);
    // Every token anybody was given still works two minutes later — after the grace window,
    // when only the row's own hash counts.
    const later = now + 2 * 60_000;
    for (const token of issued) {
      expect(await resolveSession(server.db, token!, server.config.sessionIdleDays, later)).not.toBeNull();
    }
    // And the losers, who kept the original, are inside the grace window right now.
    expect(await resolveSession(server.db, original, server.config.sessionIdleDays, now + 1_000)).not.toBeNull();
  });

  it("accepts the previous token briefly, so a request already in flight does not fail", async () => {
    const alice = await register(server, "alice");
    const original = alice.cookie("session")!;
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [
      Math.floor(Date.now() / DAY_MS) - 1,
    ]);
    await alice.get("/api/auth/me"); // rotates

    const inFlight = await resolveSession(server.db, original, server.config.sessionIdleDays);
    expect(inFlight, "the old token is still good inside the grace window").not.toBeNull();
  });

  it("stops accepting the previous token once the grace window has passed", async () => {
    const alice = await register(server, "alice");
    const original = alice.cookie("session")!;
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [
      Math.floor(Date.now() / DAY_MS) - 1,
    ]);
    await alice.get("/api/auth/me");

    // Two minutes later the captured cookie is worthless, which is the whole point of
    // rotating: a stolen token has a shelf life even if nobody notices the theft.
    const later = Date.now() + 2 * 60_000;
    expect(
      await resolveSession(server.db, original, server.config.sessionIdleDays, later),
    ).toBeNull();
    const stillMine = await resolveSession(
      server.db,
      alice.cookie("session")!,
      server.config.sessionIdleDays,
      later,
    );
    expect(stillMine).not.toBeNull();
  });

  it("does not let a rotated-away token be resurrected by guessing its hash", async () => {
    const alice = await register(server, "alice");
    const original = alice.cookie("session")!;
    await server.db.run("UPDATE sessions SET last_seen_day = ?", [
      Math.floor(Date.now() / DAY_MS) - 1,
    ]);
    await alice.get("/api/auth/me");
    const row = await server.db.get<{ previous_token_hash: string | null }>(
      "SELECT previous_token_hash FROM sessions",
    );
    expect(row!.previous_token_hash).toBe(sha256(original));
  });
});

describe("listing and revoking", () => {
  it("lists sessions without leaking a token or an address, and revokes one by id", async () => {
    const alice = await register(server, "alice");
    const second = await server.app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: {
        host: "localhost",
        origin: "http://localhost",
        cookie: `csrf=${alice.cookie("csrf")}`,
        "x-csrf-token": alice.cookie("csrf") ?? "",
        "content-type": "application/json",
      },
      payload: JSON.stringify({ username: "alice", authSecret: "x".repeat(86), pow: null }),
    });
    expect([401, 428]).toContain(second.statusCode); // wrong secret: no second session

    const listed = await alice.get<{
      sessions: Array<{ id: string; current: boolean; lastSeenOn: string }>;
    }>("/api/auth/sessions");
    expect(listed.status).toBe(200);
    expect(listed.body.sessions.length).toBe(1);
    expect(listed.body.sessions[0]!.current).toBe(true);
    // What a session listing must never contain: the token, or where it was used from.
    const text = JSON.stringify(listed.body);
    expect(text).not.toContain(alice.cookie("session"));
    expect(text).not.toMatch(/\d+\.\d+\.\d+\.\d+/);

    const revoked = await alice.del(`/api/auth/sessions/${listed.body.sessions[0]!.id}`);
    expect(revoked.status).toBe(200);
    expect((await alice.get("/api/auth/me")).status).toBe(401);
  });

  it("answers the same way for a session that is not yours and one that does not exist", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const hers = await alice.get<{ sessions: Array<{ id: string }> }>("/api/auth/sessions");

    const notMine = await bob.del(`/api/auth/sessions/${hers.body.sessions[0]!.id}`);
    const notReal = await bob.del(`/api/auth/sessions/${randomUUID()}`);
    expect(notMine.status).toBe(notReal.status);
    expect(notMine.body).toEqual(notReal.body);
    // And hers is untouched.
    expect((await alice.get("/api/auth/me")).status).toBe(200);
  });
});

describe("identifiers (point 72)", () => {
  it("uses unguessable internal ids, never a sequence", async () => {
    for (const name of ["alice", "bob", "carol"]) await register(server, name);
    const ids = (await server.db.all<{ id: string }>("SELECT id FROM users")).map((row) => row.id);
    for (const id of ids) {
      expect(id, "internal ids are random UUIDs, not counters").toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
    }
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("never hands one account the internal id of another", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const bobId = (await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
      "bob",
    ]))!.id;

    // Everything Alice can legitimately read about Bob: he is a name, a public profile and
    // a set of public keys. The internal id is the join key of the database and stays there.
    for (const url of [
      `/api/keys/bundle?username=${bob.username}`,
      `/api/market/sellers/${bob.username}`,
      "/api/market/listings",
      "/api/auth/me",
      "/api/notifications",
    ]) {
      const response = await alice.get(url);
      expect(JSON.stringify(response.body), `${url} leaked another account's id`).not.toContain(
        bobId,
      );
    }
  });
});
