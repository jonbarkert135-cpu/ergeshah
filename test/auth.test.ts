import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  authSecretFor,
  register,
  startTestServer,
  TestClient,
  type TestServer,
} from "./helpers.ts";

let server: TestServer;

// A fresh instance per test: rate-limit buckets, "first user becomes admin" and session
// state are all per-instance behaviour, and sharing them would hide bugs in either.
beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

describe("registration and login", () => {
  it("registers with nothing but a username and a derived secret", async () => {
    const client = await register(server, "alice");
    const me = await client.get<{ username: string; role: string }>("/api/auth/me");
    expect(me.body.username).toBe("alice");
    // The first account bootstraps the instance; everyone after is an ordinary user.
    expect(me.body.role).toBe("admin");

    const stored = await server.db.get<Record<string, unknown>>(
      "SELECT * FROM users WHERE username = ?",
      ["alice"],
    );
    expect(Object.keys(stored ?? {})).toEqual([
      "id",
      "username",
      "password_hash",
      "role",
      "status",
      "status_reason",
      "created_day",
    ]);
    // No email, no phone, no address, no IP, and the stored hash is not the client secret.
    expect(String(stored?.password_hash)).toMatch(/^\$argon2id\$/);
    expect(String(stored?.password_hash)).not.toContain(authSecretFor("alice", "correct horse battery staple"));
  });

  it("rejects weak or malformed usernames", async () => {
    const client = new TestClient(server);
    await client.get("/");
    for (const username of ["ab", "-nope", "Пользователь", "a".repeat(40), "user name"]) {
      const response = await client.post("/api/auth/register", {
        username,
        authSecret: authSecretFor("x", "y"),
      });
      expect(response.status).toBe(400);
    }
  });

  it("does not distinguish a wrong password from a missing account", async () => {
    await register(server, "carol");
    const client = new TestClient(server);
    await client.get("/");
    const wrongPassword = await client.post<{ message: string }>("/api/auth/login", {
      username: "carol",
      authSecret: authSecretFor("carol", "not the password"),
    });
    const missingAccount = await client.post<{ message: string }>("/api/auth/login", {
      username: "nobodyhere",
      authSecret: authSecretFor("nobodyhere", "whatever else"),
    });
    expect(wrongPassword.status).toBe(401);
    expect(missingAccount.status).toBe(401);
    expect(wrongPassword.body.message).toBe(missingAccount.body.message);
  });

  it("logs in, lists sessions and revokes them", async () => {
    await register(server, "dave");
    const client = new TestClient(server);
    await client.get("/");
    const login = await client.post("/api/auth/login", {
      username: "dave",
      authSecret: authSecretFor("dave", "correct horse battery staple"),
    });
    expect(login.status).toBe(200);
    expect(client.cookie("session")).toBeTruthy();
    expect(client.cookie("csrf")).toBeTruthy();

    const sessions = await client.get<{ sessions: Array<{ id: string; current: boolean }> }>(
      "/api/auth/sessions",
    );
    expect(sessions.body.sessions.length).toBeGreaterThanOrEqual(1);
    expect(sessions.body.sessions.some((session) => session.current)).toBe(true);

    await client.post("/api/auth/logout");
    const after = await client.get("/api/auth/me");
    expect(after.status).toBe(401);
  });

  it("suspends an account and kills its sessions immediately", async () => {
    const admin = await register(server, "alice2");
    await server.db.run("UPDATE users SET role = 'admin' WHERE username = ?", ["alice2"]);
    const victim = await register(server, "spammer");
    expect((await victim.get("/api/auth/me")).status).toBe(200);

    const suspension = await admin.post("/api/moderation/users/spammer/status", {
      status: "suspended",
      reason: "selling prohibited goods",
    });
    expect(suspension.status).toBe(200);
    expect((await victim.get("/api/auth/me")).status).toBe(401);
  });
});

describe("session and CSRF handling", () => {
  it("rejects state-changing requests without a matching CSRF token", async () => {
    const client = await register(server, "erin");
    const missing = await client.request("POST", "/api/auth/logout", undefined, { csrf: null });
    expect(missing.status).toBe(403);
    const wrong = await client.request("POST", "/api/auth/logout", undefined, { csrf: "not-it" });
    expect(wrong.status).toBe(403);
  });

  it("rejects a cross-origin request even with a stolen token", async () => {
    const client = await register(server, "frank");
    const response = await client.request("POST", "/api/auth/logout", undefined, {
      origin: "https://evil.example",
    });
    expect(response.status).toBe(403);
  });

  it("stores only a hash of the session token", async () => {
    const client = await register(server, "grace");
    const token = client.cookie("session");
    const rows = await server.db.all<{ token_hash: string }>("SELECT token_hash FROM sessions");
    expect(rows.every((row) => row.token_hash !== token)).toBe(true);
  });

  it("rate-limits repeated failed logins", async () => {
    await register(server, "harry");
    const client = new TestClient(server);
    await client.get("/");
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 14; attempt += 1) {
      const response = await client.post("/api/auth/login", {
        username: "harry",
        authSecret: authSecretFor("harry", `guess-${attempt}`),
      });
      statuses.push(response.status);
    }
    expect(statuses).toContain(429);
  });
});

describe("privacy of what is stored", () => {
  it("never writes an address, user agent or referrer to any table", async () => {
    const client = await register(server, "ivan");
    await client.get("/api/auth/me");
    const tables = await server.db.all<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'table'",
    );
    for (const table of tables) {
      const columns = await server.db.all<{ name: string }>(`PRAGMA table_info(${table.name})`);
      for (const column of columns) {
        expect(column.name).not.toMatch(/(^|_)(ip|ip_address|user_agent|referrer|fingerprint)$/);
      }
    }
  });
});
