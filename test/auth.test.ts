import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  authSecretFor,
  FAST_KDF,
  promote,
  publishDevice,
  register,
  startTestServer,
  TestClient,
  type TestServer,
} from "./helpers.ts";
import {
  deriveAccountKeys,
  deriveRecoveryKeys,
  generateMasterKey,
  openVault,
  sealVault,
  unwrapMasterKey,
  wrapMasterKey,
  type VaultBackup,
} from "../src/shared/crypto/vault.ts";
import { fromUtf8, utf8 } from "../src/shared/encoding.ts";
import { listColumns, listTables } from "./database.ts";

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
      "recovery_public_key",
      "pgp_public_key",
      "pgp_fingerprint",
    ]);
    // No email, no phone, no address, no IP, and the stored hash is not the client secret.
    expect(String(stored?.password_hash)).toMatch(/^scrypt\$32768\$8\$1\$/);
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
    const tables = await listTables(server.db);
    // `pgp_fingerprint` is the hash of a public key the user chose to publish — the one
    // kind of fingerprint that is not a way of recognising a browser behind its back.
    for (const table of tables) {
      for (const column of await listColumns(server.db, table)) {
        if (column === "pgp_fingerprint") continue;
        expect(column).not.toMatch(/(^|_)(ip|ip_address|user_agent|referrer|fingerprint)$/);
      }
    }
  });
});

/**
 * What the browser does: a random master key seals the vault, and the master key itself
 * is wrapped under the password (and under the recovery phrase, when there is one).
 */
function backupFor(
  username: string,
  password: string,
  note: string,
  phrase?: string,
): VaultBackup {
  const keys = deriveAccountKeys(username, password, FAST_KDF);
  const masterKey = generateMasterKey();
  const recovery = phrase ? deriveRecoveryKeys(username, phrase, FAST_KDF) : null;
  return {
    v: 3,
    vault: sealVault(masterKey, utf8(JSON.stringify({ note }))),
    password: wrapMasterKey(keys.wrapKey, masterKey),
    recovery: recovery ? wrapMasterKey(recovery.wrapKey, masterKey) : null,
  };
}

/** Open a backup the way a browser would, and return what was inside the vault. */
function openBackup(username: string, password: string, backup: VaultBackup): unknown {
  const keys = deriveAccountKeys(username, password, FAST_KDF);
  const masterKey = unwrapMasterKey(keys.wrapKey, backup.password);
  return JSON.parse(fromUtf8(openVault(masterKey, backup.vault)));
}

describe("changing the password", () => {

  it("moves the auth secret and the sealed vault together, and drops other sessions", async () => {
    const client = await register(server, "alice");
    await client.put("/api/keys/vault", {
      sealedVault: backupFor("alice", "correct horse battery staple", "before"),
    });

    // A second browser, signed in under the old password.
    const other = new TestClient(server);
    await other.get("/");
    const signedIn = await other.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", "correct horse battery staple"),
    });
    expect(signedIn.status).toBe(200);

    const changed = await client.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("alice", "correct horse battery staple"),
      newAuthSecret: authSecretFor("alice", "a much longer passphrase entirely"),
      sealedVault: backupFor("alice", "a much longer passphrase entirely", "after"),
    });
    expect(changed.status).toBe(200);

    // The old password is gone, the new one works.
    const stale = new TestClient(server);
    await stale.get("/");
    expect(
      (
        await stale.post("/api/auth/login", {
          username: "alice",
          authSecret: authSecretFor("alice", "correct horse battery staple"),
        })
      ).status,
    ).toBe(401);
    const relogin = new TestClient(server);
    await relogin.get("/");
    const fresh = await relogin.post<{ sealedVault: VaultBackup }>(
      "/api/auth/login",
      {
        username: "alice",
        authSecret: authSecretFor("alice", "a much longer passphrase entirely"),
      },
    );
    expect(fresh.status).toBe(200);

    // And the stored backup opens under the new password, not the old one.
    expect(openBackup("alice", "a much longer passphrase entirely", fresh.body.sealedVault!)).toEqual({
      note: "after",
    });
    expect(() =>
      openBackup("alice", "correct horse battery staple", fresh.body.sealedVault!),
    ).toThrow();

    // The other browser's session was authorised under the old password: it is gone.
    expect((await other.get("/api/auth/me")).status).toBe(401);
    // The session that made the change still works, with a rotated token.
    expect((await client.get("/api/auth/me")).status).toBe(200);
  });

  it("refuses a wrong current password, and refuses to orphan an existing vault", async () => {
    const client = await register(server, "bob");
    await client.put("/api/keys/vault", {
      sealedVault: backupFor("bob", "correct horse battery staple", "keys"),
    });

    const wrong = await client.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("bob", "not my password"),
      newAuthSecret: authSecretFor("bob", "a much longer passphrase entirely"),
      sealedVault: backupFor("bob", "a much longer passphrase entirely", "keys"),
    });
    expect(wrong.status).toBe(401);

    const noVault = await client.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("bob", "correct horse battery staple"),
      newAuthSecret: authSecretFor("bob", "a much longer passphrase entirely"),
    });
    expect(noVault.status).toBe(400);
    expect((noVault.body as { error: string }).error).toBe("vault_required");

    // Neither failure changed anything.
    expect((await client.get("/api/auth/me")).status).toBe(200);
    const stored = await server.db.get<{ sealed: string }>("SELECT sealed FROM vaults");
    expect(
      openBackup("bob", "correct horse battery staple", JSON.parse(stored!.sealed) as VaultBackup),
    ).toEqual({ note: "keys" });
  });
});

describe("deleting an account", () => {
  it("removes everything belonging to the account and frees the username", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    await publishDevice(bob);
    await alice.put("/api/keys/vault", {
      sealedVault: backupFor("alice", "correct horse battery staple", "keys"),
    });
    const aliceDevice = await publishDevice(alice);
    const sent = await bob.post("/api/messages", {
      to: "alice",
      channel: "Y2hhbm5lbA",
      messages: [{ deviceId: aliceDevice, payload: JSON.stringify({ v: 2, h: "AA", ct: "BB" }) }],
    });
    expect(sent.status).toBe(200);
    expect(await server.db.get("SELECT id FROM envelopes")).toBeTruthy();

    const aliceId = (await server.db.get<{ id: string }>(
      "SELECT id FROM users WHERE username = ?",
      ["alice"],
    ))!.id;
    const deleted = await alice.post("/api/auth/delete", {
      authSecret: authSecretFor("alice", "correct horse battery staple"),
    });
    expect(deleted.status).toBe(200);

    // Nothing that belonged to alice survives anywhere, and bob is untouched.
    for (const [table, column] of [
      ["users", "id"],
      ["vaults", "user_id"],
      ["devices", "user_id"],
      ["sessions", "user_id"],
    ] as const) {
      // audit:allow — table and column come from the literal list above, in a test
      const rows = await server.db.all(`SELECT * FROM ${table} WHERE ${column} = ?`, [aliceId]);
      expect(rows.length, table).toBe(0);
    }
    expect((await server.db.all("SELECT * FROM envelopes")).length).toBe(0);
    expect((await server.db.all("SELECT * FROM users")).length).toBe(1); // bob
    expect((await alice.get("/api/auth/me")).status).toBe(401);

    // The name is available again, and the new account is a different account.
    const impostor = await register(server, "alice");
    const me = await impostor.get<{ username: string; role: string }>("/api/auth/me");
    expect(me.body.username).toBe("alice");
    expect(me.body.role).toBe("user");
  });

  it("keeps moderation history, without the moderator's identity", async () => {
    const applicant = await register(server, "seller1");
    const moderator = await register(server, "mod1");
    await promote(server, "mod1", "moderator");
    const application = await applicant.post<{ id: string }>("/api/market/seller-applications", {
      displayName: "Careful Software",
      statement: "I will sell carefully written software and design work.",
    });
    await moderator.post(
      `/api/moderation/seller-applications/${application.body.id}/decide`,
      { decision: "approved", note: "welcome" },
    );
    expect((await server.db.all("SELECT * FROM audit_log")).length).toBeGreaterThan(0);

    const wrongPassword = await moderator.post("/api/auth/delete", {
      authSecret: authSecretFor("mod1", "wrong password entirely"),
    });
    expect(wrongPassword.status).toBe(401);

    const deleted = await moderator.post("/api/auth/delete", {
      authSecret: authSecretFor("mod1", "correct horse battery staple"),
    });
    expect(deleted.status).toBe(200);

    // The decision and the audit trail survive; the actor is unlinked, not erased.
    const audit = await server.db.all<{ actor_user_id: string | null; action: string }>(
      "SELECT actor_user_id, action FROM audit_log",
    );
    expect(audit.length).toBeGreaterThan(0);
    expect(audit.every((row) => row.actor_user_id === null)).toBe(true);
    const decided = await server.db.get<{ status: string; decided_by: string | null }>(
      "SELECT status, decided_by FROM seller_applications",
    );
    expect(decided?.status).toBe("approved");
    expect(decided?.decided_by).toBeNull();
  });
});
