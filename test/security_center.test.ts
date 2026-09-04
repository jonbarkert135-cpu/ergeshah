/**
 * The security centre: the account's own history, and what a credential rotation actually
 * revokes.
 *
 * Two properties are worth more than the feature itself. First, the history is a *count per
 * day per kind* and nothing else — no address, no user agent, no time of day, no
 * counterparty — so it cannot become the activity log this project exists not to keep.
 * Second, a recovery or a password change invalidates every credential minted under the old
 * one: sessions, pending challenges and parked device-link codes (ADR-0089, ADR-0090).
 */
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  authSecretFor,
  FAST_KDF,
  register,
  startTestServer,
  TestClient,
  type TestServer,
} from "./helpers.ts";
import { listColumns } from "./database.ts";
import { deriveRecoveryKeys, signWithRecoveryKey } from "../src/shared/crypto/vault.ts";
import { generatePhrase } from "../src/shared/crypto/mnemonic.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import { toBase64Url, utf8 } from "../src/shared/encoding.ts";

const PASSWORD = "correct horse battery staple";
const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;

beforeEach(async () => {
  await sodiumReady();
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

interface Events {
  retentionDays: number;
  events: Array<{ kind: string; on: string; count: number }>;
}

describe("the account's own security history", () => {
  it("records the events a person could recognise as not theirs", async () => {
    const client = await register(server, "alice");

    const stranger = new TestClient(server);
    await stranger.get("/");
    expect((await stranger.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", "not the password"),
    })).status).toBe(401);
    expect((await stranger.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    })).status).toBe(200);

    const history = await client.get<Events>("/api/auth/security-events");
    expect(history.status).toBe(200);
    const kinds = Object.fromEntries(history.body.events.map((row) => [row.kind, row.count]));
    expect(kinds["login.failed"]).toBe(1);
    expect(kinds["login.password"]).toBe(1);
    expect(history.body.retentionDays).toBe(server.config.securityEventRetentionDays);
    // A day, not a moment: yyyy-mm-dd and nothing finer.
    for (const row of history.body.events) expect(row.on).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("counts repeats within a day instead of building a timeline", async () => {
    const client = await register(server, "alice");
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const stranger = new TestClient(server);
      await stranger.get("/");
      await stranger.post("/api/auth/login", {
        username: "alice",
        authSecret: authSecretFor("alice", "wrong password entirely"),
      });
    }
    const history = await client.get<Events>("/api/auth/security-events");
    const failed = history.body.events.filter((row) => row.kind === "login.failed");
    expect(failed.length).toBe(1);
    expect(failed[0]!.count).toBe(3);

    // One row per kind per day, whatever an attacker does: the log that tells on a flood
    // cannot itself be the flood.
    const rows = await server.db.all("SELECT * FROM security_events");
    expect(rows.length).toBeLessThanOrEqual(3);
  });

  it("keeps nothing that could locate a person, and belongs to one account only", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    await alice.post("/api/auth/logout-everywhere");

    const columns = (await listColumns(server.db, "security_events")).sort();
    expect(columns).toEqual(["count", "day", "kind", "user_id"]);

    // Nothing readable by anybody but the owner: there is no staff route over this table.
    expect(read("src/server/routes/moderation.ts")).not.toContain("security_events");
    expect(read("src/server/routes/moderation.ts")).not.toContain("security_event");
    expect((await bob.get<Events>("/api/auth/security-events")).body.events).toEqual([]);

    // A failed sign-in against a name nobody registered records nothing at all — otherwise
    // the table would slowly become a list of usernames strangers have guessed.
    const stranger = new TestClient(server);
    await stranger.get("/");
    await stranger.post("/api/auth/login", {
      username: "nobody-here",
      authSecret: authSecretFor("nobody-here", PASSWORD),
    });
    expect((await server.db.all("SELECT * FROM security_events")).length).toBe(1);
  });
});

describe("what a credential rotation revokes", () => {
  it("takes the sessions, the pending challenges and the parked device codes with it", async () => {
    const phrase = generatePhrase(24);
    const recovery = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    const client = new TestClient(server);
    await client.get("/");
    expect((await client.post("/api/auth/register", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
      recoveryPublicKey: toBase64Url(recovery.signPublicKey),
    })).status).toBe(200);

    // A device-link code parked for the next browser, and a PGP enrolment challenge
    // waiting for a signature: both are credentials the old password minted.
    expect((await client.post("/api/auth/link", {
      linkHash: toBase64Url(Buffer.alloc(32, 7)),
      label: "laptop",
    })).status).toBe(200);
    expect((await client.post("/api/auth/pgp/challenge", {})).status).toBe(200);
    expect((await server.db.all("SELECT * FROM device_links")).length).toBe(1);
    const pending = await server.db.all<{ kind: string }>("SELECT kind FROM auth_challenges");
    expect(pending.map((row) => row.kind)).toContain("pgp-enroll");

    const rescue = new TestClient(server);
    await rescue.get("/");
    const challenge = await rescue.post<{ challengeId: string; challenge: string }>(
      "/api/auth/recovery/challenge",
      { username: "alice" },
    );
    const completed = await rescue.post("/api/auth/recovery/complete", {
      challengeId: challenge.body.challengeId,
      signature: toBase64Url(
        signWithRecoveryKey(recovery.signPrivateKey, utf8(challenge.body.challenge)),
      ),
      newAuthSecret: authSecretFor("alice", "a brand new long passphrase"),
    });
    expect(completed.status).toBe(200);

    expect((await client.get("/api/auth/me")).status).toBe(401);
    expect((await server.db.all("SELECT * FROM device_links")).length).toBe(0);
    // Only anonymous proof-of-work tickets are left: they belong to nobody and open nothing.
    const left = await server.db.all<{ kind: string }>(
      "SELECT kind FROM auth_challenges WHERE user_id IS NOT NULL",
    );
    expect(left).toEqual([]);
  });

  it("does the same for a password change", async () => {
    const client = await register(server, "alice");
    expect((await client.post("/api/auth/link", {
      linkHash: toBase64Url(Buffer.alloc(32, 9)),
      label: "laptop",
    })).status).toBe(200);

    expect((await client.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("alice", PASSWORD),
      newAuthSecret: authSecretFor("alice", "an entirely different passphrase"),
    })).status).toBe(200);

    expect((await server.db.all("SELECT * FROM device_links")).length).toBe(0);
    const history = await client.get<Events>("/api/auth/security-events");
    expect(history.body.events.some((row) => row.kind === "password.changed")).toBe(true);
  });
});
