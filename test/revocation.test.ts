/**
 * Point 131: after a credential rotation, does the old session actually stop working?
 *
 * The mechanisms exist and are tested in pieces — `test/security_center.test.ts` proves a
 * password change and a recovery take the device codes and the pending challenges,
 * `test/security.test.ts` proves "sign out everywhere" empties the table. What no suite asked
 * was the matrix itself, from the point of view of the *other* browser: a second session,
 * opened before the rotation, that must be 401 afterwards.
 *
 * Asking it that way found a hole. Enrolling, rotating or removing the PGP factor, and
 * replacing the recovery key, left every other session alive — so a session minted before a
 * factor changed kept working, which is the case a rotation is performed to end (ADR-0102).
 *
 * The rule the four cases check: a credential rotation ends every *other* session, and the
 * session that performed the rotation survives it unless the rotation was a sign-out.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { generateKey, createMessage, readPrivateKey, sign } from "openpgp";
import {
  authSecretFor,
  FAST_KDF,
  register,
  startTestServer,
  TestClient,
  type TestServer,
} from "./helpers.ts";
import { deriveRecoveryKeys, signWithRecoveryKey } from "../src/shared/crypto/vault.ts";
import { generatePhrase } from "../src/shared/crypto/mnemonic.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import { toBase64Url, utf8 } from "../src/shared/encoding.ts";

const PASSWORD = "correct horse battery staple";

interface Keypair {
  publicKey: string;
  privateKey: string;
}

let first: Keypair;
let second: Keypair;
let server: TestServer;

async function detachedSignature(pair: Keypair, text: string): Promise<string> {
  const key = await readPrivateKey({ armoredKey: pair.privateKey });
  return (await sign({
    message: await createMessage({ text }),
    signingKeys: key,
    detached: true,
    format: "armored",
  })) as string;
}

/** A second browser signed in with the password, exactly as a stolen session would be. */
async function secondSession(username: string): Promise<TestClient> {
  const client = new TestClient(server);
  await client.get("/");
  const login = await client.post("/api/auth/login", {
    username,
    authSecret: authSecretFor(username, PASSWORD),
  });
  expect(login.status, "the second session must exist before it can be revoked").toBe(200);
  expect((await client.get("/api/auth/me")).status).toBe(200);
  return client;
}

/** The same, for an account that now has a second factor: password, then a signature. */
async function secondSessionWithPgp(username: string, pair: Keypair): Promise<TestClient> {
  const client = new TestClient(server);
  await client.get("/");
  const login = await client.post<{ challengeId: string; challenge: string; pgpRequired?: boolean }>(
    "/api/auth/login",
    { username, authSecret: authSecretFor(username, PASSWORD) },
  );
  expect(login.body.pgpRequired).toBe(true);
  expect((await client.post("/api/auth/pgp/complete", {
    challengeId: login.body.challengeId,
    signature: await detachedSignature(pair, login.body.challenge),
  })).status).toBe(200);
  expect((await client.get("/api/auth/me")).status).toBe(200);
  return client;
}

async function challenge(client: TestClient, intent?: "remove") {
  const response = await client.post<{ challengeId: string; challenge: string }>(
    "/api/auth/pgp/challenge",
    intent ? { intent } : {},
  );
  expect(response.status).toBe(200);
  return response.body;
}

beforeAll(async () => {
  await sodiumReady();
  [first, second] = (await Promise.all([
    generateKey({ userIDs: [{ name: "first" }], type: "ecc", format: "armored" }),
    generateKey({ userIDs: [{ name: "second" }], type: "ecc", format: "armored" }),
  ])) as unknown as [Keypair, Keypair];
}, 30_000);

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

describe("a password change", () => {
  it("ends every session, including the one that changed it, and hands that one a new session", async () => {
    const owner = await register(server, "alice");
    const other = await secondSession("alice");

    expect((await owner.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("alice", PASSWORD),
      newAuthSecret: authSecretFor("alice", "an entirely different passphrase"),
    })).status).toBe(200);

    // The other browser is out, and the caller continues on the session it was just issued.
    expect((await other.get("/api/auth/me")).status).toBe(401);
    expect((await owner.get("/api/auth/me")).status).toBe(200);
    const rows = await server.db.all<{ user_id: string }>("SELECT user_id FROM sessions");
    expect(rows.length).toBe(1);
  });
});

describe("a change to the PGP factor (point 131)", () => {
  it("ends the sessions that were signed in without it — enrolment, rotation and removal", async () => {
    const owner = await register(server, "alice");

    // 1. Enrolment. The other session was authenticated by the password alone; after a
    //    second factor exists, that is no longer what signing in to this account means.
    let other = await secondSession("alice");
    const enrolment = await challenge(owner);
    expect((await owner.post("/api/auth/pgp/key", {
      authSecret: authSecretFor("alice", PASSWORD),
      publicKey: first.publicKey,
      challengeId: enrolment.challengeId,
      signature: await detachedSignature(first, enrolment.challenge),
    })).status).toBe(200);
    expect((await other.get("/api/auth/me")).status).toBe(401);
    expect((await owner.get("/api/auth/me")).status).toBe(200);

    // 2. Rotation. A key is replaced because the old one is not trusted any more, so a
    //    session minted while it was is not either.
    // A password-only login cannot mint a session now that a factor exists, so this second
    // browser arrives through the two-step flow — which is what makes it a fair test: the
    // session is as legitimate as a session gets, and the rotation still ends it.
    other = await secondSessionWithPgp("alice", first);
    const rotation = await challenge(owner);
    expect((await owner.post("/api/auth/pgp/key", {
      authSecret: authSecretFor("alice", PASSWORD),
      publicKey: second.publicKey,
      challengeId: rotation.challengeId,
      signature: await detachedSignature(second, rotation.challenge),
      currentSignature: await detachedSignature(first, rotation.challenge),
    })).status).toBe(200);
    expect((await other.get("/api/auth/me")).status).toBe(401);

    // 3. Removal. Taking the factor off is a weakening of the account, and the sessions
    //    signed in under it end with it.
    other = await secondSessionWithPgp("alice", second);
    const removal = await challenge(owner, "remove");
    expect((await owner.post("/api/auth/pgp/remove", {
      authSecret: authSecretFor("alice", PASSWORD),
      challengeId: removal.challengeId,
      signature: await detachedSignature(second, removal.challenge),
    })).status).toBe(200);
    expect((await other.get("/api/auth/me")).status).toBe(401);
    expect((await owner.get("/api/auth/me")).status).toBe(200);
  });
});

describe("a recovery", () => {
  it("ends every session when the phrase is used, and when the recovery key is replaced", async () => {
    const phrase = generatePhrase(24);
    const keys = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    const owner = await register(server, "alice");

    // Replacing the key that can mint a login without the password is a rotation too.
    const other = await secondSession("alice");
    expect((await owner.post("/api/auth/recovery/key", {
      authSecret: authSecretFor("alice", PASSWORD),
      recoveryPublicKey: toBase64Url(keys.signPublicKey),
    })).status).toBe(200);
    expect((await other.get("/api/auth/me")).status).toBe(401);
    expect((await owner.get("/api/auth/me")).status).toBe(200);

    // And using the phrase ends everything, the caller included: it is a new sign-in.
    const rescue = new TestClient(server);
    await rescue.get("/");
    const issued = await rescue.post<{ challengeId: string; challenge: string }>(
      "/api/auth/recovery/challenge",
      { username: "alice" },
    );
    expect((await rescue.post("/api/auth/recovery/complete", {
      challengeId: issued.body.challengeId,
      signature: toBase64Url(signWithRecoveryKey(keys.signPrivateKey, utf8(issued.body.challenge))),
      newAuthSecret: authSecretFor("alice", "a brand new long passphrase"),
    })).status).toBe(200);
    expect((await owner.get("/api/auth/me")).status).toBe(401);
  });
});

describe("signing out everywhere", () => {
  it("leaves no session at all, from whichever browser asked", async () => {
    const owner = await register(server, "alice");
    const other = await secondSession("alice");
    expect((await other.post("/api/auth/logout-everywhere")).status).toBe(200);
    expect((await owner.get("/api/auth/me")).status).toBe(401);
    expect((await other.get("/api/auth/me")).status).toBe(401);
    expect(await server.db.all("SELECT id FROM sessions")).toEqual([]);
  });
});

describe("what a rotation cannot revoke, stated rather than implied", () => {
  it("leaves unspent send tokens usable, because they carry no owner (ADR-0084)", async () => {
    const owner = await register(server, "alice");
    const minted = await owner.post<{ tokens: string[] }>("/api/messages/tokens", {});
    expect(minted.status).toBe(200);
    expect(minted.body.tokens.length).toBeGreaterThan(0);

    expect((await owner.post("/api/auth/password", {
      currentAuthSecret: authSecretFor("alice", PASSWORD),
      newAuthSecret: authSecretFor("alice", "an entirely different passphrase"),
    })).status).toBe(200);

    // The table has no column that could be joined to an account, which is the price of
    // sealed sender: the rows survive the rotation, and they cannot read anything.
    const rows = await server.db.all<Record<string, unknown>>("SELECT * FROM send_tokens");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(Object.keys(row)).not.toContain("user_id");
    }
  });
});
