/**
 * PGP as a second factor.
 *
 * The signing in these tests stands in for what a user does with `gpg --detach-sign` on
 * their own machine: keys are generated here, and the private halves never leave this
 * file — which is the same property the real flow has, only harder to see from the server.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createMessage, generateKey, readPrivateKey, sign } from "openpgp";
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
import { inspectPublicKey, readableFingerprint, verifyDetachedSignature } from "../src/server/lib/pgp.ts";

interface Keypair {
  publicKey: string;
  privateKey: string;
}

let alice: Keypair;
let mallory: Keypair;
let server: TestServer;

/** Detached, armoured, over exactly this text — what `gpg --detach-sign --armor` makes. */
async function detachedSignature(pair: Keypair, text: string): Promise<string> {
  const key = await readPrivateKey({ armoredKey: pair.privateKey });
  return (await sign({
    message: await createMessage({ text }),
    signingKeys: key,
    detached: true,
    format: "armored",
  })) as string;
}

beforeAll(async () => {
  // Curve25519 keys: fast to generate, and what a modern gpg produces by default.
  [alice, mallory] = (await Promise.all([
    generateKey({ userIDs: [{ name: "alice" }], type: "ecc", format: "armored" }),
    generateKey({ userIDs: [{ name: "mallory" }], type: "ecc", format: "armored" }),
  ])) as unknown as [Keypair, Keypair];
}, 30_000);

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

describe("reading a public key", () => {
  it("accepts a signing-capable key and reports its fingerprint", async () => {
    const facts = await inspectPublicKey(alice.publicKey);
    expect(facts.fingerprint).toMatch(/^[0-9a-f]{40}$/);
    expect(facts.readable).toBe(readableFingerprint(facts.fingerprint));
    expect(facts.readable).toMatch(/^[0-9A-F]{4} ([0-9A-F]{4} ){8}[0-9A-F]{4}$/);
    expect(facts.identities.join()).toContain("alice");
    // Leading and trailing whitespace from a paste does not change the key.
    expect((await inspectPublicKey(`\n  ${alice.publicKey}  \n`)).fingerprint).toBe(facts.fingerprint);
  });

  it("refuses a private key outright, with an explanation", async () => {
    await expect(inspectPublicKey(alice.privateKey)).rejects.toThrow(/private key/);
  });

  it("refuses text that is not a key, and armour that is too large", async () => {
    await expect(inspectPublicKey("hello")).rejects.toThrow(/armoured public key/);
    await expect(
      inspectPublicKey(`-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnonsense\n-----END-----`),
    ).rejects.toThrow(/could not be read/);
    await expect(inspectPublicKey("-----BEGIN PGP ".padEnd(70_000, "A"))).rejects.toThrow(/too large/);
  });
});

describe("verifying a detached signature", () => {
  it("accepts the right key over the right text, and nothing else", async () => {
    const challenge = "a1b2c3-challenge-text";
    const signature = await detachedSignature(alice, challenge);

    expect(await verifyDetachedSignature(alice.publicKey, challenge, signature)).toBe(true);
    // Another key's signature, the right key over other text, and junk: all false, never
    // an exception, because a caller must not have to tell "invalid" from "malformed".
    expect(await verifyDetachedSignature(mallory.publicKey, challenge, signature)).toBe(false);
    expect(await verifyDetachedSignature(alice.publicKey, "a different challenge", signature)).toBe(false);
    expect(await verifyDetachedSignature(alice.publicKey, challenge, "not a signature")).toBe(false);
    expect(
      await verifyDetachedSignature(
        alice.publicKey,
        challenge,
        await detachedSignature(mallory, challenge),
      ),
    ).toBe(false);
  });
});

describe("enrolling a key", () => {
  const PASSWORD = "correct horse battery staple";

  async function enrol(client: TestClient, username: string, pair: Keypair) {
    const challenge = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    return client.post<{ fingerprint: string }>("/api/auth/pgp/key", {
      authSecret: authSecretFor(username, PASSWORD),
      publicKey: pair.publicKey,
      challengeId: challenge.body.challengeId,
      signature: await detachedSignature(pair, challenge.body.challenge),
    });
  }

  it("requires the password, a challenge and a signature made by that very key", async () => {
    const client = await register(server, "alice");
    const challenge = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );

    // Right key, wrong password.
    expect((await client.post("/api/auth/pgp/key", {
      authSecret: authSecretFor("alice", "not the password"),
      publicKey: alice.publicKey,
      challengeId: challenge.body.challengeId,
      signature: await detachedSignature(alice, challenge.body.challenge),
    })).status).toBe(401);

    // Right password, but the signature comes from a key the user does not control —
    // which is what "proof of possession" is there to catch.
    const second = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    expect((await client.post("/api/auth/pgp/key", {
      authSecret: authSecretFor("alice", PASSWORD),
      publicKey: alice.publicKey,
      challengeId: second.body.challengeId,
      signature: await detachedSignature(mallory, second.body.challenge),
    })).status).toBe(400);

    // Nothing was stored by either attempt.
    expect(
      (await server.db.get<{ pgp_fingerprint: string | null }>(
        "SELECT pgp_fingerprint FROM users WHERE username = 'alice'",
      ))?.pgp_fingerprint,
    ).toBeNull();

    const ok = await enrol(client, "alice", alice);
    expect(ok.status).toBe(200);
    expect(ok.body.fingerprint).toBe((await inspectPublicKey(alice.publicKey)).readable);
    const me = await client.get<{ pgpFingerprint: string | null }>("/api/auth/me");
    expect(me.body.pgpFingerprint).toBe(ok.body.fingerprint);
  });

  it("refuses a private key, and stores no signing material at all", async () => {
    const client = await register(server, "alice");
    const challenge = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    const attempt = await client.post<{ error?: string }>("/api/auth/pgp/key", {
      authSecret: authSecretFor("alice", PASSWORD),
      publicKey: alice.privateKey,
      challengeId: challenge.body.challengeId,
      signature: await detachedSignature(alice, challenge.body.challenge),
    });
    expect(attempt.status).toBe(400);
    expect(JSON.stringify(attempt.body)).toMatch(/private key/);

    await enrol(client, "alice", alice);
    const dump = JSON.stringify(await server.db.all("SELECT * FROM users"));
    expect(dump).toContain("PUBLIC KEY BLOCK");
    expect(dump).not.toContain("PRIVATE KEY BLOCK");
  });

  it("uses a challenge once, and only for the account that asked for it", async () => {
    const client = await register(server, "alice");
    const challenge = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    const signature = await detachedSignature(alice, challenge.body.challenge);
    const body = {
      authSecret: authSecretFor("alice", PASSWORD),
      publicKey: alice.publicKey,
      challengeId: challenge.body.challengeId,
      signature,
    };
    expect((await client.post("/api/auth/pgp/key", body)).status).toBe(200);
    expect((await client.post("/api/auth/pgp/key", body)).status).toBe(401);

    // Bob cannot enrol against a challenge issued to alice, even with a valid signature.
    const bob = await register(server, "bob");
    const alices = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    expect((await bob.post("/api/auth/pgp/key", {
      authSecret: authSecretFor("bob", PASSWORD),
      publicKey: mallory.publicKey,
      challengeId: alices.body.challengeId,
      signature: await detachedSignature(mallory, alices.body.challenge),
    })).status).toBe(401);
  });
});

describe("logging in with password and PGP", () => {
  const PASSWORD = "correct horse battery staple";

  async function accountWithPgp(username: string) {
    const client = await register(server, username);
    const challenge = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    const response = await client.post("/api/auth/pgp/key", {
      authSecret: authSecretFor(username, PASSWORD),
      publicKey: alice.publicKey,
      challengeId: challenge.body.challengeId,
      signature: await detachedSignature(alice, challenge.body.challenge),
    });
    if (response.status !== 200) throw new Error(JSON.stringify(response.body));
    return client;
  }

  it("gives the password alone a challenge instead of a session", async () => {
    await accountWithPgp("alice");
    const client = new TestClient(server);
    await client.get("/");

    const login = await client.post<{
      pgpRequired?: boolean;
      challengeId: string;
      challenge: string;
      token?: string;
      fingerprint?: string;
    }>("/api/auth/login", { username: "alice", authSecret: authSecretFor("alice", PASSWORD) });
    expect(login.status).toBe(200);
    expect(login.body.pgpRequired).toBe(true);
    expect(login.body.token).toBeUndefined();
    expect(login.body.fingerprint).toBe((await inspectPublicKey(alice.publicKey)).readable);
    // The password step alone left no usable session behind.
    expect((await client.get("/api/auth/me")).status).toBe(401);

    // A signature from the wrong key does not get in, and burns the challenge.
    const wrong = await client.post("/api/auth/pgp/complete", {
      challengeId: login.body.challengeId,
      signature: await detachedSignature(mallory, login.body.challenge),
    });
    expect(wrong.status).toBe(401);
    expect((await client.post("/api/auth/pgp/complete", {
      challengeId: login.body.challengeId,
      signature: await detachedSignature(alice, login.body.challenge),
    })).status).toBe(401);

    // A fresh round with the right key does.
    const again = await client.post<{ challengeId: string; challenge: string }>("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    });
    const completed = await client.post<{ username: string; sealedVault: unknown }>(
      "/api/auth/pgp/complete",
      {
        challengeId: again.body.challengeId,
        signature: await detachedSignature(alice, again.body.challenge),
      },
    );
    expect(completed.status).toBe(200);
    expect(completed.body.username).toBe("alice");
    expect((await client.get("/api/auth/me")).status).toBe(200);
  });

  it("refuses a signature over an expired challenge", async () => {
    await accountWithPgp("alice");
    const client = new TestClient(server);
    await client.get("/");
    const login = await client.post<{ challengeId: string; challenge: string }>("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    });
    await server.db.run("UPDATE auth_challenges SET expires_at = ? WHERE id = ?", [
      Date.now() - 1,
      login.body.challengeId,
    ]);
    expect((await client.post("/api/auth/pgp/complete", {
      challengeId: login.body.challengeId,
      signature: await detachedSignature(alice, login.body.challenge),
    })).status).toBe(401);
  });

  it("lets the owner turn the factor off with their password, and nobody else", async () => {
    const client = await accountWithPgp("alice");
    expect((await client.post("/api/auth/pgp/remove", {
      authSecret: authSecretFor("alice", "not the password"),
    })).status).toBe(401);
    expect((await client.post("/api/auth/pgp/remove", {
      authSecret: authSecretFor("alice", PASSWORD),
    })).status).toBe(200);

    const fresh = new TestClient(server);
    await fresh.get("/");
    const login = await fresh.post<{ pgpRequired?: boolean; token?: string }>("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    });
    expect(login.body.pgpRequired).toBeUndefined();
    expect((await fresh.get("/api/auth/me")).status).toBe(200);
  });
});

/**
 * The deliberate ordering: a recovery phrase outranks the second factor.
 *
 * Someone recovering an account has lost their password, and there is no reason to assume
 * they still hold the signing key. If the factor survived a recovery, a lost PGP key would
 * turn a recoverable account into an unreachable one — and the phrase is already the
 * strongest secret in the system, so this grants it nothing it did not have.
 */
describe("recovery and the PGP factor", () => {
  it("clears the factor so a new key can be enrolled afterwards", async () => {
    await sodiumReady();
    const phrase = generatePhrase(24);
    const recovery = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    const client = await register(server, "alice");
    await client.post("/api/auth/recovery/key", {
      authSecret: authSecretFor("alice", "correct horse battery staple"),
      recoveryPublicKey: toBase64Url(recovery.signPublicKey),
    });
    const enrolment = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/pgp/challenge",
      {},
    );
    expect((await client.post("/api/auth/pgp/key", {
      authSecret: authSecretFor("alice", "correct horse battery staple"),
      publicKey: alice.publicKey,
      challengeId: enrolment.body.challengeId,
      signature: await detachedSignature(alice, enrolment.body.challenge),
    })).status).toBe(200);

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

    const me = await rescue.get<{ pgpFingerprint: string | null }>("/api/auth/me");
    expect(me.body.pgpFingerprint).toBeNull();
    const next = new TestClient(server);
    await next.get("/");
    const login = await next.post<{ pgpRequired?: boolean }>("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", "a brand new long passphrase"),
    });
    expect(login.body.pgpRequired).toBeUndefined();
    expect((await next.get("/api/auth/me")).status).toBe(200);
  });
});
