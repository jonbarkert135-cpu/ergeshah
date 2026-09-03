/**
 * Anti-automation (point 71) and recovery hygiene (points 69, 70).
 *
 * The measure under test is a proof of work, not a CAPTCHA: nothing here contacts a third
 * party, fingerprints a browser or asks for a phone number, and these tests assert that
 * the cost lands on the client rather than on the user's privacy.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  authSecretFor,
  register,
  startTestServer,
  TestClient,
  TEST_POW_BITS,
  type TestServer,
} from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { loadConfig } from "../src/server/config.ts";
import { issueProofOfWork } from "../src/server/lib/pow.ts";
import { meetsDifficulty, powPreimage, solveProofOfWork } from "../src/shared/pow.ts";

const sha256 = (input: Uint8Array) => new Uint8Array(createHash("sha256").update(input).digest());

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

/** A raw client that does *not* solve challenges, so the gate itself is observable. */
async function bare(): Promise<TestClient> {
  const client = new TestClient(server);
  await client.get("/");
  return client;
}

describe("the proof-of-work gate", () => {
  it("refuses an unsolved registration and hands back a challenge to solve", async () => {
    const client = await bare();
    const response = await client.request<{
      error: string;
      pow?: { challenge: string; mac: string; bits: number };
    }>("POST", "/api/auth/register", {
      username: "hopeful",
      authSecret: authSecretFor("hopeful", "correct horse battery staple"),
    }, {}, true); // `true` = do not auto-solve

    expect(response.status).toBe(428);
    expect(response.body.error).toBe("pow_required");
    expect(response.body.pow?.bits).toBe(TEST_POW_BITS);
    expect(response.body.pow?.challenge).toBeTruthy();
    // Nothing was created by an unsolved attempt.
    expect((await server.db.all("SELECT id FROM users")).length).toBe(0);
  });

  it("gates login and recovery too, not only registration", async () => {
    await register(server, "alice");
    const client = await bare();
    for (const [url, body] of [
      ["/api/auth/login", { username: "alice", authSecret: authSecretFor("alice", "x") }],
      ["/api/auth/recovery/challenge", { username: "alice" }],
    ] as const) {
      const response = await client.request("POST", url, body, {}, true);
      expect(response.status, url).toBe(428);
    }
  });

  it("accepts a correct solution and refuses a wrong nonce", async () => {
    const client = await bare();
    const first = await client.request<{ pow: { challenge: string; mac: string; bits: number } }>(
      "POST",
      "/api/auth/register",
      { username: "hopeful", authSecret: authSecretFor("hopeful", "pw") },
      {},
      true,
    );
    const { challenge, mac, bits } = first.body.pow;

    // A nonce that provably does *not* meet the difficulty. Picking one at random would
    // be a flaky test: at the low difficulty these tests run at, one guess in sixteen is
    // accidentally a valid proof.
    let dud = 0;
    while (meetsDifficulty(sha256(new TextEncoder().encode(powPreimage(challenge, dud))), bits)) {
      dud += 1;
    }
    const wrong = await client.request(
      "POST",
      "/api/auth/register",
      {
        username: "hopeful",
        authSecret: authSecretFor("hopeful", "pw"),
        pow: { challenge, mac, nonce: dud },
      },
      {},
      true,
    );
    expect(wrong.status, "a nonce that does not meet the difficulty is not a proof").toBe(428);

    const nonce = solveProofOfWork(challenge, bits, sha256);
    const right = await client.request(
      "POST",
      "/api/auth/register",
      {
        username: "hopeful",
        authSecret: authSecretFor("hopeful", "pw"),
        pow: { challenge, mac, nonce },
      },
      {},
      true,
    );
    expect(right.status).toBe(200);
  });

  it("refuses a forged challenge and a downgraded difficulty", async () => {
    const client = await bare();
    const genuine = issueProofOfWork(server.config.bucketPepper, TEST_POW_BITS);

    // A challenge the server never issued: the MAC is what makes one ours.
    const forged = { challenge: `forged.${Date.now()}`, mac: genuine.mac, nonce: 0 };
    const a = await client.request(
      "POST",
      "/api/auth/register",
      { username: "forger", authSecret: authSecretFor("forger", "pw"), pow: forged },
      {},
      true,
    );
    expect(a.status).toBe(428);

    // A genuine challenge replayed at a difficulty of 1 bit: the MAC covers the difficulty,
    // so a client cannot choose how much work to do.
    const easy = issueProofOfWork(server.config.bucketPepper, 1);
    const b = await client.request(
      "POST",
      "/api/auth/register",
      {
        username: "forger",
        authSecret: authSecretFor("forger", "pw"),
        pow: { challenge: easy.challenge, mac: easy.mac, nonce: solveProofOfWork(easy.challenge, 1, sha256) },
      },
      {},
      true,
    );
    expect(b.status).toBe(428);
  });

  it("spends a proof once: the same solution cannot register two accounts", async () => {
    const client = await bare();
    const issued = await client.request<{ pow: { challenge: string; mac: string; bits: number } }>(
      "POST",
      "/api/auth/register",
      { username: "first", authSecret: authSecretFor("first", "pw") },
      {},
      true,
    );
    const { challenge, mac, bits } = issued.body.pow;
    const pow = { challenge, mac, nonce: solveProofOfWork(challenge, bits, sha256) };

    const one = await client.request(
      "POST",
      "/api/auth/register",
      { username: "first", authSecret: authSecretFor("first", "pw"), pow },
      {},
      true,
    );
    const two = await client.request(
      "POST",
      "/api/auth/register",
      { username: "second", authSecret: authSecretFor("second", "pw"), pow },
      {},
      true,
    );
    expect(one.status).toBe(200);
    expect(two.status).toBe(400);
    expect((two.body as { error: string }).error).toBe("pow_spent");
  });

  it("asks nothing about the client: no third party, no identifier, no state until it is spent", async () => {
    const client = await bare();
    const response = await client.request<{ pow: Record<string, unknown> }>(
      "POST",
      "/api/auth/register",
      { username: "hopeful", authSecret: authSecretFor("hopeful", "pw") },
      {},
      true,
    );
    // The whole challenge: a token, a MAC, a difficulty, a lifetime. No cookie to set, no
    // script to load, no origin to contact.
    expect(Object.keys(response.body.pow).sort()).toEqual([
      "bits",
      "challenge",
      "expiresInSeconds",
      "mac",
    ]);
    // Issuing costs no row — otherwise asking for challenges would itself be the attack.
    expect((await server.db.all("SELECT id FROM auth_challenges")).length).toBe(0);
  });

  it("solves the shipped difficulty in a sane number of attempts", () => {
    // The default is a cost, not an obstacle: this asserts the arithmetic behind that
    // claim rather than the wall-clock time, which depends on the machine running CI. The
    // difficulty is read from the configuration, so raising the default without thinking
    // about what a phone has to do fails here.
    const bits = loadConfig({}).powBits;
    expect(bits).toBeGreaterThan(8);
    expect(bits, "a difficulty a browser cannot pay in under a second is a locked door").toBeLessThanOrEqual(18);
    const challenge = "difficulty-check.1";
    const nonce = solveProofOfWork(challenge, bits, sha256);
    expect(meetsDifficulty(sha256(new TextEncoder().encode(powPreimage(challenge, nonce))), bits)).toBe(
      true,
    );
    // ~2^18 expected attempts; a factor of eight over that would mean the search is wrong.
    expect(nonce).toBeLessThan(8 * 2 ** bits);
  });
});

describe("attempts aimed at one account", () => {
  it("limits guesses against a username without limiting everyone else", async () => {
    await register(server, "victim");
    await register(server, "bystander");
    const tight = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, account_attempt: { burst: 3, perMinute: 0.1 } },
    });
    try {
      const client = new TestClient(tight);
      await client.get("/");
      await client.post("/api/auth/register", {
        username: "victim",
        authSecret: authSecretFor("victim", "correct horse battery staple"),
      });

      const statuses: number[] = [];
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const response = await client.post("/api/auth/login", {
          username: "victim",
          authSecret: authSecretFor("victim", `guess-${attempt}`),
        });
        statuses.push(response.status);
      }
      expect(statuses, "guessing one name must run out of allowance").toContain(429);

      // A different name is unaffected: the bucket is per account, not one global counter.
      const other = await client.post("/api/auth/login", {
        username: "someone-else",
        authSecret: authSecretFor("someone-else", "whatever"),
      });
      expect(other.status).not.toBe(429);
    } finally {
      await tight.close();
    }
  });

  it("charges the same for a name that exists and one that does not", async () => {
    await register(server, "real");
    const client = await bare();
    const known = await client.post("/api/auth/login", {
      username: "real",
      authSecret: authSecretFor("real", "wrong password"),
    });
    const unknown = await client.post("/api/auth/login", {
      username: "not-real",
      authSecret: authSecretFor("not-real", "wrong password"),
    });
    expect(known.status).toBe(unknown.status);
    expect(known.body).toEqual(unknown.body);
  });
});

describe("recovery challenges (point 69)", () => {
  it("invalidates the previous challenge when a new one is issued", async () => {
    const alice = await register(server, "alice");
    // Give her a recovery key so the challenges are real ones rather than decoys.
    await alice.post("/api/auth/recovery/key", {
      authSecret: authSecretFor("alice", "correct horse battery staple"),
      recoveryPublicKey: Buffer.alloc(32, 7).toString("base64url"),
    });

    const client = await bare();
    const first = await client.post<{ challengeId: string }>("/api/auth/recovery/challenge", {
      username: "alice",
    });
    const second = await client.post<{ challengeId: string }>("/api/auth/recovery/challenge", {
      username: "alice",
    });
    expect(first.body.challengeId).not.toBe(second.body.challengeId);

    const live = await server.db.all<{ id: string }>(
      "SELECT id FROM auth_challenges WHERE kind = 'recovery'",
    );
    expect(live.length, "only the newest challenge survives").toBe(1);
    expect(live[0]!.id).toBe(second.body.challengeId);

    // And the superseded one cannot be redeemed, however good the signature would be.
    const stale = await client.post("/api/auth/recovery/complete", {
      challengeId: first.body.challengeId,
      signature: Buffer.alloc(64).toString("base64url"),
      newAuthSecret: authSecretFor("alice", "a brand new password"),
    });
    expect(stale.status).toBe(401);
  });

  it("fails identically for a real account, an unknown name and a bad signature", async () => {
    await register(server, "alice");
    const client = await bare();
    const known = await client.post<{ challengeId: string }>("/api/auth/recovery/challenge", {
      username: "alice",
    });
    const unknown = await client.post<{ challengeId: string }>("/api/auth/recovery/challenge", {
      username: "ghost",
    });

    const signature = Buffer.alloc(64).toString("base64url");
    const newAuthSecret = authSecretFor("alice", "another password");
    const a = await client.post("/api/auth/recovery/complete", {
      challengeId: known.body.challengeId,
      signature,
      newAuthSecret,
    });
    const b = await client.post("/api/auth/recovery/complete", {
      challengeId: unknown.body.challengeId,
      signature,
      newAuthSecret,
    });
    const c = await client.post("/api/auth/recovery/complete", {
      challengeId: "00000000-0000-4000-8000-000000000000",
      signature,
      newAuthSecret,
    });
    expect(a.status).toBe(401);
    expect([a.body, b.body, c.body]).toEqual([a.body, a.body, a.body]);
  });
});
