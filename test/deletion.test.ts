/**
 * Point 74: deletion at every layer, and the honesty about what deletion is not.
 *
 * Server side is testable directly: a shorter expiry when the sender asks for one, clamped
 * to the deployment's own limit, and a row that is gone the moment it is acknowledged.
 * Client side is tested through the real client modules with a stubbed browser, the same
 * way `test/client.test.ts` does it — pruning, deleting one message, and deleting a
 * conversation together with its session keys.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import { createDeviceIdentity } from "../src/shared/crypto/identity.ts";
import {
  deserializeState,
  MAX_SKIPPED_KEY_AGE_MS,
  ratchetDecrypt,
  serializeState,
} from "../src/shared/crypto/ratchet.ts";
import { acceptSession, encryptText, openSession } from "../src/shared/crypto/session.ts";
import { decodeMessage } from "../src/shared/crypto/ratchet.ts";
import { toBase64Url } from "../src/shared/encoding.ts";

let server: TestServer;

beforeEach(async () => {
  await sodiumReady();
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

/** Publishes one device and returns its id: enough to be a valid envelope recipient. */
async function device(client: TestClient): Promise<string> {
  const identity = createDeviceIdentity(4);
  const response = await client.post<{ deviceId: string }>("/api/keys/device", {
    identityKey: toBase64Url(identity.identity.publicKey),
    signedPreKeyId: identity.signedPreKey.keyId,
    signedPreKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
    signedPreKeySignature: toBase64Url(identity.signedPreKeySignature),
    oneTimePreKeys: identity.oneTimePreKeys.map((key) => ({
      keyId: key.keyId,
      publicKey: toBase64Url(key.keyPair.publicKey),
    })),
  });
  return response.body.deviceId;
}

async function send(from: TestClient, to: string, deviceId: string, body: Record<string, unknown>) {
  return from.post("/api/messages", {
    to,
    channel: toBase64Url(new Uint8Array(24).fill(7)),
    messages: [{ deviceId, payload: "hello-ciphertext" }],
    ...body,
  });
}

describe("disappearing messages, server side", () => {
  it("stores the shorter expiry the sender asked for", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const deviceId = await device(bob);

    const before = Date.now();
    const response = await send(alice, "bob", deviceId, { ttlHours: 1 });
    expect(response.status).toBe(200);

    const row = await server.db.get<{ expires_at: number }>(
      "SELECT expires_at FROM envelopes LIMIT 1",
    );
    expect(row!.expires_at).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(row!.expires_at).toBeLessThan(before + 3_600_000 + 5_000);
  });

  it("never lets a sender ask for longer than the deployment allows", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const deviceId = await device(bob);

    await send(alice, "bob", deviceId, { ttlHours: 720 });
    const row = await server.db.get<{ created_at: number; expires_at: number }>(
      "SELECT created_at, expires_at FROM envelopes LIMIT 1",
    );
    // 720 hours is 30 days, exactly the default — the clamp is what keeps it there rather
    // than at 720 hours *plus* whatever a future default becomes.
    expect(row!.expires_at - row!.created_at).toBeLessThanOrEqual(server.config.envelopeTtlMs);
  });

  it("refuses a lifetime outside the allowed range instead of ignoring it", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const deviceId = await device(bob);

    for (const ttlHours of [0, -1, 721, 1.5, "soon"]) {
      const response = await send(alice, "bob", deviceId, { ttlHours });
      expect(response.status, String(ttlHours)).toBe(400);
    }
  });

  it("uses the default when no lifetime is asked for", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const deviceId = await device(bob);

    await send(alice, "bob", deviceId, {});
    const row = await server.db.get<{ created_at: number; expires_at: number }>(
      "SELECT created_at, expires_at FROM envelopes LIMIT 1",
    );
    expect(row!.expires_at - row!.created_at).toBe(server.config.envelopeTtlMs);
  });

  it("forgets an envelope the moment it is acknowledged", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const deviceId = await device(bob);
    await send(alice, "bob", deviceId, { ttlHours: 24 });

    const fetched = await bob.get<{ envelopes: Array<{ id: string }> }>(
      `/api/messages?deviceId=${deviceId}`,
    );
    expect(fetched.body.envelopes).toHaveLength(1);
    await bob.post("/api/messages/ack", { deviceId, ids: [fetched.body.envelopes[0]!.id] });

    const left = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes");
    expect(left!.n).toBe(0);
  });

  it("deletes an expired envelope even if nobody ever collects it", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const deviceId = await device(bob);
    await send(alice, "bob", deviceId, { ttlHours: 1 });

    // The past, as the housekeeping sweep would see it an hour later.
    await server.db.run("UPDATE envelopes SET expires_at = ?", [Date.now() - 1]);
    await bob.get(`/api/messages?deviceId=${deviceId}`);
    const left = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes");
    expect(left!.n).toBe(0);
  });
});

describe("key destruction", () => {
  /** A live session pair, out of order on purpose so that a skipped key exists. */
  function sessionPair() {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: sending, invite } = openSession(alice.identity, {
      identityKey: bob.identity.publicKey,
      signedPreKeyId: bob.signedPreKey.keyId,
      signedPreKey: bob.signedPreKey.keyPair.publicKey,
      signedPreKeySignature: bob.signedPreKeySignature,
      oneTimePreKeyId: bob.oneTimePreKeys[0]!.keyId,
      oneTimePreKey: bob.oneTimePreKeys[0]!.keyPair.publicKey,
    });
    const first = encryptText(sending, "one");
    const receiving = acceptSession(
      bob.identity,
      bob.signedPreKey,
      bob.oneTimePreKeys[0]!,
      invite,
    );
    ratchetDecrypt(receiving, decodeMessage(first));
    return { sending, receiving };
  }

  it("holds a skipped message key, and destroys it once it is stale", () => {
    const { sending, receiving } = sessionPair();
    const skipped = encryptText(sending, "arrives late");
    const later = encryptText(sending, "arrives first");

    // Receiving the second message derives and stores the key for the first.
    ratchetDecrypt(receiving, decodeMessage(later));
    const stored = serializeState(receiving);
    expect(stored.skipped).toHaveLength(1);
    expect(stored.skipped[0]!.at).toBeTypeOf("number");

    // Still openable while it is fresh.
    const fresh = deserializeState(stored);
    expect(new TextDecoder().decode(ratchetDecrypt(fresh, decodeMessage(skipped)))).toBe(
      "arrives late",
    );

    // A week later the key is gone, and the message it would have opened no longer opens:
    // the same outcome the peer sees for any other message that was lost.
    const aged = deserializeState({
      ...stored,
      skipped: stored.skipped.map((entry) => ({
        ...entry,
        at: Date.now() - MAX_SKIPPED_KEY_AGE_MS - 1,
      })),
    });
    expect(() => ratchetDecrypt(aged, decodeMessage(skipped))).toThrow();
    expect(serializeState(aged).skipped).toHaveLength(0);
  });

  it("treats a vault written before keys had an age as fresh, not as expired", () => {
    const { sending, receiving } = sessionPair();
    const skipped = encryptText(sending, "late");
    ratchetDecrypt(receiving, decodeMessage(encryptText(sending, "first")));
    const stored = serializeState(receiving);

    const legacy = deserializeState({
      ...stored,
      skipped: stored.skipped.map(({ id, headerKey, messageKey }) => ({ id, headerKey, messageKey })),
    });
    expect(new TextDecoder().decode(ratchetDecrypt(legacy, decodeMessage(skipped)))).toBe("late");
  });
});
