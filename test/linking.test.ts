/**
 * Device linking, exercised through the API exactly as the two browsers do it: the new
 * device makes its own keys and a code, the signed-in device vouches for them, the new
 * device redeems one session.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { publishDevice, register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import {
  createDeviceIdentity,
  rotateSignedPreKey,
  signSignedPreKey,
} from "../src/shared/crypto/identity.ts";
import { sodium } from "../src/shared/crypto/sodium.ts";
import { toBase64Url } from "../src/shared/encoding.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

/** What a fresh browser produces before anyone has vouched for it. */
function newDevice() {
  const identity = createDeviceIdentity(0);
  const secret = sodium().randombytes_buf(32);
  return {
    secret,
    linkHash: toBase64Url(sodium().crypto_hash_sha256(secret)),
    bundle: {
      label: "laptop",
      identityKey: toBase64Url(identity.identity.publicKey),
      signedPreKeyId: identity.signedPreKey.keyId,
      signedPreKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64Url(
        signSignedPreKey(identity.identity, identity.signedPreKey),
      ),
      oneTimePreKeys: [],
    },
  };
}

describe("linking a second device", () => {
  it("gives the new device its own identity, its own session, and its own copies", async () => {
    const alice = await register(server, "alice");
    const phoneDeviceId = await publishDevice(alice);
    const bob = await register(server, "bob");
    await publishDevice(bob);

    const laptop = newDevice();
    const published = await alice.post<{ deviceId: string }>("/api/keys/device", laptop.bundle);
    expect(published.status).toBe(200);
    const laptopDeviceId = published.body.deviceId;
    expect((await alice.post("/api/auth/link", { linkHash: laptop.linkHash, label: "laptop" })).status).toBe(200);

    // The new browser has no cookies of its own until it redeems the code.
    const linked = new TestClient(server);
    await linked.get("/");
    const claim = await linked.post<{ username: string; role: string }>("/api/auth/link/claim", {
      linkSecret: toBase64Url(laptop.secret),
    });
    expect(claim.status).toBe(200);
    expect(claim.body.username).toBe("alice");
    expect((await linked.get("/api/auth/me")).status).toBe(200);

    // Two devices on the account, two separate identities.
    const status = await alice.get<{ devices: Array<{ deviceId: string }> }>("/api/keys/status");
    expect(status.body.devices.length).toBe(2);

    // A sender fans out to both devices, so each gets its own ciphertext.
    const bundles = await bob.get<{ bundles: Array<{ deviceId: string }> }>(
      "/api/keys/bundle/alice",
    );
    expect(bundles.body.bundles.length).toBe(2);
    const sent = await bob.post<{ delivered: number }>("/api/messages", {
      to: "alice",
      channel: "Y2hhbm5lbA",
      messages: bundles.body.bundles.map((bundle) => ({
        deviceId: bundle.deviceId,
        payload: JSON.stringify({ v: 2, h: "AA", ct: "BB" }),
      })),
    });
    expect(sent.status).toBe(200);
    const forLinked = await linked.get<{ envelopes: unknown[] }>(
      `/api/messages?deviceId=${laptopDeviceId}`,
    );
    const forAlice = await alice.get<{ envelopes: unknown[] }>(
      `/api/messages?deviceId=${phoneDeviceId}`,
    );
    expect(forLinked.body.envelopes.length).toBe(1);
    expect(forAlice.body.envelopes.length).toBe(1);
  });

  it("is single-use, and unknown or expired codes are refused", async () => {
    const alice = await register(server, "alice");
    const laptop = newDevice();
    await alice.post("/api/keys/device", laptop.bundle);
    await alice.post("/api/auth/link", { linkHash: laptop.linkHash });

    const stranger = new TestClient(server);
    await stranger.get("/");
    const wrong = await stranger.post("/api/auth/link/claim", {
      linkSecret: toBase64Url(sodium().randombytes_buf(32)),
    });
    expect(wrong.status).toBe(401);

    const first = new TestClient(server);
    await first.get("/");
    expect((await first.post("/api/auth/link/claim", { linkSecret: toBase64Url(laptop.secret) })).status).toBe(200);

    // A replay of the same code — a photographed screen, say — finds nothing.
    const replay = new TestClient(server);
    await replay.get("/");
    expect((await replay.post("/api/auth/link/claim", { linkSecret: toBase64Url(laptop.secret) })).status).toBe(401);

    // And an authorisation that aged out is gone even before it is used.
    const stale = newDevice();
    await alice.post("/api/keys/device", stale.bundle);
    await alice.post("/api/auth/link", { linkHash: stale.linkHash });
    await server.db.run("UPDATE device_links SET expires_at = ? WHERE link_hash = ?", [
      Date.now() - 1,
      stale.linkHash,
    ]);
    const expired = new TestClient(server);
    await expired.get("/");
    expect((await expired.post("/api/auth/link/claim", { linkSecret: toBase64Url(stale.secret) })).status).toBe(401);
  });

  it("cannot be created without a session, and links only the caller's own account", async () => {
    const alice = await register(server, "alice");
    const laptop = newDevice();

    const anonymous = new TestClient(server);
    await anonymous.get("/");
    expect((await anonymous.post("/api/auth/link", { linkHash: laptop.linkHash })).status).toBe(401);

    // Bob authorising a code binds it to *Bob's* account, never to Alice's.
    const bob = await register(server, "bob");
    await bob.post("/api/keys/device", laptop.bundle);
    await bob.post("/api/auth/link", { linkHash: laptop.linkHash });
    const linked = new TestClient(server);
    await linked.get("/");
    const claim = await linked.post<{ username: string }>("/api/auth/link/claim", {
      linkSecret: toBase64Url(laptop.secret),
    });
    expect(claim.body.username).toBe("bob");
    expect(alice.username).toBe("alice");
  });

  it("stores no usable credential while the authorisation is pending", async () => {
    const alice = await register(server, "alice");
    const laptop = newDevice();
    await alice.post("/api/keys/device", laptop.bundle);
    await alice.post("/api/auth/link", { linkHash: laptop.linkHash });

    const rows = await server.db.all<Record<string, unknown>>("SELECT * FROM device_links");
    expect(rows.length).toBe(1);
    // Only a hash of the secret and the account it belongs to: no token to steal.
    expect(Object.keys(rows[0]!).sort()).toEqual(["expires_at", "label", "link_hash", "user_id"]);
    expect(JSON.stringify(rows[0])).not.toContain(toBase64Url(laptop.secret));
    expect(rows[0]!.link_hash).toBe(laptop.linkHash);
  });
});

describe("a signed prekey that nobody rotated (ADR-0078)", () => {
  it("is reported stale once it passes the client's own rotation window", async () => {
    const alice = await register(server, "stalealice");
    // Published the way the browser does it, so that rotation later re-uses the *same*
    // identity key and updates one device rather than creating a second one.
    const identity = createDeviceIdentity(2);
    const publish = (signedPreKey = identity.signedPreKey, signature = identity.signedPreKeySignature) =>
      alice.post("/api/keys/device", {
        identityKey: toBase64Url(identity.identity.publicKey),
        signedPreKeyId: signedPreKey.keyId,
        signedPreKey: toBase64Url(signedPreKey.keyPair.publicKey),
        signedPreKeySignature: toBase64Url(signature),
        oneTimePreKeys: [],
      });
    expect((await publish()).status).toBe(200);
    const fresh = await alice.get<{
      devices: Array<{ deviceId: string; signedPreKeyAgeDays: number; signedPreKeyStale: boolean }>;
    }>("/api/keys/status");
    expect(fresh.body.devices[0]).toMatchObject({ signedPreKeyAgeDays: 0, signedPreKeyStale: false });

    // Eight days without a sign-in: the state a browser left open used to stay in forever,
    // because rotation only ever happened at sign-in.
    await server.db.run("UPDATE devices SET rotated_day = rotated_day - 8");
    const stale = await alice.get<{
      devices: Array<{ signedPreKeyAgeDays: number; signedPreKeyStale: boolean }>;
    }>("/api/keys/status");
    expect(stale.body.devices[0]).toMatchObject({ signedPreKeyAgeDays: 8, signedPreKeyStale: true });

    // Publishing a new signed prekey — which is what the browser now does in the background,
    // with the private half never leaving it — clears the flag.
    const rotatedIdentity = rotateSignedPreKey(identity);
    expect(
      (await publish(rotatedIdentity.signedPreKey, rotatedIdentity.signedPreKeySignature)).status,
    ).toBe(200);
    expect(await server.db.all("SELECT id FROM devices")).toHaveLength(1);
    const rotated = await alice.get<{ devices: Array<{ signedPreKeyStale: boolean }> }>(
      "/api/keys/status",
    );
    expect(rotated.body.devices[0]?.signedPreKeyStale).toBe(false);
  });
});
