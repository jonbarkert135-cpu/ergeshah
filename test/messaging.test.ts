import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";
import {
  createDeviceIdentity,
  type DeviceIdentity,
} from "../src/shared/crypto/identity.ts";
import { fromBase64Url, toBase64Url } from "../src/shared/encoding.ts";
import {
  acceptSession,
  decryptText,
  encryptText,
  openSession,
  type SessionInvite,
} from "../src/shared/crypto/session.ts";
import type { RatchetState } from "../src/shared/crypto/ratchet.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

/** A minimal client: exactly what the browser does, without the DOM. */
class Peer {
  identity: DeviceIdentity = createDeviceIdentity(4);
  deviceId = "";
  sessions = new Map<string, RatchetState>();
  channel = "";

  readonly http: TestClient;

  constructor(http: TestClient) {
    this.http = http;
  }

  async publish(): Promise<void> {
    const response = await this.http.post<{ deviceId: string }>("/api/keys/device", {
      identityKey: toBase64Url(this.identity.identity.publicKey),
      signedPreKeyId: this.identity.signedPreKey.keyId,
      signedPreKey: toBase64Url(this.identity.signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64Url(this.identity.signedPreKeySignature),
      oneTimePreKeys: this.identity.oneTimePreKeys.map((key) => ({
        keyId: key.keyId,
        publicKey: toBase64Url(key.keyPair.publicKey),
      })),
    });
    this.deviceId = response.body.deviceId;
  }

  async send(to: string, channel: string, text: string): Promise<number> {
    const { body } = await this.http.get<{
      bundles: Array<{
        deviceId: string;
        identityKey: string;
        signedPreKeyId: number;
        signedPreKey: string;
        signedPreKeySignature: string;
        oneTimePreKeyId: number | null;
        oneTimePreKey: string | null;
      }>;
    }>(`/api/keys/bundle/${to}`);

    const messages = body.bundles.map((bundle) => {
      const existing = this.sessions.get(bundle.identityKey);
      const plaintext = JSON.stringify({ from: this.http.username, text, at: Date.now() });
      if (existing) {
        return { deviceId: bundle.deviceId, payload: encryptText(existing, plaintext) };
      }
      const { state, invite } = openSession(this.identity.identity, {
        identityKey: fromBase64Url(bundle.identityKey),
        signedPreKeyId: bundle.signedPreKeyId,
        signedPreKey: fromBase64Url(bundle.signedPreKey),
        signedPreKeySignature: fromBase64Url(bundle.signedPreKeySignature),
        oneTimePreKeyId: bundle.oneTimePreKeyId,
        oneTimePreKey: bundle.oneTimePreKey ? fromBase64Url(bundle.oneTimePreKey) : null,
      });
      this.sessions.set(bundle.identityKey, state);
      return { deviceId: bundle.deviceId, payload: encryptText(state, plaintext), invite };
    });

    const response = await this.http.post<{ delivered: number }>("/api/messages", {
      to,
      channel,
      messages,
    });
    if (response.status !== 200) throw new Error(JSON.stringify(response.body));
    return response.body.delivered;
  }

  async receive(): Promise<string[]> {
    const { body } = await this.http.get<{
      envelopes: Array<{ id: string; channel: string; payload: string; invite: SessionInvite | null }>;
    }>(`/api/messages?deviceId=${this.deviceId}`);
    const texts: string[] = [];
    for (const envelope of body.envelopes) {
      this.channel = envelope.channel;
      // Trying a session consumes ratchet state on success, so the plaintext has to be
      // taken from the attempt that worked — exactly what the browser client does.
      let plaintext: string | null = null;
      for (const candidate of this.sessions.values()) {
        try {
          plaintext = decryptText(candidate, envelope.payload);
          break;
        } catch {
          continue;
        }
      }
      if (plaintext === null && envelope.invite) {
        const oneTime =
          envelope.invite.oneTimePreKeyId === null
            ? null
            : (this.identity.oneTimePreKeys.find(
                (key) => key.keyId === envelope.invite!.oneTimePreKeyId,
              ) ?? null);
        const session = acceptSession(
          this.identity.identity,
          this.identity.signedPreKey,
          oneTime,
          envelope.invite,
        );
        this.sessions.set(envelope.invite.identityKey, session);
        plaintext = decryptText(session, envelope.payload);
      }
      if (plaintext === null) continue;
      texts.push((JSON.parse(plaintext) as { text: string }).text);
    }
    await this.http.post("/api/messages/ack", {
      deviceId: this.deviceId,
      ids: body.envelopes.map((envelope) => envelope.id),
    });
    return texts;
  }
}

async function peer(username: string): Promise<Peer> {
  const client = await register(server, username);
  const instance = new Peer(client);
  await instance.publish();
  return instance;
}

describe("end-to-end messaging through the real API", () => {
  it("carries a conversation that the server cannot read", async () => {
    const alice = await peer("alice");
    const bob = await peer("bob");
    const channel = toBase64Url(new Uint8Array(24).fill(7));

    await alice.send("bob", channel, "the server cannot read this");
    const stored = await server.db.all<{ payload: string; invite: string | null }>(
      "SELECT payload, invite FROM envelopes",
    );
    expect(stored).toHaveLength(1);
    expect(stored[0]!.payload).not.toContain("the server cannot read this");
    expect(JSON.stringify(stored)).not.toContain("alice");

    expect(await bob.receive()).toEqual(["the server cannot read this"]);
    await bob.send("alice", channel, "and neither can it read the reply");
    expect(await alice.receive()).toEqual(["and neither can it read the reply"]);

    for (let i = 0; i < 3; i += 1) {
      await alice.send("bob", channel, `a${i}`);
      expect(await bob.receive()).toEqual([`a${i}`]);
      await bob.send("alice", channel, `b${i}`);
      expect(await alice.receive()).toEqual([`b${i}`]);
    }
  });

  it("stores no sender and forgets the envelope once acknowledged", async () => {
    const alice = await peer("alice");
    const bob = await peer("bob");
    await alice.send("bob", toBase64Url(new Uint8Array(24).fill(1)), "ephemeral");

    const columns = await server.db.all<{ name: string }>("PRAGMA table_info(envelopes)");
    expect(columns.map((column) => column.name)).toEqual([
      "id",
      "recipient_device_id",
      "channel",
      "payload",
      "invite",
      "created_at",
      "expires_at",
    ]);

    await bob.receive();
    const remaining = await server.db.all("SELECT id FROM envelopes");
    expect(remaining).toHaveLength(0);
  });

  it("consumes each one-time prekey exactly once", async () => {
    const bob = await peer("bob");
    const alice = await peer("alice");
    const carol = await peer("carol");
    const before = await server.db.all("SELECT id FROM one_time_prekeys WHERE device_id = ?", [
      bob.deviceId,
    ]);
    await alice.send("bob", "AAAA", "one");
    await carol.send("bob", "BBBB", "two");
    const after = await server.db.all("SELECT id FROM one_time_prekeys WHERE device_id = ?", [
      bob.deviceId,
    ]);
    expect(after.length).toBe(before.length - 2);
    expect(await bob.receive()).toEqual(["one", "two"]);
  });

  it("keeps working after the one-time prekeys run out", async () => {
    const bob = await peer("bob");
    await server.db.run("DELETE FROM one_time_prekeys WHERE device_id = ?", [bob.deviceId]);
    const alice = await peer("alice");
    await alice.send("bob", "CCCC", "no one-time prekey left");
    expect(await bob.receive()).toEqual(["no one-time prekey left"]);
  });

  it("refuses to hand out envelopes addressed to someone else's device", async () => {
    const alice = await peer("alice");
    const bob = await peer("bob");
    await alice.send("bob", "DDDD", "private");
    const theft = await alice.http.get(`/api/messages?deviceId=${bob.deviceId}`);
    expect(theft.status).toBe(404);
    const forgedAck = await alice.http.post("/api/messages/ack", {
      deviceId: bob.deviceId,
      ids: ["00000000-0000-4000-8000-000000000000"],
    });
    expect(forgedAck.status).toBe(404);
  });

  it("rejects claiming an identity key that belongs to another account", async () => {
    const alice = await peer("alice");
    const mallory = await register(server, "mallory");
    const response = await mallory.post("/api/keys/device", {
      identityKey: toBase64Url(alice.identity.identity.publicKey),
      signedPreKeyId: 1,
      signedPreKey: toBase64Url(alice.identity.signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64Url(alice.identity.signedPreKeySignature),
      oneTimePreKeys: [],
    });
    expect(response.status).toBe(409);
  });

  it("drops undelivered envelopes when a device is revoked", async () => {
    const alice = await peer("alice");
    const bob = await peer("bob");
    await alice.send("bob", "EEEE", "will never arrive");
    await bob.http.post("/api/keys/revoke", { deviceId: bob.deviceId });
    expect(await server.db.all("SELECT id FROM envelopes")).toHaveLength(0);
    const bundle = await alice.http.get(`/api/keys/bundle/bob`);
    expect(bundle.status).toBe(404);
  });

  it("stores the key vault sealed, and never the key that opens it", async () => {
    const alice = await peer("alice");
    const sealed = { v: 2, nonce: "AAAA", data: "BBBB" };
    expect((await alice.http.request("PUT", "/api/keys/vault", { sealedVault: sealed })).status).toBe(200);
    const row = await server.db.get<{ sealed: string }>("SELECT sealed FROM vaults");
    expect(JSON.parse(row!.sealed)).toEqual(sealed);
    const mallory = await register(server, "mallory");
    const stolen = await mallory.get<{ sealedVault: unknown }>("/api/keys/vault");
    expect(stolen.body.sealedVault).toBeNull();
  });
});
