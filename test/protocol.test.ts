import { beforeAll, describe, expect, it } from "vitest";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import { fromBase64Url, toBase64Url } from "../src/shared/encoding.ts";
import {
  createDeviceIdentity,
  safetyNumber,
  signedPreKeyNeedsRotation,
  rotateSignedPreKey,
  verifySignedPreKey,
  type DeviceIdentity,
} from "../src/shared/crypto/identity.ts";
import {
  acceptSession,
  decryptText,
  encryptText,
  openSession,
  type SessionInvite,
} from "../src/shared/crypto/session.ts";
import {
  decodeMessage,
  encodeMessage,
  deserializeState,
  serializeState,
  MAX_SKIP_PER_CHAIN,
} from "../src/shared/crypto/ratchet.ts";
import { deriveAccountKeys, openVault, sealVault } from "../src/shared/crypto/vault.ts";

const FAST = { opsLimit: 1, memLimit: 8192 };

function bundleOf(identity: DeviceIdentity, useOneTime = true) {
  const oneTime = useOneTime ? identity.oneTimePreKeys[0] : undefined;
  return {
    identityKey: identity.identity.publicKey,
    signedPreKeyId: identity.signedPreKey.keyId,
    signedPreKey: identity.signedPreKey.keyPair.publicKey,
    signedPreKeySignature: identity.signedPreKeySignature,
    oneTimePreKeyId: oneTime ? oneTime.keyId : null,
    oneTimePreKey: oneTime ? oneTime.keyPair.publicKey : null,
  };
}

function accept(bob: DeviceIdentity, invite: SessionInvite) {
  const oneTime =
    invite.oneTimePreKeyId === null
      ? null
      : (bob.oneTimePreKeys.find((key) => key.keyId === invite.oneTimePreKeyId) ?? null);
  return acceptSession(bob.identity, bob.signedPreKey, oneTime, invite);
}

beforeAll(async () => {
  await sodiumReady();
});

describe("identity and prekeys", () => {
  it("signs and verifies the signed prekey, and rejects a substituted one", () => {
    const alice = createDeviceIdentity(2);
    const mallory = createDeviceIdentity(2);
    expect(
      verifySignedPreKey(
        alice.identity.publicKey,
        alice.signedPreKey.keyPair.publicKey,
        alice.signedPreKey.keyId,
        alice.signedPreKeySignature,
      ),
    ).toBe(true);
    // malicious key substitution: attacker's prekey under Alice's identity
    expect(
      verifySignedPreKey(
        alice.identity.publicKey,
        mallory.signedPreKey.keyPair.publicKey,
        alice.signedPreKey.keyId,
        alice.signedPreKeySignature,
      ),
    ).toBe(false);
    // signature bound to the key id as well
    expect(
      verifySignedPreKey(
        alice.identity.publicKey,
        alice.signedPreKey.keyPair.publicKey,
        alice.signedPreKey.keyId + 1,
        alice.signedPreKeySignature,
      ),
    ).toBe(false);
  });

  it("rotates the signed prekey on schedule", () => {
    const identity = createDeviceIdentity(1);
    expect(signedPreKeyNeedsRotation(identity)).toBe(false);
    expect(signedPreKeyNeedsRotation(identity, Date.now() + 8 * 86_400_000)).toBe(true);
    const rotated = rotateSignedPreKey(identity);
    expect(toBase64Url(rotated.signedPreKey.keyPair.publicKey)).not.toBe(
      toBase64Url(identity.signedPreKey.keyPair.publicKey),
    );
    expect(
      verifySignedPreKey(
        rotated.identity.publicKey,
        rotated.signedPreKey.keyPair.publicKey,
        rotated.signedPreKey.keyId,
        rotated.signedPreKeySignature,
      ),
    ).toBe(true);
  });

  it("produces an order-independent safety number", () => {
    const a = createDeviceIdentity(1);
    const b = createDeviceIdentity(1);
    expect(safetyNumber(a.identity.publicKey, b.identity.publicKey)).toBe(
      safetyNumber(b.identity.publicKey, a.identity.publicKey),
    );
    expect(safetyNumber(a.identity.publicKey, b.identity.publicKey)).not.toBe(
      safetyNumber(a.identity.publicKey, a.identity.publicKey),
    );
  });
});

describe("X3DH + Double Ratchet", () => {
  it("agrees on a session and carries a conversation both ways", () => {
    const alice = createDeviceIdentity(4);
    const bob = createDeviceIdentity(4);

    const { state: aliceState, invite } = openSession(alice.identity, bundleOf(bob));
    const first = encryptText(aliceState, "привет, это первое сообщение");

    const bobState = accept(bob, invite);
    expect(decryptText(bobState, first)).toBe("привет, это первое сообщение");

    expect(decryptText(aliceState, encryptText(bobState, "reply 1"))).toBe("reply 1");
    expect(decryptText(bobState, encryptText(aliceState, "reply 2"))).toBe("reply 2");
    for (let i = 0; i < 5; i += 1) {
      expect(decryptText(aliceState, encryptText(bobState, `b${i}`))).toBe(`b${i}`);
      expect(decryptText(bobState, encryptText(aliceState, `a${i}`))).toBe(`a${i}`);
    }
  });

  it("works without a one-time prekey (exhausted bundle) but still authenticates", () => {
    const alice = createDeviceIdentity(1);
    const bob = createDeviceIdentity(1);
    const { state, invite } = openSession(alice.identity, bundleOf(bob, false));
    expect(invite.oneTimePreKeyId).toBeNull();
    const bobState = accept(bob, invite);
    expect(decryptText(bobState, encryptText(state, "no otk"))).toBe("no otk");
  });

  it("rejects a bundle whose signed prekey signature does not verify", () => {
    const alice = createDeviceIdentity(1);
    const bob = createDeviceIdentity(1);
    const mallory = createDeviceIdentity(1);
    const forged = { ...bundleOf(bob), signedPreKey: mallory.signedPreKey.keyPair.publicKey };
    expect(() => openSession(alice.identity, forged)).toThrow(/signature is invalid/);
  });

  it("derives a unique message key per message (forward secrecy inside a chain)", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state, invite } = openSession(alice.identity, bundleOf(bob));
    const bobState = accept(bob, invite);
    const payloads = [0, 1, 2, 3].map(() => encryptText(state, "same plaintext"));
    const ciphertexts = payloads.map((p) => decodeMessage(p)).map((m) => toBase64Url(m.ciphertext));
    expect(new Set(ciphertexts).size).toBe(4); // no key or nonce reuse
    for (const payload of payloads) expect(decryptText(bobState, payload)).toBe("same plaintext");
  });

  it("re-keys the root key on every DH ratchet step (post-compromise security)", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);
    decryptText(b, encryptText(a, "hello"));

    const roots = new Set<string>();
    for (let i = 0; i < 4; i += 1) {
      roots.add(toBase64Url(a.rootKey));
      decryptText(a, encryptText(b, `b${i}`));
      roots.add(toBase64Url(b.rootKey));
      decryptText(b, encryptText(a, `a${i}`));
    }
    expect(roots.size).toBeGreaterThanOrEqual(4);
  });

  it("decrypts out-of-order and dropped messages", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);

    const messages = ["m0", "m1", "m2", "m3", "m4"].map((text) => encryptText(a, text));
    expect(decryptText(b, messages[4]!)).toBe("m4"); // arrives first
    expect(decryptText(b, messages[0]!)).toBe("m0");
    expect(decryptText(b, messages[2]!)).toBe("m2");
    expect(decryptText(b, messages[1]!)).toBe("m1");
    // m3 never delivered; the session still works afterwards
    expect(decryptText(a, encryptText(b, "still alive"))).toBe("still alive");
  });

  it("rejects replays of an already-consumed message", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);
    const first = encryptText(a, "once");
    const second = encryptText(a, "twice");
    expect(decryptText(b, second)).toBe("twice"); // stores skipped key for `first`
    expect(decryptText(b, first)).toBe("once");
    expect(() => decryptText(b, first)).toThrow(/failed authentication/);
    expect(() => decryptText(b, second)).toThrow(/failed authentication/);
  });

  it("fails authentication when the header or ciphertext is tampered with", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);
    const message = decodeMessage(encryptText(a, "integrity"));

    const tamperedHeader = new Uint8Array(message.encryptedHeader);
    tamperedHeader[30] = (tamperedHeader[30]! ^ 0x01) & 0xff;
    expect(() =>
      decryptText(b, encodeMessage({ ...message, encryptedHeader: tamperedHeader })),
    ).toThrow(/failed authentication/);

    const flipped = new Uint8Array(message.ciphertext);
    flipped[0] = (flipped[0]! ^ 0x01) & 0xff;
    expect(() => decryptText(b, encodeMessage({ ...message, ciphertext: flipped }))).toThrow(
      /failed authentication/,
    );
    // the untampered message still decrypts
    expect(decryptText(b, encodeMessage(message))).toBe("integrity");
  });

  it("keeps the ratchet key and the counters off the wire", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);

    const payload = encryptText(a, "metadata check");
    const parsed = JSON.parse(payload) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(["ct", "h", "v"]);
    // The sending ratchet key is what would let a server group messages by session.
    expect(payload).not.toContain(toBase64Url(a.self.publicKey));

    // Successive envelopes look alike: same size, no shared prefix to correlate on.
    const second = encryptText(a, "metadata check");
    const headers = [payload, second].map((p) => decodeMessage(p).encryptedHeader);
    expect(headers[0]!.length).toBe(headers[1]!.length);
    expect(toBase64Url(headers[0]!)).not.toBe(toBase64Url(headers[1]!));

    expect(decryptText(b, payload)).toBe("metadata check");
    expect(decryptText(b, second)).toBe("metadata check");
  });

  it("pads plaintext into buckets so length no longer identifies the message", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);

    const sizeOf = (text: string) => decodeMessage(encryptText(a, text)).ciphertext.length;
    // "hi" and a 63-byte message are indistinguishable: same bucket, same ciphertext size.
    expect(sizeOf("hi")).toBe(64 + 16);
    expect(sizeOf("x".repeat(63))).toBe(64 + 16);
    // Larger messages move up a bucket, which is all an observer learns.
    expect(sizeOf("x".repeat(64))).toBe(256 + 16);
    expect(sizeOf("x".repeat(300))).toBe(1024 + 16);
    expect(decryptText(b, encryptText(a, "hi"))).toBe("hi");
  });

  it("still opens a skipped message from a retired chain after several ratchet steps", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);

    const delayed = encryptText(a, "sent early, delivered late");
    decryptText(b, encryptText(a, "arrives first")); // stores the skipped key + its header key
    for (let i = 0; i < 3; i += 1) {
      decryptText(a, encryptText(b, `b${i}`));
      decryptText(b, encryptText(a, `a${i}`));
    }
    // Three DH ratchet steps later the header key that sealed it is long retired, but the
    // stored skipped entry carries it, so the message is still readable exactly once.
    expect(decryptText(b, delayed)).toBe("sent early, delivered late");
    expect(() => decryptText(b, delayed)).toThrow(/failed authentication/);
  });

  it("rejects a header sealed by a stranger's session", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);
    const { state: mallory } = openSession(
      createDeviceIdentity(2).identity,
      bundleOf(createDeviceIdentity(2)),
    );
    const forged = decodeMessage(encryptText(mallory, "let me in"));
    const genuine = decodeMessage(encryptText(a, "genuine"));

    expect(() =>
      decryptText(b, encodeMessage({ ...genuine, encryptedHeader: forged.encryptedHeader })),
    ).toThrow(/failed authentication/);
    expect(decryptText(b, encodeMessage(genuine))).toBe("genuine");
  });

  it("refuses an absurd skip count instead of grinding through key derivations", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);
    decryptText(b, encryptText(a, "first"));
    // The counter is inside the sealed header now, so this cannot be forged from outside:
    // the sender genuinely runs far ahead, and the receiver refuses to catch up.
    let payload = "";
    for (let i = 0; i <= MAX_SKIP_PER_CHAIN + 1; i += 1) payload = encryptText(a, `m${i}`);
    expect(() => decryptText(b, payload)).toThrow(/too many skipped/);
  });

  it("a third party with the full bundle cannot read the conversation", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const mallory = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const payload = encryptText(a, "secret");
    // Mallory replays Alice's invite with her own identity keys: AD mismatch, no shared secret
    const malloryState = acceptSession(
      mallory.identity,
      mallory.signedPreKey,
      mallory.oneTimePreKeys[0]!,
      invite,
    );
    expect(() => decryptText(malloryState, payload)).toThrow();
  });

  it("survives serialization of session state (client vault round-trip)", () => {
    const alice = createDeviceIdentity(2);
    const bob = createDeviceIdentity(2);
    const { state: a, invite } = openSession(alice.identity, bundleOf(bob));
    const b = accept(bob, invite);
    decryptText(b, encryptText(a, "before reload"));

    const revivedA = deserializeState(JSON.parse(JSON.stringify(serializeState(a))));
    const revivedB = deserializeState(JSON.parse(JSON.stringify(serializeState(b))));
    expect(decryptText(revivedA, encryptText(revivedB, "after reload"))).toBe("after reload");
    expect(decryptText(revivedB, encryptText(revivedA, "and back"))).toBe("and back");
  });
});

describe("password derivation and vault", () => {
  it("splits the password into independent auth and vault halves", () => {
    const keys = deriveAccountKeys("Alice", "correct horse battery staple", FAST);
    expect(keys.authSecret.length).toBe(32);
    expect(keys.vaultKey.length).toBe(32);
    expect(toBase64Url(keys.authSecret)).not.toBe(toBase64Url(keys.vaultKey));
    // deterministic for the same inputs, and username-insensitive to case only
    const again = deriveAccountKeys("alice", "correct horse battery staple", FAST);
    expect(toBase64Url(again.authSecret)).toBe(toBase64Url(keys.authSecret));
    const other = deriveAccountKeys("alice2", "correct horse battery staple", FAST);
    expect(toBase64Url(other.authSecret)).not.toBe(toBase64Url(keys.authSecret));
    const wrongPassword = deriveAccountKeys("alice", "correct horse battery stapl", FAST);
    expect(toBase64Url(wrongPassword.vaultKey)).not.toBe(toBase64Url(keys.vaultKey));
  });

  it("seals and opens the vault, and rejects the wrong key", () => {
    const keys = deriveAccountKeys("alice", "pw-one", FAST);
    const wrong = deriveAccountKeys("alice", "pw-two", FAST);
    const secret = fromBase64Url(toBase64Url(createDeviceIdentity(1).identity.privateKey));
    const sealed = sealVault(keys.vaultKey, secret);
    expect(toBase64Url(openVault(keys.vaultKey, sealed))).toBe(toBase64Url(secret));
    expect(() => openVault(wrong.vaultKey, sealed)).toThrow();
  });
});
