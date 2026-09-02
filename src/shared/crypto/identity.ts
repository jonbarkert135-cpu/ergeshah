/**
 * Cryptographic identity, deliberately separate from account identity.
 *
 * A device owns one long-term Ed25519 identity key. Its X25519 counterpart (used for
 * Diffie-Hellman) is derived from the same key with libsodium's standard
 * ed25519 -> curve25519 conversion, so a device cannot present two unrelated identities.
 *
 * Losing the account password does not expose these keys: they live in the client vault,
 * encrypted with a key the server never receives (see `vault.ts`).
 */
import { fromBase64Url, toBase64Url, utf8 } from "../encoding.ts";
import { sodium } from "./sodium.ts";

const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
const SPK_SIGNATURE_CONTEXT = utf8("ergeshah-signed-prekey-v1");

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface PreKey {
  keyId: number;
  keyPair: KeyPair;
}

export interface DeviceIdentity {
  /** Ed25519 signing keypair — the device's long-term identity. */
  identity: KeyPair;
  signedPreKey: PreKey;
  signedPreKeySignature: Uint8Array;
  signedPreKeyCreatedAt: number;
  oneTimePreKeys: PreKey[];
}

/** Public half of an identity, as published to the server. */
export interface PreKeyBundle {
  identityKey: string;
  signedPreKeyId: number;
  signedPreKey: string;
  signedPreKeySignature: string;
  oneTimePreKeyId?: number | null;
  oneTimePreKey?: string | null;
}

export function generateX25519KeyPair(): KeyPair {
  const s = sodium();
  const pair = s.crypto_kx_keypair();
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return sodium().crypto_scalarmult(privateKey, publicKey);
}

export function identityToX25519Public(ed25519PublicKey: Uint8Array): Uint8Array {
  return sodium().crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKey);
}

export function identityToX25519Private(ed25519PrivateKey: Uint8Array): Uint8Array {
  return sodium().crypto_sign_ed25519_sk_to_curve25519(ed25519PrivateKey);
}

function signedPreKeyMessage(publicKey: Uint8Array, keyId: number): Uint8Array {
  const idBytes = new Uint8Array(4);
  new DataView(idBytes.buffer).setUint32(0, keyId, false);
  const out = new Uint8Array(SPK_SIGNATURE_CONTEXT.length + publicKey.length + 4);
  out.set(SPK_SIGNATURE_CONTEXT, 0);
  out.set(publicKey, SPK_SIGNATURE_CONTEXT.length);
  out.set(idBytes, SPK_SIGNATURE_CONTEXT.length + publicKey.length);
  return out;
}

export function signSignedPreKey(identity: KeyPair, preKey: PreKey): Uint8Array {
  return sodium().crypto_sign_detached(
    signedPreKeyMessage(preKey.keyPair.publicKey, preKey.keyId),
    identity.privateKey,
  );
}

export function verifySignedPreKey(
  identityPublicKey: Uint8Array,
  signedPreKey: Uint8Array,
  keyId: number,
  signature: Uint8Array,
): boolean {
  try {
    return sodium().crypto_sign_verify_detached(
      signature,
      signedPreKeyMessage(signedPreKey, keyId),
      identityPublicKey,
    );
  } catch {
    return false;
  }
}

export function createDeviceIdentity(oneTimePreKeyCount = 64): DeviceIdentity {
  const s = sodium();
  const signing = s.crypto_sign_keypair();
  const identity: KeyPair = { publicKey: signing.publicKey, privateKey: signing.privateKey };
  const signedPreKey: PreKey = { keyId: randomKeyId(), keyPair: generateX25519KeyPair() };
  return {
    identity,
    signedPreKey,
    signedPreKeySignature: signSignedPreKey(identity, signedPreKey),
    signedPreKeyCreatedAt: Date.now(),
    oneTimePreKeys: generateOneTimePreKeys(oneTimePreKeyCount),
  };
}

export function generateOneTimePreKeys(count: number): PreKey[] {
  const keys: PreKey[] = [];
  const seen = new Set<number>();
  while (keys.length < count) {
    const keyId = randomKeyId();
    if (seen.has(keyId)) continue;
    seen.add(keyId);
    keys.push({ keyId, keyPair: generateX25519KeyPair() });
  }
  return keys;
}

/** Rotates the signed prekey; callers publish the result and keep the old key briefly. */
export function rotateSignedPreKey(identity: DeviceIdentity): DeviceIdentity {
  const signedPreKey: PreKey = { keyId: randomKeyId(), keyPair: generateX25519KeyPair() };
  return {
    ...identity,
    signedPreKey,
    signedPreKeySignature: signSignedPreKey(identity.identity, signedPreKey),
    signedPreKeyCreatedAt: Date.now(),
  };
}

export function signedPreKeyNeedsRotation(identity: DeviceIdentity, now = Date.now()): boolean {
  return now - identity.signedPreKeyCreatedAt >= SIGNED_PREKEY_ROTATION_MS;
}

function randomKeyId(): number {
  const bytes = sodium().randombytes_buf(4);
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false) & 0x7fffffff;
}

/**
 * Short human-verifiable fingerprint of two identities, order-independent, so both sides
 * of a conversation read the same words when they verify each other out of band.
 */
export function safetyNumber(a: Uint8Array, b: Uint8Array): string {
  const s = sodium();
  const [first, second] = toBase64Url(a) < toBase64Url(b) ? [a, b] : [b, a];
  const digest = s.crypto_generichash(30, new Uint8Array([...first, ...second]));
  return (
    toBase64Url(digest)
      .slice(0, 40)
      .match(/.{1,8}/g) ?? []
  ).join(" ");
}

export const encodeKey = toBase64Url;
export const decodeKey = fromBase64Url;
