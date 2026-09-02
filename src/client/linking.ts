/**
 * Linking a second browser to an account.
 *
 * Each device keeps its own cryptographic identity — sharing one identity across browsers
 * would mean two copies of the same ratchet advancing independently, which breaks
 * conversations. So the new device generates its own keys, and an already-signed-in device
 * vouches for them.
 *
 * The code the new device shows carries its public bundle and a one-time secret. The
 * trusted device publishes the bundle (it is authenticated, the new device is not), then
 * parks an authorisation under SHA-256 of the secret; the new device redeems it for a
 * session. Both screens display the same fingerprint of the identity key, so the person
 * doing the linking can see that what arrived is what was sent.
 *
 * What linking does *not* do: move history. Messages live only on the device that
 * received them, and the server holds no plaintext to replay. A linked device starts
 * empty and receives everything sent from that moment on.
 */
import { api } from "./api.ts";
import { createDeviceIdentity, signSignedPreKey, type DeviceIdentity } from "../shared/crypto/identity.ts";
import { randomBytes, sodium } from "../shared/crypto/sodium.ts";
import { fromBase64Url, toBase64Url } from "../shared/encoding.ts";

const PREFIX = "symvolon-link.v1";

export interface DeviceCode {
  code: string;
  fingerprint: string;
  secret: Uint8Array;
  identity: DeviceIdentity;
}

/** Human-comparable digest of an identity key: four groups, uppercase hex. */
export function fingerprintOf(identityKey: Uint8Array): string {
  const digest = sodium().crypto_hash_sha256(identityKey).subarray(0, 8);
  return (
    [...digest]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase()
      .match(/.{4}/g) ?? []
  ).join(" ");
}

/** New device: generate an identity and the code to read out to the trusted device. */
export function newDeviceCode(): DeviceCode {
  const identity = createDeviceIdentity(0); // one-time prekeys are added once we have a session
  const signature =
    identity.signedPreKeySignature.length > 0
      ? identity.signedPreKeySignature
      : signSignedPreKey(identity.identity, identity.signedPreKey);
  const secret = randomBytes(32);
  const code = [
    PREFIX,
    toBase64Url(secret),
    toBase64Url(identity.identity.publicKey),
    String(identity.signedPreKey.keyId),
    toBase64Url(identity.signedPreKey.keyPair.publicKey),
    toBase64Url(signature),
  ].join(".");
  return { code, fingerprint: fingerprintOf(identity.identity.publicKey), secret, identity };
}

export interface ParsedDeviceCode {
  secret: Uint8Array;
  identityKey: string;
  signedPreKeyId: number;
  signedPreKey: string;
  signedPreKeySignature: string;
  fingerprint: string;
}

/** Trusted device: read a code. Throws on anything that is not exactly our format. */
export function parseDeviceCode(input: string): ParsedDeviceCode {
  const parts = input.trim().split(".");
  if (parts.length !== 6 || parts[0] !== PREFIX) throw new Error("that is not a device code");
  const [, secret, identityKey, keyId, signedPreKey, signature] = parts as [
    string, string, string, string, string, string,
  ];
  const keyIdNumber = Number(keyId);
  if (!Number.isInteger(keyIdNumber) || keyIdNumber < 0) throw new Error("device code is damaged");
  const secretBytes = fromBase64Url(secret);
  const identityBytes = fromBase64Url(identityKey);
  if (secretBytes.length !== 32 || identityBytes.length !== 32) {
    throw new Error("device code is damaged");
  }
  return {
    secret: secretBytes,
    identityKey,
    signedPreKeyId: keyIdNumber,
    signedPreKey,
    signedPreKeySignature: signature,
    fingerprint: fingerprintOf(identityBytes),
  };
}

/** Trusted device: publish the new device's bundle, then authorise one claim of it. */
export async function authoriseDevice(parsed: ParsedDeviceCode, label: string): Promise<void> {
  await api("/api/keys/device", {
    method: "POST",
    body: {
      label,
      identityKey: parsed.identityKey,
      signedPreKeyId: parsed.signedPreKeyId,
      signedPreKey: parsed.signedPreKey,
      signedPreKeySignature: parsed.signedPreKeySignature,
      oneTimePreKeys: [],
    },
  });
  await api("/api/auth/link", {
    method: "POST",
    body: { linkHash: toBase64Url(sodium().crypto_hash_sha256(parsed.secret)), label },
  });
}

export interface ClaimedAccount {
  id: string;
  username: string;
  role: "user" | "moderator" | "admin";
}

/** New device: try to redeem the authorisation. Returns null while it does not exist yet. */
export async function claimDeviceLink(secret: Uint8Array): Promise<ClaimedAccount | null> {
  try {
    return await api<ClaimedAccount>("/api/auth/link/claim", {
      method: "POST",
      body: { linkSecret: toBase64Url(secret) },
    });
  } catch {
    // 401 until the other device authorises; anything else is also worth retrying once.
    return null;
  }
}
