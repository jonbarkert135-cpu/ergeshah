/**
 * Client state and the encrypted local vault.
 *
 * Everything sensitive — identity keys, prekeys, ratchet state, message history — lives
 * in one object that is only ever written to disk (localStorage) and to the server in
 * sealed form. The vault key is derived from the password, kept in memory, and dropped
 * on logout or reload: a stolen device without the password yields ciphertext.
 */
import { api } from "./api.ts";
import { sodiumReady } from "../shared/crypto/sodium.ts";
import { deriveAccountKeys, openVault, sealVault, type SealedVault } from "../shared/crypto/vault.ts";
import {
  createDeviceIdentity,
  generateOneTimePreKeys,
  rotateSignedPreKey,
  signSignedPreKey,
  signedPreKeyNeedsRotation,
  type DeviceIdentity,
} from "../shared/crypto/identity.ts";
import { fromBase64Url, toBase64Url, utf8, fromUtf8 } from "../shared/encoding.ts";
import type { SerializedRatchetState } from "../shared/crypto/ratchet.ts";

export interface ChatMessage {
  from: string;
  text: string;
  at: number;
  mine: boolean;
}

export interface Conversation {
  channel: string;
  peer: string;
  messages: ChatMessage[];
  /** Ratchet state per remote device, plus our own view of the session. */
  sessions: Record<string, SerializedRatchetState>;
}

export interface VaultContents {
  identity: {
    identity: { publicKey: string; privateKey: string };
    signedPreKey: { keyId: number; publicKey: string; privateKey: string };
    signedPreKeySignature: string;
    signedPreKeyCreatedAt: number;
    oneTimePreKeys: Array<{ keyId: number; publicKey: string; privateKey: string }>;
  };
  deviceId: string | null;
  conversations: Record<string, Conversation>;
}

export interface Account {
  id: string;
  username: string;
  role: "user" | "moderator" | "admin";
}

const STORAGE_KEY = "ergeshah.vault.v2";

export const state: {
  account: Account | null;
  vaultKey: Uint8Array | null;
  vault: VaultContents | null;
} = { account: null, vaultKey: null, vault: null };

export async function ready(): Promise<void> {
  await sodiumReady();
}

export function encodeIdentity(identity: DeviceIdentity): VaultContents["identity"] {
  return {
    identity: {
      publicKey: toBase64Url(identity.identity.publicKey),
      privateKey: toBase64Url(identity.identity.privateKey),
    },
    signedPreKey: {
      keyId: identity.signedPreKey.keyId,
      publicKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
      privateKey: toBase64Url(identity.signedPreKey.keyPair.privateKey),
    },
    signedPreKeySignature: toBase64Url(identity.signedPreKeySignature),
    signedPreKeyCreatedAt: identity.signedPreKeyCreatedAt,
    oneTimePreKeys: identity.oneTimePreKeys.map((key) => ({
      keyId: key.keyId,
      publicKey: toBase64Url(key.keyPair.publicKey),
      privateKey: toBase64Url(key.keyPair.privateKey),
    })),
  };
}

export function decodeIdentity(stored: VaultContents["identity"]): DeviceIdentity {
  return {
    identity: {
      publicKey: fromBase64Url(stored.identity.publicKey),
      privateKey: fromBase64Url(stored.identity.privateKey),
    },
    signedPreKey: {
      keyId: stored.signedPreKey.keyId,
      keyPair: {
        publicKey: fromBase64Url(stored.signedPreKey.publicKey),
        privateKey: fromBase64Url(stored.signedPreKey.privateKey),
      },
    },
    signedPreKeySignature: fromBase64Url(stored.signedPreKeySignature),
    signedPreKeyCreatedAt: stored.signedPreKeyCreatedAt,
    oneTimePreKeys: stored.oneTimePreKeys.map((key) => ({
      keyId: key.keyId,
      keyPair: {
        publicKey: fromBase64Url(key.publicKey),
        privateKey: fromBase64Url(key.privateKey),
      },
    })),
  };
}

export function newVault(): VaultContents {
  return { identity: encodeIdentity(createDeviceIdentity(64)), deviceId: null, conversations: {} };
}

export function deriveKeys(username: string, password: string) {
  return deriveAccountKeys(username, password);
}

export function unlockVault(vaultKey: Uint8Array, sealed: SealedVault): VaultContents {
  return JSON.parse(fromUtf8(openVault(vaultKey, sealed))) as VaultContents;
}

export function sealCurrentVault(): SealedVault {
  if (!state.vaultKey || !state.vault) throw new Error("vault is locked");
  return sealVault(state.vaultKey, utf8(JSON.stringify(state.vault)));
}

/** Persist locally and back the sealed blob up to the server, which cannot read it. */
export async function persistVault(sync = true): Promise<void> {
  if (!state.vault || !state.vaultKey) return;
  const sealed = sealCurrentVault();
  localStorage.setItem(STORAGE_KEY, JSON.stringify(sealed));
  if (sync) {
    await api("/api/keys/vault", { method: "PUT", body: { sealedVault: sealed } }).catch(() => {
      /* offline or rate-limited: the local copy is authoritative anyway */
    });
  }
}

export function localSealedVault(): SealedVault | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? (JSON.parse(raw) as SealedVault) : null;
}

export function forgetLocalVault(): void {
  localStorage.removeItem(STORAGE_KEY);
}

/**
 * Publishes this device's public key material and tops up one-time prekeys when the
 * server reports that they are running out (each one is used exactly once).
 */
export async function publishDevice(label: string | null = null): Promise<void> {
  if (!state.vault) throw new Error("vault is locked");
  let identity = decodeIdentity(state.vault.identity);
  if (signedPreKeyNeedsRotation(identity)) {
    identity = rotateSignedPreKey(identity);
    state.vault.identity = encodeIdentity(identity);
  }
  const response = await api<{ deviceId: string; oneTimePreKeysStored: number }>(
    "/api/keys/device",
    {
      method: "POST",
      body: {
        label,
        identityKey: toBase64Url(identity.identity.publicKey),
        signedPreKeyId: identity.signedPreKey.keyId,
        signedPreKey: toBase64Url(identity.signedPreKey.keyPair.publicKey),
        signedPreKeySignature: toBase64Url(
          identity.signedPreKeySignature.length > 0
            ? identity.signedPreKeySignature
            : signSignedPreKey(identity.identity, identity.signedPreKey),
        ),
        oneTimePreKeys: identity.oneTimePreKeys.map((key) => ({
          keyId: key.keyId,
          publicKey: toBase64Url(key.keyPair.publicKey),
        })),
      },
    },
  );
  state.vault.deviceId = response.deviceId;

  if (response.oneTimePreKeysStored < 16) {
    const fresh = generateOneTimePreKeys(48);
    identity.oneTimePreKeys.push(...fresh);
    state.vault.identity = encodeIdentity(identity);
    await api("/api/keys/one-time", {
      method: "POST",
      body: {
        deviceId: response.deviceId,
        oneTimePreKeys: fresh.map((key) => ({
          keyId: key.keyId,
          publicKey: toBase64Url(key.keyPair.publicKey),
        })),
      },
    });
  }
  await persistVault();
}

export function lock(): void {
  state.vaultKey?.fill(0);
  state.vaultKey = null;
  state.vault = null;
  state.account = null;
}
