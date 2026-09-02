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
import {
  deriveAccountKeys,
  generateMasterKey,
  openVault,
  sealVault,
  unwrapMasterKey,
  wrapMasterKey,
  type KeyEnvelope,
  type SealedVault,
  type VaultBackup,
} from "../shared/crypto/vault.ts";
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

/**
 * The key to one delivered file, received over the encrypted channel and kept in the
 * vault — never on the server, which is the whole point of the feature.
 */
export interface DeliveryKey {
  key: string;
  nonce: string;
  name: string;
  at: number;
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
  /** Delivery keys by order id. Absent on vaults written before deliveries existed. */
  deliveries?: Record<string, DeliveryKey>;
  /** True on a device that was linked rather than signed in: it does not own the backup. */
  linked?: boolean;
}

export interface Account {
  id: string;
  username: string;
  role: "user" | "moderator" | "admin";
}

const STORAGE_KEY = "symvolon.vault.v2";

export const state: {
  account: Account | null;
  /** The key that seals the vault. Random, unwrapped at unlock, never derived directly. */
  masterKey: Uint8Array | null;
  vault: VaultContents | null;
  /** The wrapped copies as last written, so a rewrap keeps the one it is not touching. */
  envelopes: { password: KeyEnvelope; recovery?: KeyEnvelope | null } | null;
} = { account: null, masterKey: null, vault: null, envelopes: null };

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

/**
 * Open a backup with a wrapping key: unwrap the master key, then the vault. Which
 * envelope is used decides what the caller had to know — a password or a phrase.
 */
export function unlockBackup(
  wrapKey: Uint8Array,
  backup: VaultBackup,
  route: "password" | "recovery" = "password",
): { vault: VaultContents; masterKey: Uint8Array } {
  const envelope = route === "password" ? backup.password : backup.recovery;
  if (!envelope) throw new Error("this backup has no recovery copy of its keys");
  const masterKey = unwrapMasterKey(wrapKey, envelope);
  return {
    vault: JSON.parse(fromUtf8(openVault(masterKey, backup.vault))) as VaultContents,
    masterKey,
  };
}

function currentBackup(): VaultBackup {
  if (!state.masterKey || !state.vault || !state.envelopes) throw new Error("vault is locked");
  return {
    v: 3,
    vault: sealVault(state.masterKey, utf8(JSON.stringify(state.vault))),
    password: state.envelopes.password,
    recovery: state.envelopes.recovery ?? null,
  };
}

/** The current vault, sealed under the current master key. Used when rewrapping keys. */
export function sealedVaultNow(): SealedVault {
  if (!state.masterKey || !state.vault) throw new Error("vault is locked");
  return sealVault(state.masterKey, utf8(JSON.stringify(state.vault)));
}

/** Start a brand-new vault: a random master key, wrapped for each route we were given. */
export function initialiseVault(
  vault: VaultContents,
  wrapKeys: { password: Uint8Array; recovery?: Uint8Array | null },
): void {
  const masterKey = generateMasterKey();
  state.vault = vault;
  state.masterKey = masterKey;
  state.envelopes = {
    password: wrapMasterKey(wrapKeys.password, masterKey),
    recovery: wrapKeys.recovery ? wrapMasterKey(wrapKeys.recovery, masterKey) : null,
  };
}

/**
 * Persist locally and back the sealed blob up to the server, which cannot read it.
 *
 * A linked device never uploads: the account has one sealed backup, it belongs to the
 * device that knows the account password, and overwriting it with a different device's
 * vault would destroy the only copy of that device's keys.
 */
export async function persistVault(sync = true): Promise<void> {
  if (!state.vault || !state.masterKey || !state.envelopes) return;
  const backup = currentBackup();
  localStorage.setItem(STORAGE_KEY, JSON.stringify(backup));
  if (sync && !state.vault.linked) {
    await api("/api/keys/vault", { method: "PUT", body: { sealedVault: backup } }).catch(() => {
      /* offline or rate-limited: the local copy is authoritative anyway */
    });
  }
}

export function localSealedVault(): VaultBackup | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  const parsed = JSON.parse(raw) as VaultBackup;
  return parsed.v === 3 ? parsed : null;
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
  state.masterKey?.fill(0);
  state.masterKey = null;
  state.vault = null;
  state.account = null;
  state.envelopes = null;
}

/**
 * Change the password. Both halves move together: the server gets the new auth secret and
 * the vault re-sealed under the new vault key in one request, because a password that
 * authenticates but no longer opens the vault is worse than no change at all.
 */
/**
 * Change the password. Only the password-wrapped copy of the master key is rewrapped —
 * 32 bytes — so the vault, the recovery copy and every session key stay exactly as they
 * are. The recovery phrase keeps working, which is the point of the indirection.
 */
export async function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  if (!state.account || !state.vault || !state.masterKey || !state.envelopes) {
    throw new Error("unlock the vault first");
  }
  const current = deriveAccountKeys(state.account.username, currentPassword);
  const next = deriveAccountKeys(state.account.username, newPassword);
  // Prove the current password locally too: the server checks the auth secret, but only
  // the wrap key can open the envelope, and a mismatch here means a corrupt backup.
  unwrapMasterKey(current.wrapKey, state.envelopes.password).fill(0);

  state.envelopes = {
    password: wrapMasterKey(next.wrapKey, state.masterKey),
    recovery: state.envelopes.recovery ?? null,
  };
  const backup = currentBackup();
  await api("/api/auth/password", {
    method: "POST",
    body: {
      currentAuthSecret: toBase64Url(current.authSecret),
      newAuthSecret: toBase64Url(next.authSecret),
      sealedVault: backup,
    },
  });
  current.authSecret.fill(0);
  current.wrapKey.fill(0);
  next.wrapKey.fill(0);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(backup));
}

/** Delete the account server-side, then leave nothing behind in this browser. */
export async function deleteAccount(password: string): Promise<void> {
  if (!state.account) throw new Error("not signed in");
  const keys = deriveAccountKeys(state.account.username, password);
  await api("/api/auth/delete", {
    method: "POST",
    body: { authSecret: toBase64Url(keys.authSecret) },
  });
  keys.authSecret.fill(0);
  keys.wrapKey.fill(0);
  forgetLocalVault();
  lock();
}

/**
 * New device, after its bundle was authorised elsewhere: build a local vault around the
 * identity it generated, then publish its one-time prekeys with the session it just got.
 *
 * The device password protects this browser's vault only. It is never sent anywhere and
 * does not have to match the account password — this device cannot open the account's
 * sealed backup and does not need to.
 */
export async function adoptLinkedIdentity(
  account: Account,
  identity: DeviceIdentity,
  devicePassword: string,
): Promise<void> {
  const keys = deriveAccountKeys(account.username, devicePassword);
  keys.authSecret.fill(0);
  state.account = account;
  initialiseVault(
    { identity: encodeIdentity(identity), deviceId: null, conversations: {}, linked: true },
    { password: keys.wrapKey },
  );
  await publishDevice("linked device");
}
