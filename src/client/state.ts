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
  /** Local, random, never sent: what "delete this one" refers to on this device. */
  id?: string;
  from: string;
  text: string;
  at: number;
  mine: boolean;
  /** Disappearing messages: when this device drops it, agreed by the sender (point 74). */
  expiresAt?: number;
  /** Set on a message of mine when the peer chose to send a read receipt (point 77). */
  readAt?: number;
  /** An encrypted blob in blind storage, openable only with the key kept here. */
  attachment?: AttachmentRef;
}

/** Everything needed to fetch and open one attachment; the key exists only in vaults. */
export interface AttachmentRef {
  id: string;
  key: string;
  nonce: string;
  name: string;
  /** Plaintext size, for the label. The server sees only the padded ciphertext. */
  bytes: number;
}

export interface Conversation {
  channel: string;
  peer: string;
  messages: ChatMessage[];
  /** Ratchet state per remote device, plus our own view of the session. */
  sessions: Record<string, SerializedRatchetState>;
  /** Peer identity keys whose safety number the user compared, and when. */
  verifiedKeys?: Record<string, number>;
  /** Disappearing messages for this conversation: hours, or null for "keep". */
  disappearHours?: number | null;
  /** The peer has told us they read everything up to this timestamp (point 77). */
  readUpTo?: number;
}

/**
 * Metadata the product could emit and does not, unless asked (points 75-77).
 *
 * Every one of these is off by default, and every one of them is a message between two
 * clients rather than a column on the server — which is also why these settings live in the
 * vault: a preference stored server-side would itself be metadata ("this account cares
 * about read receipts"), and a preference the server enforces is a preference the server
 * can read.
 */
export interface PrivacySettings {
  /** Tell a peer when their messages were read. */
  readReceipts: boolean;
  /** Tell a peer that you are typing. Costs one envelope per burst — see docs/METADATA.md. */
  typingIndicators: boolean;
  /** Default disappearing-message lifetime for new conversations, in hours. */
  disappearHours: number | null;
  /**
   * Ask the server to hold each envelope for a random quarter to two minutes before it can
   * be fetched (ADR-0085). It breaks the send/fetch timing correlation and costs immediacy,
   * which is why it is a choice and not a default.
   */
  delayDelivery: boolean;
}

export const DEFAULT_PRIVACY: PrivacySettings = {
  readReceipts: false,
  typingIndicators: false,
  disappearHours: null,
  delayDelivery: false,
};

/**
 * The key to one delivered file, received over the encrypted channel and kept in the
 * vault — never on the server, which is the whole point of the feature.
 */
export interface DeliveryKey {
  key: string;
  nonce: string;
  name: string;
  /** How to present the plaintext: save a file, or show text. Absent on older keys: a file. */
  kind?: "file" | "text";
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
  /** Shipping details a buyer sent us, by order id. Never uploaded anywhere. */
  shipments?: Record<string, { text: string; at: number }>;
  /** True on a device that was linked rather than signed in: it does not own the backup. */
  linked?: boolean;
  /** Absent on vaults written before the settings existed: the defaults apply. */
  privacy?: Partial<PrivacySettings>;
  /** Usernames whose messages this device discards on arrival (point 84). */
  blocked?: string[];
  /**
   * Unspent sealed-sender tokens (ADR-0084). They live in the vault because the vault is
   * the one place this client keeps secrets, and they are worth exactly one envelope each.
   */
  sendTokens?: string[];
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

/**
 * Everything that must exist before the first real render. Takes the crypto load already
 * in flight (started by the entry module before painting) so the two overlap instead of
 * queueing.
 */
export async function ready(crypto: Promise<unknown> = sodiumReady()): Promise<void> {
  await crypto;
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
 * Rotates this device's signed prekey when the server says it is old (ADR-0078).
 *
 * `publishDevice` has always rotated a stale key, but it only runs at sign-in, so a browser
 * left signed in for months kept one signed prekey for months — the compromise of that one
 * key would decrypt the first message of every conversation started in that window. This is
 * the same rotation, triggered from a live session, and it is best-effort on purpose: a
 * network failure here must never look like a broken account.
 */
export async function rotateStaleKeys(): Promise<boolean> {
  if (!state.vault) return false;
  try {
    const status = await api<{ devices: Array<{ deviceId: string; signedPreKeyStale: boolean }> }>(
      "/api/keys/status",
    );
    const mine = status.devices.find((device) => device.deviceId === state.vault?.deviceId);
    if (!mine?.signedPreKeyStale) return false;
    // The private half never leaves this browser: rotation is a new key pair here and a new
    // public key published, exactly as at sign-in.
    await publishDevice();
    await persistVault();
    return true;
  } catch {
    return false;
  }
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

/** The settings as they actually apply: stored values over `DEFAULT_PRIVACY`. */
export function privacySettings(): PrivacySettings {
  return { ...DEFAULT_PRIVACY, ...(state.vault?.privacy ?? {}) };
}

export async function setPrivacy(patch: Partial<PrivacySettings>): Promise<void> {
  if (!state.vault) throw new Error("unlock the vault first");
  state.vault.privacy = { ...privacySettings(), ...patch };
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
