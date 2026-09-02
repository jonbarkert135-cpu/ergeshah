/**
 * Double Ratchet (Signal specification, rev. 1, 2016) over X25519 / HKDF-SHA256 /
 * XChaCha20-Poly1305.
 *
 * Guarantees, inherited from the specification and exercised by `test/ratchet.test.ts`:
 *  - a message key is derived, used once and destroyed (forward secrecy inside a chain);
 *  - every DH ratchet step re-keys the session (post-compromise security);
 *  - out-of-order and dropped messages are handled through bounded skipped-key storage;
 *  - replays and tampered headers fail authentication (header is part of the AAD).
 *
 * The header itself (ratchet public key, chain length, counter) is *not* encrypted in
 * this version — see `docs/CRYPTO.md` "Known limitations" and ROADMAP item PQ-2.
 */
import { concat, fromBase64Url, toBase64Url, utf8 } from "../encoding.ts";
import { aeadDecrypt, aeadEncrypt } from "./aead.ts";
import { hkdf, hmacSha256 } from "./hkdf.ts";
import { dh, generateX25519KeyPair, type KeyPair } from "./identity.ts";

const ROOT_INFO = utf8("ergeshah-root-v1");
const MESSAGE_INFO = utf8("ergeshah-message-key-v1");
const ZERO_SALT = new Uint8Array(32);
const CHAIN_MESSAGE_CONSTANT = Uint8Array.of(0x01);
const CHAIN_NEXT_CONSTANT = Uint8Array.of(0x02);

export const MAX_SKIP_PER_CHAIN = 1000;
export const MAX_STORED_SKIPPED_KEYS = 2000;

export interface MessageHeader {
  /** Sender's current ratchet public key. */
  dh: Uint8Array;
  /** Number of messages in the previous sending chain. */
  pn: number;
  /** Message number in the current sending chain. */
  n: number;
}

export interface RatchetMessage {
  header: MessageHeader;
  ciphertext: Uint8Array;
}

export interface RatchetState {
  self: KeyPair;
  remote: Uint8Array | null;
  rootKey: Uint8Array;
  sendChainKey: Uint8Array | null;
  receiveChainKey: Uint8Array | null;
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  skipped: Map<string, Uint8Array>;
  associatedData: Uint8Array;
}

function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const derived = hkdf(dhOutput, rootKey, ROOT_INFO, 64);
  return [derived.slice(0, 32), derived.slice(32, 64)];
}

function kdfChainKey(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  return [
    hmacSha256(chainKey, CHAIN_MESSAGE_CONSTANT),
    hmacSha256(chainKey, CHAIN_NEXT_CONSTANT),
  ];
}

function messageKeyMaterial(messageKey: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const derived = hkdf(messageKey, ZERO_SALT, MESSAGE_INFO, 56);
  return { key: derived.slice(0, 32), nonce: derived.slice(32, 56) };
}

export function serializeHeader(header: MessageHeader): Uint8Array {
  const meta = new Uint8Array(8);
  const view = new DataView(meta.buffer);
  view.setUint32(0, header.pn, false);
  view.setUint32(4, header.n, false);
  return concat(header.dh, meta);
}

function skippedKeyId(remote: Uint8Array, counter: number): string {
  return `${toBase64Url(remote)}:${counter}`;
}

/** Initiator side: knows the responder's signed prekey public and starts sending. */
export function initiateSession(
  sharedSecret: Uint8Array,
  remoteSignedPreKey: Uint8Array,
  associatedData: Uint8Array,
): RatchetState {
  const self = generateX25519KeyPair();
  const [rootKey, sendChainKey] = kdfRootKey(sharedSecret, dh(self.privateKey, remoteSignedPreKey));
  return {
    self,
    remote: remoteSignedPreKey,
    rootKey,
    sendChainKey,
    receiveChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skipped: new Map(),
    associatedData,
  };
}

/** Responder side: its signed prekey pair is the first ratchet key. */
export function acceptSession(
  sharedSecret: Uint8Array,
  signedPreKeyPair: KeyPair,
  associatedData: Uint8Array,
): RatchetState {
  return {
    self: signedPreKeyPair,
    remote: null,
    // copy: the caller wipes its own copy of the shared secret right after this call
    rootKey: new Uint8Array(sharedSecret),
    sendChainKey: null,
    receiveChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skipped: new Map(),
    associatedData,
  };
}

export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): RatchetMessage {
  if (!state.sendChainKey) {
    throw new Error("ratchet: no sending chain — receive a message before replying");
  }
  const [messageKey, nextChainKey] = kdfChainKey(state.sendChainKey);
  state.sendChainKey = nextChainKey;

  const header: MessageHeader = {
    dh: state.self.publicKey,
    pn: state.previousSendCount,
    n: state.sendCount,
  };
  state.sendCount += 1;

  const { key, nonce } = messageKeyMaterial(messageKey);
  const ciphertext = aeadEncrypt(
    key,
    plaintext,
    concat(state.associatedData, serializeHeader(header)),
    nonce,
  );
  messageKey.fill(0);
  key.fill(0);
  return { header, ciphertext };
}

/**
 * Decryption never mutates the live session until the message has been authenticated:
 * we ratchet a copy and commit it only on success. Without this, anyone who can post an
 * envelope could desynchronise a session with a forged header — cheap denial of service
 * against a conversation, and a trap the naive reading of the specification walks into.
 */
export function ratchetDecrypt(state: RatchetState, message: RatchetMessage): Uint8Array {
  const working = cloneState(state);
  const plaintext = decryptInto(working, message);
  commitState(state, working);
  return plaintext;
}

function decryptInto(state: RatchetState, message: RatchetMessage): Uint8Array {
  const skippedPlaintext = trySkippedKeys(state, message);
  if (skippedPlaintext) return skippedPlaintext;

  const isNewRatchetKey =
    !state.remote || toBase64Url(state.remote) !== toBase64Url(message.header.dh);

  if (isNewRatchetKey) {
    skipMessageKeys(state, message.header.pn);
    performDhRatchet(state, message.header.dh);
  }

  skipMessageKeys(state, message.header.n);

  if (!state.receiveChainKey) throw new Error("ratchet: no receiving chain");
  const [messageKey, nextChainKey] = kdfChainKey(state.receiveChainKey);
  state.receiveChainKey = nextChainKey;
  state.receiveCount += 1;
  return decryptWithMessageKey(state, message, messageKey);
}

function cloneState(state: RatchetState): RatchetState {
  return {
    self: {
      publicKey: new Uint8Array(state.self.publicKey),
      privateKey: new Uint8Array(state.self.privateKey),
    },
    remote: state.remote ? new Uint8Array(state.remote) : null,
    rootKey: new Uint8Array(state.rootKey),
    sendChainKey: state.sendChainKey ? new Uint8Array(state.sendChainKey) : null,
    receiveChainKey: state.receiveChainKey ? new Uint8Array(state.receiveChainKey) : null,
    sendCount: state.sendCount,
    receiveCount: state.receiveCount,
    previousSendCount: state.previousSendCount,
    skipped: new Map([...state.skipped].map(([id, key]) => [id, new Uint8Array(key)])),
    associatedData: state.associatedData,
  };
}

function commitState(target: RatchetState, source: RatchetState): void {
  target.self = source.self;
  target.remote = source.remote;
  target.rootKey = source.rootKey;
  target.sendChainKey = source.sendChainKey;
  target.receiveChainKey = source.receiveChainKey;
  target.sendCount = source.sendCount;
  target.receiveCount = source.receiveCount;
  target.previousSendCount = source.previousSendCount;
  target.skipped = source.skipped;
}

function decryptWithMessageKey(
  state: RatchetState,
  message: RatchetMessage,
  messageKey: Uint8Array,
): Uint8Array {
  const { key, nonce } = messageKeyMaterial(messageKey);
  try {
    return aeadDecrypt(
      key,
      message.ciphertext,
      concat(state.associatedData, serializeHeader(message.header)),
      nonce,
    );
  } catch {
    throw new Error("ratchet: message failed authentication (tampered, replayed or foreign)");
  } finally {
    messageKey.fill(0);
    key.fill(0);
  }
}

function trySkippedKeys(state: RatchetState, message: RatchetMessage): Uint8Array | null {
  const id = skippedKeyId(message.header.dh, message.header.n);
  const messageKey = state.skipped.get(id);
  if (!messageKey) return null;
  const plaintext = decryptWithMessageKey(state, message, messageKey);
  state.skipped.delete(id); // one-time use: a replay of the same message now fails
  return plaintext;
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (!state.receiveChainKey || !state.remote) return;
  if (until - state.receiveCount > MAX_SKIP_PER_CHAIN) {
    throw new Error("ratchet: too many skipped messages — refusing to derive keys");
  }
  while (state.receiveCount < until) {
    const [messageKey, nextChainKey] = kdfChainKey(state.receiveChainKey);
    state.receiveChainKey = nextChainKey;
    state.skipped.set(skippedKeyId(state.remote, state.receiveCount), messageKey);
    state.receiveCount += 1;
    pruneSkipped(state);
  }
}

function pruneSkipped(state: RatchetState): void {
  while (state.skipped.size > MAX_STORED_SKIPPED_KEYS) {
    const oldest = state.skipped.keys().next();
    if (oldest.done) return;
    const key = state.skipped.get(oldest.value);
    key?.fill(0);
    state.skipped.delete(oldest.value);
  }
}

function performDhRatchet(state: RatchetState, remotePublicKey: Uint8Array): void {
  state.previousSendCount = state.sendCount;
  state.sendCount = 0;
  state.receiveCount = 0;
  state.remote = remotePublicKey;

  const [rootKeyAfterReceive, receiveChainKey] = kdfRootKey(
    state.rootKey,
    dh(state.self.privateKey, remotePublicKey),
  );
  state.rootKey = rootKeyAfterReceive;
  state.receiveChainKey = receiveChainKey;

  state.self = generateX25519KeyPair();
  const [rootKeyAfterSend, sendChainKey] = kdfRootKey(
    state.rootKey,
    dh(state.self.privateKey, remotePublicKey),
  );
  state.rootKey = rootKeyAfterSend;
  state.sendChainKey = sendChainKey;
}

/* ---------- persistence (the client stores this inside its encrypted vault) ---------- */

export interface SerializedRatchetState {
  self: { publicKey: string; privateKey: string };
  remote: string | null;
  rootKey: string;
  sendChainKey: string | null;
  receiveChainKey: string | null;
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  skipped: Array<[string, string]>;
  associatedData: string;
}

export function serializeState(state: RatchetState): SerializedRatchetState {
  return {
    self: {
      publicKey: toBase64Url(state.self.publicKey),
      privateKey: toBase64Url(state.self.privateKey),
    },
    remote: state.remote ? toBase64Url(state.remote) : null,
    rootKey: toBase64Url(state.rootKey),
    sendChainKey: state.sendChainKey ? toBase64Url(state.sendChainKey) : null,
    receiveChainKey: state.receiveChainKey ? toBase64Url(state.receiveChainKey) : null,
    sendCount: state.sendCount,
    receiveCount: state.receiveCount,
    previousSendCount: state.previousSendCount,
    skipped: [...state.skipped.entries()].map(([id, key]) => [id, toBase64Url(key)]),
    associatedData: toBase64Url(state.associatedData),
  };
}

export function deserializeState(data: SerializedRatchetState): RatchetState {
  return {
    self: {
      publicKey: fromBase64Url(data.self.publicKey),
      privateKey: fromBase64Url(data.self.privateKey),
    },
    remote: data.remote ? fromBase64Url(data.remote) : null,
    rootKey: fromBase64Url(data.rootKey),
    sendChainKey: data.sendChainKey ? fromBase64Url(data.sendChainKey) : null,
    receiveChainKey: data.receiveChainKey ? fromBase64Url(data.receiveChainKey) : null,
    sendCount: data.sendCount,
    receiveCount: data.receiveCount,
    previousSendCount: data.previousSendCount,
    skipped: new Map(data.skipped.map(([id, key]) => [id, fromBase64Url(key)])),
    associatedData: fromBase64Url(data.associatedData),
  };
}

export function encodeMessage(message: RatchetMessage): string {
  return JSON.stringify({
    v: 1,
    dh: toBase64Url(message.header.dh),
    pn: message.header.pn,
    n: message.header.n,
    ct: toBase64Url(message.ciphertext),
  });
}

export function decodeMessage(encoded: string): RatchetMessage {
  const parsed = JSON.parse(encoded) as {
    v: number;
    dh: string;
    pn: number;
    n: number;
    ct: string;
  };
  if (parsed.v !== 1) throw new Error("ratchet: unsupported message version");
  return {
    header: { dh: fromBase64Url(parsed.dh), pn: parsed.pn, n: parsed.n },
    ciphertext: fromBase64Url(parsed.ct),
  };
}
