/**
 * Double Ratchet (Signal specification, rev. 1, 2016) over X25519 / HKDF-SHA256 /
 * XChaCha20-Poly1305.
 *
 * Guarantees, inherited from the specification and exercised by `test/protocol.test.ts`
 * and `test/cryptography.test.ts`:
 *  - a message key is derived, used once and destroyed (forward secrecy inside a chain);
 *  - every DH ratchet step re-keys the session (post-compromise security);
 *  - out-of-order and dropped messages are handled through bounded skipped-key storage;
 *  - replays and tampered headers fail authentication (the header is part of the AAD).
 *
 * Headers are encrypted (the specification's "header encryption" variant): the ratchet
 * public key, the chain length and the counter travel under a separate header key, so a
 * server holding the envelope cannot group messages by session, count a conversation's
 * turns, or watch a DH ratchet step happen. Plaintexts are padded to buckets before
 * encryption, so the ciphertext length no longer reveals the message length.
 */
import { concat, fromBase64Url, toBase64Url, utf8 } from "../encoding.ts";
import { NONCE_BYTES, aeadDecrypt, aeadEncrypt } from "./aead.ts";
import { hkdf, hmacSha256 } from "./hkdf.ts";
import { dh, generateX25519KeyPair, type KeyPair } from "./identity.ts";
import { pad, unpad } from "./padding.ts";
import { randomBytes } from "./sodium.ts";

const ROOT_INFO = utf8("ergeshah-root-he-v1");
const MESSAGE_INFO = utf8("ergeshah-message-key-v1");
/**
 * The two header keys both sides must agree on before the first DH ratchet step: the
 * initiator's first sending key, and the responder's. Signal's specification calls these
 * `shared_hka` and `shared_nhkb` and expects X3DH to hand them over; deriving them from
 * the X3DH secret with distinct labels gives the same independence without adding a
 * field to the handshake.
 */
const HEADER_KEY_INITIATOR_INFO = utf8("ergeshah-header-key-initiator-v1");
const HEADER_KEY_RESPONDER_INFO = utf8("ergeshah-header-key-responder-v1");
const ZERO_SALT = new Uint8Array(32);
const CHAIN_MESSAGE_CONSTANT = Uint8Array.of(0x01);
const CHAIN_NEXT_CONSTANT = Uint8Array.of(0x02);
/** 32-byte ratchet key + two 32-bit counters. Constant, so it hides nothing by length. */
const HEADER_BYTES = 40;

export const MAX_SKIP_PER_CHAIN = 1000;
const MAX_STORED_SKIPPED_KEYS = 2000;

export interface MessageHeader {
  /** Sender's current ratchet public key. */
  dh: Uint8Array;
  /** Number of messages in the previous sending chain. */
  pn: number;
  /** Message number in the current sending chain. */
  n: number;
}

/** On the wire the header is opaque: a nonce and a sealed 40-byte block. */
export interface RatchetMessage {
  encryptedHeader: Uint8Array;
  ciphertext: Uint8Array;
}

/** A message key held for an out-of-order message, with the header key that finds it. */
interface SkippedKey {
  headerKey: Uint8Array;
  messageKey: Uint8Array;
}

export interface RatchetState {
  self: KeyPair;
  remote: Uint8Array | null;
  rootKey: Uint8Array;
  sendChainKey: Uint8Array | null;
  receiveChainKey: Uint8Array | null;
  /** Header keys: current and next, per direction (HKs / NHKs / HKr / NHKr). */
  sendHeaderKey: Uint8Array | null;
  nextSendHeaderKey: Uint8Array;
  receiveHeaderKey: Uint8Array | null;
  nextReceiveHeaderKey: Uint8Array;
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  skipped: Map<string, SkippedKey>;
  associatedData: Uint8Array;
}

/** Root KDF: new root key, new chain key, and the header key for the step after this one. */
function kdfRootKey(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): [Uint8Array, Uint8Array, Uint8Array] {
  const derived = hkdf(dhOutput, rootKey, ROOT_INFO, 96);
  return [derived.slice(0, 32), derived.slice(32, 64), derived.slice(64, 96)];
}

function initialHeaderKeys(sharedSecret: Uint8Array): {
  initiator: Uint8Array;
  responder: Uint8Array;
} {
  return {
    initiator: hkdf(sharedSecret, ZERO_SALT, HEADER_KEY_INITIATOR_INFO, 32),
    responder: hkdf(sharedSecret, ZERO_SALT, HEADER_KEY_RESPONDER_INFO, 32),
  };
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

function serializeHeader(header: MessageHeader): Uint8Array {
  const meta = new Uint8Array(8);
  const view = new DataView(meta.buffer);
  view.setUint32(0, header.pn, false);
  view.setUint32(4, header.n, false);
  return concat(header.dh, meta);
}

function parseHeader(bytes: Uint8Array): MessageHeader {
  if (bytes.length !== HEADER_BYTES) throw new Error("ratchet: bad header length");
  const view = new DataView(bytes.buffer, bytes.byteOffset + 32, 8);
  return { dh: bytes.slice(0, 32), pn: view.getUint32(0, false), n: view.getUint32(4, false) };
}

/** Sealed header: `nonce || AEAD(headerKey, header)`. Always the same size. */
function sealHeader(
  headerKey: Uint8Array,
  header: MessageHeader,
  associatedData: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(NONCE_BYTES);
  return concat(
    nonce,
    aeadEncrypt(headerKey, serializeHeader(header), associatedData, nonce),
  );
}

function openHeader(
  headerKey: Uint8Array,
  encryptedHeader: Uint8Array,
  associatedData: Uint8Array,
): MessageHeader | null {
  if (encryptedHeader.length !== NONCE_BYTES + HEADER_BYTES + 16) return null;
  try {
    return parseHeader(
      aeadDecrypt(
        headerKey,
        encryptedHeader.subarray(NONCE_BYTES),
        associatedData,
        encryptedHeader.subarray(0, NONCE_BYTES),
      ),
    );
  } catch {
    // Wrong header key. Expected: the receiver trials the current and the next one.
    return null;
  }
}

function skippedKeyId(headerKey: Uint8Array, counter: number): string {
  return `${toBase64Url(headerKey)}:${counter}`;
}

/** Initiator side: knows the responder's signed prekey public and starts sending. */
export function initiateSession(
  sharedSecret: Uint8Array,
  remoteSignedPreKey: Uint8Array,
  associatedData: Uint8Array,
): RatchetState {
  const self = generateX25519KeyPair();
  const headerKeys = initialHeaderKeys(sharedSecret);
  const [rootKey, sendChainKey, nextSendHeaderKey] = kdfRootKey(
    sharedSecret,
    dh(self.privateKey, remoteSignedPreKey),
  );
  return {
    self,
    remote: remoteSignedPreKey,
    rootKey,
    sendChainKey,
    receiveChainKey: null,
    sendHeaderKey: headerKeys.initiator,
    nextSendHeaderKey,
    receiveHeaderKey: null,
    // The responder's first sending header key, known in advance by both sides.
    nextReceiveHeaderKey: headerKeys.responder,
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
  const headerKeys = initialHeaderKeys(sharedSecret);
  return {
    self: signedPreKeyPair,
    remote: null,
    // copy: the caller wipes its own copy of the shared secret right after this call
    rootKey: new Uint8Array(sharedSecret),
    sendChainKey: null,
    receiveChainKey: null,
    sendHeaderKey: null,
    nextSendHeaderKey: headerKeys.responder,
    receiveHeaderKey: null,
    nextReceiveHeaderKey: headerKeys.initiator,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skipped: new Map(),
    associatedData,
  };
}

export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): RatchetMessage {
  if (!state.sendChainKey || !state.sendHeaderKey) {
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

  const encryptedHeader = sealHeader(state.sendHeaderKey, header, state.associatedData);
  const { key, nonce } = messageKeyMaterial(messageKey);
  // The sealed header is the AAD, exactly as in the specification's header-encryption
  // variant: a message cannot be lifted out of one envelope and dropped into another.
  const ciphertext = aeadEncrypt(
    key,
    pad(plaintext),
    concat(state.associatedData, encryptedHeader),
    nonce,
  );
  messageKey.fill(0);
  key.fill(0);
  return { encryptedHeader, ciphertext };
}

/**
 * Decryption never mutates the live session until the message has been authenticated:
 * we ratchet a copy and commit it only on success. Without this, anyone who can post an
 * envelope could desynchronise a session with a forged header — cheap denial of service
 * against a conversation, and a trap the naive reading of the specification walks into.
 */
export function ratchetDecrypt(state: RatchetState, message: RatchetMessage): Uint8Array {
  const working = cloneState(state);
  const padded = decryptInto(working, message);
  commitState(state, working);
  return unpad(padded);
}

function decryptInto(state: RatchetState, message: RatchetMessage): Uint8Array {
  const skippedPlaintext = trySkippedKeys(state, message);
  if (skippedPlaintext) return skippedPlaintext;

  const { header, dhRatchet } = decryptHeader(state, message.encryptedHeader);

  if (dhRatchet) {
    skipMessageKeys(state, header.pn);
    performDhRatchet(state, header.dh);
  }

  skipMessageKeys(state, header.n);

  if (!state.receiveChainKey) throw new Error("ratchet: no receiving chain");
  const [messageKey, nextChainKey] = kdfChainKey(state.receiveChainKey);
  state.receiveChainKey = nextChainKey;
  state.receiveCount += 1;
  return decryptWithMessageKey(state, message, messageKey);
}

/**
 * Which header key opened the header tells us what to do: the current one means "same
 * sending chain", the next one means "the peer has ratcheted". Neither means the message
 * is not ours — a forged or replayed envelope stops here, before any state is derived.
 */
function decryptHeader(
  state: RatchetState,
  encryptedHeader: Uint8Array,
): { header: MessageHeader; dhRatchet: boolean } {
  if (state.receiveHeaderKey) {
    const header = openHeader(state.receiveHeaderKey, encryptedHeader, state.associatedData);
    if (header) return { header, dhRatchet: false };
  }
  const next = openHeader(state.nextReceiveHeaderKey, encryptedHeader, state.associatedData);
  if (next) return { header: next, dhRatchet: true };
  throw new Error("ratchet: message failed authentication (tampered, replayed or foreign)");
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
    sendHeaderKey: state.sendHeaderKey ? new Uint8Array(state.sendHeaderKey) : null,
    nextSendHeaderKey: new Uint8Array(state.nextSendHeaderKey),
    receiveHeaderKey: state.receiveHeaderKey ? new Uint8Array(state.receiveHeaderKey) : null,
    nextReceiveHeaderKey: new Uint8Array(state.nextReceiveHeaderKey),
    sendCount: state.sendCount,
    receiveCount: state.receiveCount,
    previousSendCount: state.previousSendCount,
    skipped: new Map(
      [...state.skipped].map(([id, entry]) => [
        id,
        {
          headerKey: new Uint8Array(entry.headerKey),
          messageKey: new Uint8Array(entry.messageKey),
        },
      ]),
    ),
    associatedData: state.associatedData,
  };
}

function commitState(target: RatchetState, source: RatchetState): void {
  target.self = source.self;
  target.remote = source.remote;
  target.rootKey = source.rootKey;
  target.sendChainKey = source.sendChainKey;
  target.receiveChainKey = source.receiveChainKey;
  target.sendHeaderKey = source.sendHeaderKey;
  target.nextSendHeaderKey = source.nextSendHeaderKey;
  target.receiveHeaderKey = source.receiveHeaderKey;
  target.nextReceiveHeaderKey = source.nextReceiveHeaderKey;
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
      concat(state.associatedData, message.encryptedHeader),
      nonce,
    );
  } catch {
    throw new Error("ratchet: message failed authentication (tampered, replayed or foreign)");
  } finally {
    messageKey.fill(0);
    key.fill(0);
  }
}

/**
 * With encrypted headers a stored message key can no longer be looked up directly: the
 * counter is inside the header. So each distinct header key we kept is trialled against
 * the sealed header, and only a successful open gives us the counter to look up.
 */
function trySkippedKeys(state: RatchetState, message: RatchetMessage): Uint8Array | null {
  const tried = new Set<string>();
  for (const entry of state.skipped.values()) {
    const fingerprint = toBase64Url(entry.headerKey);
    if (tried.has(fingerprint)) continue;
    tried.add(fingerprint);

    const header = openHeader(entry.headerKey, message.encryptedHeader, state.associatedData);
    if (!header) continue;

    const id = skippedKeyId(entry.headerKey, header.n);
    const skipped = state.skipped.get(id);
    if (!skipped) return null; // right chain, but that message key is spent — a replay
    const plaintext = decryptWithMessageKey(state, message, skipped.messageKey);
    state.skipped.delete(id); // one-time use: a replay of the same message now fails
    return plaintext;
  }
  return null;
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (!state.receiveChainKey || !state.receiveHeaderKey) return;
  if (until - state.receiveCount > MAX_SKIP_PER_CHAIN) {
    throw new Error("ratchet: too many skipped messages — refusing to derive keys");
  }
  while (state.receiveCount < until) {
    const [messageKey, nextChainKey] = kdfChainKey(state.receiveChainKey);
    state.receiveChainKey = nextChainKey;
    state.skipped.set(skippedKeyId(state.receiveHeaderKey, state.receiveCount), {
      headerKey: new Uint8Array(state.receiveHeaderKey),
      messageKey,
    });
    state.receiveCount += 1;
    pruneSkipped(state);
  }
}

function pruneSkipped(state: RatchetState): void {
  while (state.skipped.size > MAX_STORED_SKIPPED_KEYS) {
    const oldest = state.skipped.keys().next();
    if (oldest.done) return;
    const entry = state.skipped.get(oldest.value);
    entry?.messageKey.fill(0);
    state.skipped.delete(oldest.value);
  }
}

function performDhRatchet(state: RatchetState, remotePublicKey: Uint8Array): void {
  state.previousSendCount = state.sendCount;
  state.sendCount = 0;
  state.receiveCount = 0;
  state.remote = remotePublicKey;
  // Both sides promote the "next" header keys in the same step, which is what keeps the
  // two directions' key schedules aligned without any extra round trip.
  state.sendHeaderKey = state.nextSendHeaderKey;
  state.receiveHeaderKey = state.nextReceiveHeaderKey;

  const [rootKeyAfterReceive, receiveChainKey, nextReceiveHeaderKey] = kdfRootKey(
    state.rootKey,
    dh(state.self.privateKey, remotePublicKey),
  );
  state.rootKey = rootKeyAfterReceive;
  state.receiveChainKey = receiveChainKey;
  state.nextReceiveHeaderKey = nextReceiveHeaderKey;

  state.self = generateX25519KeyPair();
  const [rootKeyAfterSend, sendChainKey, nextSendHeaderKey] = kdfRootKey(
    state.rootKey,
    dh(state.self.privateKey, remotePublicKey),
  );
  state.rootKey = rootKeyAfterSend;
  state.sendChainKey = sendChainKey;
  state.nextSendHeaderKey = nextSendHeaderKey;
}

/* ---------- persistence (the client stores this inside its encrypted vault) ---------- */

export interface SerializedRatchetState {
  self: { publicKey: string; privateKey: string };
  remote: string | null;
  rootKey: string;
  sendChainKey: string | null;
  receiveChainKey: string | null;
  sendHeaderKey: string | null;
  nextSendHeaderKey: string;
  receiveHeaderKey: string | null;
  nextReceiveHeaderKey: string;
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  skipped: Array<{ id: string; headerKey: string; messageKey: string }>;
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
    sendHeaderKey: state.sendHeaderKey ? toBase64Url(state.sendHeaderKey) : null,
    nextSendHeaderKey: toBase64Url(state.nextSendHeaderKey),
    receiveHeaderKey: state.receiveHeaderKey ? toBase64Url(state.receiveHeaderKey) : null,
    nextReceiveHeaderKey: toBase64Url(state.nextReceiveHeaderKey),
    sendCount: state.sendCount,
    receiveCount: state.receiveCount,
    previousSendCount: state.previousSendCount,
    skipped: [...state.skipped.entries()].map(([id, entry]) => ({
      id,
      headerKey: toBase64Url(entry.headerKey),
      messageKey: toBase64Url(entry.messageKey),
    })),
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
    sendHeaderKey: data.sendHeaderKey ? fromBase64Url(data.sendHeaderKey) : null,
    nextSendHeaderKey: fromBase64Url(data.nextSendHeaderKey),
    receiveHeaderKey: data.receiveHeaderKey ? fromBase64Url(data.receiveHeaderKey) : null,
    nextReceiveHeaderKey: fromBase64Url(data.nextReceiveHeaderKey),
    sendCount: data.sendCount,
    receiveCount: data.receiveCount,
    previousSendCount: data.previousSendCount,
    skipped: new Map(
      data.skipped.map((entry) => [
        entry.id,
        {
          headerKey: fromBase64Url(entry.headerKey),
          messageKey: fromBase64Url(entry.messageKey),
        },
      ]),
    ),
    associatedData: fromBase64Url(data.associatedData),
  };
}

/**
 * Wire format. Version 2 carries two opaque blobs and nothing else — no key, no counter,
 * no chain length in the clear. Version 1 (plaintext headers) is refused outright rather
 * than supported: the platform has no deployment yet, and accepting the old format would
 * let anyone who can post an envelope ask a client to fall back to it.
 */
export function encodeMessage(message: RatchetMessage): string {
  return JSON.stringify({
    v: 2,
    h: toBase64Url(message.encryptedHeader),
    ct: toBase64Url(message.ciphertext),
  });
}

export function decodeMessage(encoded: string): RatchetMessage {
  const parsed = JSON.parse(encoded) as { v: number; h?: string; ct?: string };
  if (parsed.v !== 2) throw new Error("ratchet: unsupported message version");
  if (typeof parsed.h !== "string" || typeof parsed.ct !== "string") {
    throw new Error("ratchet: malformed message");
  }
  return {
    encryptedHeader: fromBase64Url(parsed.h),
    ciphertext: fromBase64Url(parsed.ct),
  };
}
