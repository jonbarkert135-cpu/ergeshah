/**
 * Conversation logic: claim bundles, open sessions, encrypt, poll, decrypt, acknowledge.
 *
 * Two details worth pointing at:
 *  - the sender's name travels *inside* the ciphertext, because the server is not told
 *    who sent an envelope;
 *  - a one-time prekey is deleted from the vault as soon as it is used to accept a
 *    session, which is what makes it one-time.
 */
import { api, ApiError } from "./api.ts";
import {
  decodeIdentity,
  encodeIdentity,
  persistVault,
  privacySettings,
  state,
  type AttachmentRef,
  type ChatMessage,
  type Conversation,
  type DeliveryKey,
} from "./state.ts";
import { fromBase64Url, toBase64Url } from "../shared/encoding.ts";
import { safeFileName } from "../shared/uploads.ts";
import { randomBytes } from "../shared/crypto/sodium.ts";
import { decryptFile, encryptFile, MAX_FILE_BYTES } from "../shared/crypto/file.ts";
import {
  acceptSession,
  decryptText,
  encryptText,
  openSession,
  type SessionInvite,
} from "../shared/crypto/session.ts";
import { deserializeState, serializeState } from "../shared/crypto/ratchet.ts";

interface Bundle {
  deviceId: string;
  identityKey: string;
  signedPreKeyId: number;
  signedPreKey: string;
  signedPreKeySignature: string;
  oneTimePreKeyId: number | null;
  oneTimePreKey: string | null;
}

/**
 * Typing indicators, remembered nowhere (point 76).
 *
 * A peer is "typing" for a few seconds after a signal arrives, and that fact lives in this
 * module for exactly as long as it is true. It is never written to the vault, never sent to
 * the server, and gone on reload — because a presence history is the thing this feature is
 * most likely to accidentally become.
 */
const typingUntil = new Map<string, number>();
const TYPING_SHOWN_MS = 8000;
/** One typing signal per this interval, at most: a keystroke is not an event worth sending. */
const TYPING_INTERVAL_MS = 6000;
const typingSentAt = new Map<string, number>();

export function peerIsTyping(channel: string, now = Date.now()): boolean {
  return (typingUntil.get(channel) ?? 0) > now;
}

/**
 * Bumped whenever something arrives that changes what a view should show but is not a
 * message — a read receipt, a typing signal. Without it a receipt lands silently and the
 * conversation only shows it the next time something else forces a redraw, which is how
 * "read" appeared minutes late in the first real-browser run.
 */
let revision = 0;

export function signalRevision(): number {
  return revision;
}

export function conversations(): Conversation[] {
  const all = Object.values(state.vault?.conversations ?? {});
  return all.sort((a, b) => lastAt(b) - lastAt(a));
}

function lastAt(conversation: Conversation): number {
  return conversation.messages.at(-1)?.at ?? 0;
}

function conversationWith(peer: string): Conversation | null {
  return conversations().find((conversation) => conversation.peer === peer) ?? null;
}

/**
 * `channel` is passed in for an order conversation, whose channel id was chosen by the
 * server-side order record and is known to both parties; chats pick their own.
 */
export async function startConversation(peer: string, channel?: string): Promise<Conversation> {
  const existing = channel ? state.vault!.conversations[channel] : conversationWith(peer);
  if (existing) return existing;
  const conversation: Conversation = {
    channel: channel ?? toBase64Url(randomBytes(24)),
    peer,
    messages: [],
    sessions: {},
  };
  state.vault!.conversations[conversation.channel] = conversation;
  await persistVault();
  return conversation;
}

export async function sendMessage(conversation: Conversation, text: string): Promise<void> {
  if (isBlocked(conversation.peer)) throw new Error("you blocked this person; unblock them to write");
  await sendPayload(conversation, { text });
}

/**
 * An attachment (point 78): a picture, a recording, a document, any file.
 *
 * The bytes are encrypted in this browser with a one-time key before anything leaves it,
 * uploaded as an opaque blob under an id this browser chose, and the key travels to the
 * peer inside the ordinary encrypted message — never beside the blob, never to the server.
 * TLS is what protects the upload from the network; it is not what protects it from the
 * operator, and this is the difference.
 */
export async function sendAttachment(
  conversation: Conversation,
  bytes: Uint8Array,
  name: string,
): Promise<void> {
  if (isBlocked(conversation.peer)) throw new Error("you blocked this person; unblock them to write");
  if (bytes.length > MAX_FILE_BYTES) throw new Error(`file: larger than ${MAX_FILE_BYTES} bytes`);
  const id = toBase64Url(randomBytes(24));
  const { key, nonce, ciphertext } = encryptFile(id, bytes);
  await api("/api/attachments", { method: "POST", body: { id, ciphertext: toBase64Url(ciphertext) } });
  const attachment: AttachmentRef = {
    id,
    key: toBase64Url(key),
    nonce: toBase64Url(nonce),
    name: safeFileName(name),
    bytes: bytes.length,
  };
  // Upload first, key second: a key without a blob is a broken message, a blob without a
  // key is unopenable noise that expires on its own.
  await sendPayload(conversation, { text: attachment.name, attachment }, { attachment });
}

/** Fetch and open one attachment. The server hands over ciphertext and learns nothing more. */
export async function openAttachment(reference: AttachmentRef): Promise<Uint8Array> {
  const { ciphertext } = await api<{ ciphertext: string }>(
    `/api/attachments/${encodeURIComponent(reference.id)}`,
  );
  return decryptFile(
    reference.id,
    fromBase64Url(reference.key),
    fromBase64Url(reference.nonce),
    fromBase64Url(ciphertext),
  );
}

/**
 * "They are typing" (points 75-76), sent only if this device was told to.
 *
 * It is an ordinary encrypted message with no text, so the server cannot tell it from
 * anything else — and that is also the honest cost: it *is* an envelope, so turning this on
 * multiplies how often the operator sees you send something. Hence off by default, throttled
 * hard, and documented in docs/METADATA.md rather than sold as harmless.
 */
export async function sendTyping(conversation: Conversation, now = Date.now()): Promise<void> {
  if (!privacySettings().typingIndicators || isBlocked(conversation.peer)) return;
  if (now - (typingSentAt.get(conversation.channel) ?? 0) < TYPING_INTERVAL_MS) return;
  typingSentAt.set(conversation.channel, now);
  await sendPayload(conversation, { signal: { type: "typing" } }, { store: false });
}

/**
 * "Read up to here" (point 77). Configurable, off by default, and one signal per batch
 * rather than one per message — a receipt per message would be a keystroke-level timeline
 * of when someone reads.
 */
export async function sendReadReceipt(conversation: Conversation): Promise<void> {
  if (!privacySettings().readReceipts || isBlocked(conversation.peer)) return;
  const last = conversation.messages.filter((message) => !message.mine).at(-1);
  if (!last || (conversation.readUpTo ?? 0) >= last.at) return;
  // Remembered locally so the same receipt is not resent on every render.
  conversation.readUpTo = last.at;
  await sendPayload(conversation, { signal: { type: "read", upTo: last.at } }, { store: false });
}

/**
 * Hands a delivery key to the buyer over the order's encrypted channel. The file itself
 * is already uploaded as ciphertext; this message is what makes it openable, and it is
 * protected by the same ratchet as ordinary chat.
 */
export async function sendDeliveryKey(
  peer: string,
  channel: string,
  orderId: string,
  delivery: DeliveryKey,
): Promise<void> {
  const conversation = await startConversation(peer, channel);
  await sendPayload(conversation, {
    text: `Delivered: ${delivery.name}`,
    delivery: { orderId, ...delivery },
  });
}

interface OutgoingPayload {
  /** Absent on a control message: a signal has nothing to say, and says it in fewer bytes. */
  text?: string;
  delivery?: DeliveryKey & { orderId: string };
  shipping?: { orderId: string; details: string };
  attachment?: AttachmentRef;
  /** A control message between two clients. Carries no text and is never stored. */
  signal?: { type: "typing" } | { type: "read"; upTo: number };
}

/**
 * A delivery address is a message, not a database row. It travels through the order's
 * encrypted channel like everything else, so the server never has a field to leak, and
 * the seller's copy lives in their vault until the order is done.
 */
export async function sendShippingDetails(
  peer: string,
  channel: string,
  orderId: string,
  details: string,
): Promise<void> {
  const conversation = await startConversation(peer, channel);
  await sendPayload(conversation, {
    text: "Delivery details sent.",
    shipping: { orderId, details: details.slice(0, 2000) },
  });
}

/**
 * Disappearing messages, in hours (point 74): the conversation's own setting when it has
 * one, the account default otherwise, and `null` for "keep until deleted".
 */
export function disappearHours(conversation: Conversation): number | null {
  return conversation.disappearHours === undefined
    ? privacySettings().disappearHours
    : conversation.disappearHours;
}

export async function setDisappearing(
  conversation: Conversation,
  hours: number | null,
): Promise<void> {
  conversation.disappearHours = hours;
  await persistVault();
}

async function sendPayload(
  conversation: Conversation,
  payload: OutgoingPayload,
  options: { store?: boolean; attachment?: AttachmentRef } = {},
): Promise<void> {
  const identity = decodeIdentity(state.vault!.identity);
  const { bundles } = await api<{ bundles: Bundle[] }>(
    `/api/keys/bundle/${encodeURIComponent(conversation.peer)}`,
  );
  const at = Date.now();
  const hours = disappearHours(conversation);
  const expiresAt = hours === null ? undefined : at + hours * 3_600_000;
  const plaintext = JSON.stringify({
    from: state.account!.username,
    at,
    ...payload,
    ...(expiresAt === undefined ? {} : { expiresAt }),
  });
  // Sessions are keyed by the peer's identity key, never by the server's device id:
  // the directory is untrusted, so nothing cryptographic may depend on its bookkeeping.
  const messages = bundles.map((bundle) => {
    const stored = conversation.sessions[bundle.identityKey];
    if (stored) {
      const session = deserializeState(stored);
      const encrypted = encryptText(session, plaintext);
      conversation.sessions[bundle.identityKey] = serializeState(session);
      return { deviceId: bundle.deviceId, payload: encrypted };
    }
    const { state: session, invite } = openSession(identity.identity, {
      identityKey: fromBase64Url(bundle.identityKey),
      signedPreKeyId: bundle.signedPreKeyId,
      signedPreKey: fromBase64Url(bundle.signedPreKey),
      signedPreKeySignature: fromBase64Url(bundle.signedPreKeySignature),
      oneTimePreKeyId: bundle.oneTimePreKeyId,
      oneTimePreKey: bundle.oneTimePreKey ? fromBase64Url(bundle.oneTimePreKey) : null,
    });
    const encrypted = encryptText(session, plaintext);
    conversation.sessions[bundle.identityKey] = serializeState(session);
    return { deviceId: bundle.deviceId, payload: encrypted, invite };
  });

  await postEnvelopes({
    to: conversation.peer,
    channel: conversation.channel,
    messages,
    // The same expiry for every envelope in this conversation, signals included: asking
    // for a shorter one only when a message disappears would tell the server which
    // envelopes are chat and which are receipts.
    ...(hours === null ? {} : { ttlHours: hours }),
  });
  if (options.store !== false) {
    conversation.messages.push({
      id: localId(),
      from: state.account!.username,
      text: payload.text ?? "",
      at,
      mine: true,
      ...(expiresAt === undefined ? {} : { expiresAt }),
      ...(options.attachment ? { attachment: options.attachment } : {}),
    });
  }
  await persistVault();
}

/** Refill when the pouch runs this low, so a send never waits for a batch. */
const TOKEN_FLOOR = 4;

/**
 * Sealed sender, client side (MD-4, ADR-0084). Every envelope this client posts is posted
 * with a single-use token and no cookies, so the server has no session to attribute it to.
 *
 * The tokens are minted in batches by an authenticated call, which is deliberately *not*
 * the moment of sending: the batch is fetched when the pouch runs low, and one batch covers
 * a conversation, so mint time and send time are not the same event. If the mint fails or
 * the token is refused — an old deployment, a token that expired in a long-closed tab — the
 * message still goes out over the session, because a messenger that silently stops
 * delivering is a worse failure than a messenger that reveals what it already revealed
 * yesterday. `docs/METADATA.md` says so out loud rather than promising more than this.
 */
async function postEnvelopes(body: Record<string, unknown>): Promise<void> {
  const token = await takeSendToken();
  if (token === null) {
    await api("/api/messages", { method: "POST", body });
    return;
  }
  try {
    await api("/api/messages", { method: "POST", body, sendToken: token });
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 401) throw error;
    await api("/api/messages", { method: "POST", body });
  }
}

async function takeSendToken(): Promise<string | null> {
  const vault = state.vault;
  if (!vault) return null;
  const pouch = vault.sendTokens ?? [];
  if (pouch.length <= TOKEN_FLOOR) {
    try {
      const minted = await api<{ tokens: string[] }>("/api/messages/tokens", { method: "POST" });
      pouch.push(...minted.tokens);
    } catch {
      // Out of quota, or a server without the route. Either way: send the ordinary way.
      if (pouch.length === 0) return null;
    }
  }
  const token = pouch.shift() ?? null;
  vault.sendTokens = pouch;
  return token;
}

/** A local handle for one stored message. Never sent, so it identifies nothing to anyone. */
function localId(): string {
  return toBase64Url(randomBytes(9));
}

interface Envelope {
  id: string;
  channel: string;
  payload: string;
  invite: SessionInvite | null;
  receivedAt: number;
}

/** Returns the number of messages successfully decrypted. */
export async function receiveMessages(): Promise<number> {
  const deviceId = state.vault?.deviceId;
  if (!deviceId) return 0;
  const { envelopes } = await api<{ envelopes: Envelope[] }>(
    `/api/messages?deviceId=${encodeURIComponent(deviceId)}`,
  );
  const swept = pruneExpired();
  if (envelopes.length === 0) {
    if (swept) await persistVault();
    return 0;
  }

  let decrypted = 0;
  const handled: string[] = [];
  for (const envelope of envelopes) {
    try {
      const conversation = resolveConversation(envelope);
      const opened = decryptEnvelope(conversation, envelope);
      const plaintext = JSON.parse(opened.plaintext) as {
        from: string;
        text: string;
        at: number;
        expiresAt?: number;
        attachment?: AttachmentRef;
        signal?: { type: string; upTo?: number };
        delivery?: DeliveryKey & { orderId: string };
        shipping?: { orderId: string; details: string };
      };
      conversation.sessions[opened.sessionKey] = serializeState(opened.state);
      if (conversation.peer === "unknown") conversation.peer = plaintext.from;
      handled.push(envelope.id);
      // A blocked peer's message is decrypted (the ratchet has to advance or the session
      // desynchronises) and then dropped without being stored or shown (point 84). The
      // server is told nothing: it never knew who sent it, and a block it could see would
      // be the social graph this design refuses to hand over.
      if (isBlocked(plaintext.from)) continue;
      if (plaintext.signal) {
        applySignal(conversation, plaintext.signal);
        continue;
      }
      if (plaintext.delivery) storeDeliveryKey(plaintext.delivery);
      if (plaintext.shipping) storeShipping(plaintext.shipping);
      const at = plaintext.at || envelope.receivedAt;
      conversation.messages.push({
        id: localId(),
        from: plaintext.from,
        text: plaintext.text,
        at,
        mine: false,
        ...expiryFor(conversation, at, plaintext.expiresAt),
        ...(validAttachment(plaintext.attachment) ? { attachment: plaintext.attachment } : {}),
      });
      decrypted += 1;
    } catch {
      // Undecryptable envelope: acknowledge it anyway so that a malformed or hostile
      // message cannot wedge the inbox, but keep it out of the conversation.
      handled.push(envelope.id);
    }
  }
  await persistVault();
  await api("/api/messages/ack", { method: "POST", body: { deviceId, ids: handled } });
  return decrypted;
}

/**
 * Whichever expiry is sooner: the one the sender asked for, or this side's own setting for
 * the conversation. A sender can shorten the life of what they wrote; they cannot extend it
 * past what the reader chose.
 */
function expiryFor(
  conversation: Conversation,
  at: number,
  requested: unknown,
): { expiresAt?: number } {
  const hours = disappearHours(conversation);
  const mine = hours === null ? null : at + hours * 3_600_000;
  const theirs =
    typeof requested === "number" && Number.isFinite(requested) && requested > at ? requested : null;
  const soonest = mine === null ? theirs : theirs === null ? mine : Math.min(mine, theirs);
  return soonest === null ? {} : { expiresAt: soonest };
}

/** A peer sends this, so it is validated rather than trusted, exactly like a delivery key. */
function validAttachment(value: unknown): value is AttachmentRef {
  const reference = value as AttachmentRef | undefined;
  if (!reference || typeof reference !== "object") return false;
  return (
    /^[A-Za-z0-9_-]{8,64}$/.test(String(reference.id)) &&
    typeof reference.key === "string" &&
    typeof reference.nonce === "string"
  );
}

/**
 * Control messages: applied, never stored, never shown as text. An unknown signal type is
 * ignored — a future client saying something this one does not understand must not become a
 * blank message in somebody's history.
 */
function applySignal(conversation: Conversation, signal: { type: string; upTo?: number }): void {
  if (signal.type === "typing") {
    typingUntil.set(conversation.channel, Date.now() + TYPING_SHOWN_MS);
    revision += 1;
    return;
  }
  if (signal.type === "read" && typeof signal.upTo === "number") {
    for (const message of conversation.messages) {
      if (message.mine && message.at <= signal.upTo) message.readAt = signal.upTo;
    }
    revision += 1;
  }
}

/**
 * Disappearing messages, applied locally (point 74).
 *
 * This is the whole mechanism: both clients drop the plaintext when the agreed time passes,
 * and the server's copy was already gone at acknowledgement. What it is not is a guarantee —
 * see docs/DELETION.md. Returns whether anything was removed, so the caller can decide
 * whether the vault needs rewriting.
 */
export function pruneExpired(now = Date.now()): boolean {
  let changed = false;
  for (const conversation of Object.values(state.vault?.conversations ?? {})) {
    const kept = conversation.messages.filter(
      (message) => message.expiresAt === undefined || message.expiresAt > now,
    );
    if (kept.length === conversation.messages.length) continue;
    conversation.messages = kept;
    changed = true;
  }
  return changed;
}

/** Delete one message from this device. Nobody else is asked, and nobody else is told. */
export async function deleteMessage(conversation: Conversation, id: string): Promise<void> {
  conversation.messages = conversation.messages.filter((message) => message.id !== id);
  await persistVault();
}

/**
 * Delete a conversation: its history *and* its ratchet state, which is the part that
 * matters — the session keys are what could open anything still in flight for it. The next
 * message from that peer starts a new session.
 */
export async function deleteConversation(channel: string): Promise<void> {
  const conversation = state.vault?.conversations[channel];
  if (!conversation) return;
  conversation.messages = [];
  conversation.sessions = {};
  delete state.vault!.conversations[channel];
  await persistVault();
}

export function blockedPeers(): string[] {
  return [...(state.vault?.blocked ?? [])].sort();
}

export function isBlocked(peer: string): boolean {
  return (state.vault?.blocked ?? []).includes(peer.toLowerCase());
}

/** Blocking is this device's decision and stays here: the server is never told (point 84). */
export async function setBlocked(peer: string, blocked: boolean): Promise<void> {
  const name = peer.toLowerCase();
  const current = new Set(state.vault!.blocked ?? []);
  if (blocked) current.add(name);
  else current.delete(name);
  state.vault!.blocked = [...current];
  await persistVault();
}

export interface SearchHit {
  channel: string;
  peer: string;
  message: ChatMessage;
}

/**
 * Search, in the browser, over what this device has already decrypted (point 79).
 *
 * There is no server-side equivalent and there cannot be one: the server holds ciphertext
 * and no keys, so an index there would either be useless or would require handing it the
 * plaintext. The ceiling is honest — this searches what this device holds, not what another
 * device holds, and not what has already disappeared.
 */
export function searchMessages(query: string, limit = 50): SearchHit[] {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return [];
  const hits: SearchHit[] = [];
  for (const conversation of conversations()) {
    for (const message of conversation.messages) {
      if (!message.text.toLowerCase().includes(needle)) continue;
      hits.push({ channel: conversation.channel, peer: conversation.peer, message });
      if (hits.length >= limit) return hits;
    }
  }
  return hits;
}

function resolveConversation(envelope: Envelope): Conversation {
  const existing = state.vault!.conversations[envelope.channel];
  if (existing) return existing;
  const conversation: Conversation = {
    channel: envelope.channel,
    peer: "unknown",
    messages: [],
    sessions: {},
  };
  state.vault!.conversations[envelope.channel] = conversation;
  return conversation;
}

interface OpenedEnvelope {
  sessionKey: string;
  state: ReturnType<typeof deserializeState>;
  plaintext: string;
}

function decryptEnvelope(conversation: Conversation, envelope: Envelope): OpenedEnvelope {
  // An established session takes precedence: a replayed invite must not be able to
  // reset a live conversation.
  for (const [sessionKey, stored] of Object.entries(conversation.sessions)) {
    try {
      const session = deserializeState(stored);
      const plaintext = decryptText(session, envelope.payload);
      return { sessionKey, state: session, plaintext };
    } catch {
      continue;
    }
  }
  if (!envelope.invite) throw new Error("no session can open this envelope");
  const session = acceptInvite(envelope.invite);
  return {
    sessionKey: envelope.invite.identityKey,
    state: session,
    plaintext: decryptText(session, envelope.payload),
  };
}

function acceptInvite(invite: SessionInvite) {
  const identity = decodeIdentity(state.vault!.identity);
  const oneTime =
    invite.oneTimePreKeyId === null
      ? null
      : (identity.oneTimePreKeys.find((key) => key.keyId === invite.oneTimePreKeyId) ?? null);
  const session = acceptSession(identity.identity, identity.signedPreKey, oneTime, invite);
  if (oneTime) {
    // One-time means one time: burn the private key as soon as it has been used.
    identity.oneTimePreKeys = identity.oneTimePreKeys.filter((key) => key.keyId !== oneTime.keyId);
    state.vault!.identity = encodeIdentity(identity);
  }
  return session;
}

/**
 * Keys arrive as ordinary messages, so they are validated like any other untrusted input
 * before being written to the vault — a peer can send whatever it likes here.
 */
function storeDeliveryKey(delivery: DeliveryKey & { orderId: string }): void {
  const { orderId, key, nonce, name, kind } = delivery;
  if (typeof orderId !== "string" || typeof key !== "string" || typeof nonce !== "string") return;
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(orderId)) return;
  const deliveries = (state.vault!.deliveries ??= {});
  deliveries[orderId] = {
    key,
    nonce,
    // A peer chose this name and it will end up in a download. It is sanitised here, once,
    // at the point it enters the vault (point 49).
    name: safeFileName(name),
    kind: kind === "text" ? "text" : "file",
    at: Date.now(),
  };
}

/** Same treatment as a delivery key: a peer sends this, so it is validated, not trusted. */
function storeShipping(shipping: { orderId: string; details: string }): void {
  const { orderId, details } = shipping;
  if (typeof details !== "string" || !/^[A-Za-z0-9_-]{8,64}$/.test(String(orderId))) return;
  const shipments = (state.vault!.shipments ??= {});
  shipments[orderId] = { text: details.slice(0, 2000), at: Date.now() };
}
