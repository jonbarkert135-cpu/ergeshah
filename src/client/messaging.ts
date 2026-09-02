/**
 * Conversation logic: claim bundles, open sessions, encrypt, poll, decrypt, acknowledge.
 *
 * Two details worth pointing at:
 *  - the sender's name travels *inside* the ciphertext, because the server is not told
 *    who sent an envelope;
 *  - a one-time prekey is deleted from the vault as soon as it is used to accept a
 *    session, which is what makes it one-time.
 */
import { api } from "./api.ts";
import {
  decodeIdentity,
  encodeIdentity,
  persistVault,
  state,
  type Conversation,
  type DeliveryKey,
} from "./state.ts";
import { fromBase64Url, toBase64Url } from "../shared/encoding.ts";
import { randomBytes } from "../shared/crypto/sodium.ts";
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
  await sendPayload(conversation, { text });
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
  text: string;
  delivery?: DeliveryKey & { orderId: string };
}

async function sendPayload(conversation: Conversation, payload: OutgoingPayload): Promise<void> {
  const identity = decodeIdentity(state.vault!.identity);
  const { bundles } = await api<{ bundles: Bundle[] }>(
    `/api/keys/bundle/${encodeURIComponent(conversation.peer)}`,
  );
  const at = Date.now();
  const plaintext = JSON.stringify({ from: state.account!.username, at, ...payload });
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

  await api("/api/messages", {
    method: "POST",
    body: { to: conversation.peer, channel: conversation.channel, messages },
  });
  conversation.messages.push({ from: state.account!.username, text: payload.text, at, mine: true });
  await persistVault();
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
  if (envelopes.length === 0) return 0;

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
        delivery?: DeliveryKey & { orderId: string };
      };
      conversation.sessions[opened.sessionKey] = serializeState(opened.state);
      if (conversation.peer === "unknown") conversation.peer = plaintext.from;
      if (plaintext.delivery) storeDeliveryKey(plaintext.delivery);
      conversation.messages.push({
        from: plaintext.from,
        text: plaintext.text,
        at: plaintext.at || envelope.receivedAt,
        mine: false,
      });
      decrypted += 1;
      handled.push(envelope.id);
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
  const { orderId, key, nonce, name } = delivery;
  if (typeof orderId !== "string" || typeof key !== "string" || typeof nonce !== "string") return;
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(orderId)) return;
  const deliveries = (state.vault!.deliveries ??= {});
  deliveries[orderId] = {
    key,
    nonce,
    name: typeof name === "string" ? name.slice(0, 120) : "delivery",
    at: Date.now(),
  };
}
