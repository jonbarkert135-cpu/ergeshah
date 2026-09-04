/**
 * What a peer is allowed to say, checked before it is kept.
 *
 * The AEAD in `shared/crypto/ratchet.ts` proves that the peer's device wrote the bytes; it
 * says nothing about their shape, and a peer running an edited client can write anything.
 * Everything that comes out of `decryptEnvelope` is stored in the vault and rendered by the
 * views, so a field of the wrong type is a persistent, remotely planted crash — one envelope
 * left the Messages screen blank until somebody cleared localStorage (SEC-2026-015). This
 * module is the boundary: `strangerInvite` for who may open a session at all, `parseIncoming`
 * for the payload, `validAttachment` for the one nested object the views render directly.
 */
import { api, ApiError } from "./api.ts";
import type { AttachmentRef, Conversation, DeliveryKey } from "./state.ts";
import type { SessionInvite } from "../shared/crypto/session.ts";
import { notePeerKeys } from "./verification.ts";
import { MAX_FILE_BYTES } from "../shared/crypto/file.ts";
import { safeFileName } from "../shared/uploads.ts";

/** What a peer may put inside an envelope. Everything optional is re-checked where it is used. */
export interface IncomingPayload {
  from: string;
  text: string;
  at: number;
  expiresAt?: number;
  attachment?: AttachmentRef;
  signal?: { type: string; upTo?: number };
  delivery?: DeliveryKey & { orderId: string };
  shipping?: { orderId: string; details: string };
}

/** The longest text a client of ours sends is 4 000 characters (`views/chat.ts`). */
const MAX_INCOMING_TEXT = 8_192;
/** A username, as the server defines one (`lib/validate.ts`). */
const USERNAME_RE = /^[a-z0-9](?:[a-z0-9_.-]{1,30})[a-z0-9]$/;

/**
 * The decrypted plaintext, checked field by field before anything is stored. `null` means
 * "not a message this client will keep": a signal without a text is fine, a text that is
 * not a string is not, and any nested object must be an object.
 */
export function parseIncoming(plaintext: string): IncomingPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;
  if (typeof record.from !== "string" || !USERNAME_RE.test(record.from)) return null;
  const isObject = (value: unknown): value is Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value);
  for (const key of ["signal", "attachment", "delivery", "shipping"] as const) {
    if (record[key] !== undefined && !isObject(record[key])) return null;
  }
  const signal = record.signal as IncomingPayload["signal"] | undefined;
  if (signal && typeof signal.type !== "string") return null;
  if (!signal && (typeof record.text !== "string" || record.text.length > MAX_INCOMING_TEXT)) {
    return null;
  }
  return {
    from: record.from,
    text: typeof record.text === "string" ? record.text : "",
    at: typeof record.at === "number" && Number.isFinite(record.at) ? record.at : 0,
    ...(typeof record.expiresAt === "number" ? { expiresAt: record.expiresAt } : {}),
    ...(signal ? { signal } : {}),
    ...(record.attachment ? { attachment: record.attachment as AttachmentRef } : {}),
    ...(record.delivery ? { delivery: record.delivery as IncomingPayload["delivery"] } : {}),
    ...(record.shipping ? { shipping: record.shipping as IncomingPayload["shipping"] } : {}),
  };
}

/**
 * A peer sends this, so it is validated rather than trusted, exactly like a delivery key —
 * every field, because every field is stored in the vault and rendered. The name is
 * sanitised once, here, at the point it enters the vault (point 49).
 */
export function validAttachment(value: unknown): value is AttachmentRef {
  const reference = value as AttachmentRef | undefined;
  if (!reference || typeof reference !== "object") return false;
  if (
    !/^[A-Za-z0-9_-]{8,64}$/.test(String(reference.id)) ||
    typeof reference.key !== "string" ||
    reference.key.length > 128 ||
    typeof reference.nonce !== "string" ||
    reference.nonce.length > 128 ||
    typeof reference.name !== "string" ||
    reference.name.length > 255 ||
    typeof reference.bytes !== "number" ||
    !Number.isInteger(reference.bytes) ||
    reference.bytes < 0 ||
    reference.bytes > MAX_FILE_BYTES
  ) {
    return false;
  }
  reference.name = safeFileName(reference.name);
  return true;
}

/**
 * A sender chooses the channel id, so a third account that learns an order's channel can
 * post an X3DH invite into that conversation under any display name (SEC-2026-024). Before
 * a key this conversation has never seen may open a session in it, it has to be one of the
 * peer's keys in the directory. This gives the directory a veto and nothing more — a hostile
 * server could already drop the envelope — while a hostile *account* cannot make the
 * directory list its key under somebody else's name (ADR-0112).
 *
 * Returns null when the directory could not be asked, so the caller can leave the envelope
 * unacknowledged rather than lose a legitimate new device to a network blip. `directory`
 * caches one answer per peer for the duration of a poll.
 */
export async function strangerInvite(
  conversation: Conversation,
  envelope: { invite: SessionInvite | null },
  directory: Map<string, string[] | null>,
): Promise<boolean | null> {
  const key = envelope.invite?.identityKey;
  if (!key || conversation.peer === "unknown") return false;
  if (conversation.sessions[key] || conversation.knownKeys?.[key] !== undefined) return false;
  if (!directory.has(conversation.peer)) directory.set(conversation.peer, await identityKeys(conversation.peer));
  const listed = directory.get(conversation.peer)!;
  if (listed === null) return null;
  // The directory answered for the whole peer, so the record can tell "added" from
  // "replaced" here too, which the receive path alone never could (ADR-0091).
  notePeerKeys(conversation, listed, { directory: true });
  return !listed.includes(key);
}

/** The peer's active identity keys; [] for a peer who no longer exists, null if unreachable. */
async function identityKeys(peer: string): Promise<string[] | null> {
  try {
    const { identityKeys } = await api<{ identityKeys: string[] }>(
      `/api/keys/identity/${encodeURIComponent(peer)}`,
    );
    return identityKeys;
  } catch (error) {
    return error instanceof ApiError && error.status === 404 ? [] : null;
  }
}
