/**
 * Safety numbers: comparing identity keys out of band, and remembering the answer.
 *
 * Without this, a first contact is trust-on-first-use — the key directory is the server's,
 * and a server that lies about a key reads the conversation. Comparing a safety number in
 * person (or over a channel the server does not control) is what turns that into a
 * detectable attack, and marking the result is what makes a *later* substitution visible.
 *
 * A peer may have several devices, so verification is per identity key, not per person.
 * A new unverified key in a conversation that had verified ones is exactly the event worth
 * shouting about — it is either a new device or a swapped key, and only the two humans can
 * tell which.
 */
import { decodeIdentity, persistVault, state, type Conversation } from "./state.ts";
import { safetyNumber } from "../shared/crypto/identity.ts";
import { fromBase64Url } from "../shared/encoding.ts";

export type VerificationState = "none" | "verified" | "changed";

export interface PeerDevice {
  key: string;
  safetyNumber: string;
  verifiedAt: number | null;
}

/** Identity keys we currently hold a session with, oldest first. */
export function peerDevices(conversation: Conversation): PeerDevice[] {
  const identity = state.vault ? decodeIdentity(state.vault.identity).identity.publicKey : null;
  const verified = conversation.verifiedKeys ?? {};
  return Object.keys(conversation.sessions).map((key) => ({
    key,
    safetyNumber: identity ? safetyNumber(identity, fromBase64Url(key)) : "",
    verifiedAt: verified[key] ?? null,
  }));
}

/**
 * Deliberately independent of the vault's identity keys: this is the check the chat view
 * runs on every redraw, and it must be a pure function of the conversation so it can be
 * tested without a browser.
 */
export function verificationState(conversation: Conversation): VerificationState {
  const keys = Object.keys(conversation.sessions);
  const verified = conversation.verifiedKeys ?? {};
  const known = keys.filter((key) => verified[key] !== undefined);
  if (keys.length === 0 || known.length === 0) return "none";
  return known.length === keys.length ? "verified" : "changed";
}

export async function markVerified(conversation: Conversation, key: string): Promise<void> {
  const verified = (conversation.verifiedKeys ??= {});
  verified[key] = Date.now();
  await persistVault();
}

export async function clearVerification(conversation: Conversation): Promise<void> {
  delete conversation.verifiedKeys;
  await persistVault();
}
