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

/**
 * AUTH-6. Records the identity keys a peer is using and reports a change to the user.
 *
 * The attack this covers is not a substituted key in an already-verified conversation —
 * `verificationState` has always caught that — but the case where nobody compared anything:
 * a username is deleted, registered again by someone else, and the next message goes to a
 * different person under a name the history says is trusted. Trust on first use is only
 * honest if the *second* use is checked, so every key is recorded on sight and a key that
 * arrives later is announced.
 *
 * The record stays in the vault. The alternative — a tombstone on the server, so a deleted
 * username can never be taken again — would mean keeping a list of everyone who ever left,
 * which is the collection this project refuses to make (ADR-0091).
 *
 * `directory` says whether `keys` is the peer's complete current key list from the key
 * directory (the send path) or a single key from one envelope (the receive path). Only the
 * complete list can distinguish a device added beside the old ones from every old key
 * gone, and the difference matters: the second is what re-registration looks like.
 */
export function notePeerKeys(
  conversation: Conversation,
  keys: string[],
  { directory = false }: { directory?: boolean } = {},
): void {
  // A vault written before this existed has sessions but no record. Seeding it from those
  // sessions rather than announcing them keeps an upgrade quiet: those keys are not new,
  // this device simply was not writing them down.
  const known = (conversation.knownKeys ??= Object.fromEntries(
    Object.keys(conversation.sessions).map((key) => [key, 0]),
  ));
  const first = Object.keys(known).length === 0;
  const fresh = keys.filter((key) => known[key] === undefined);
  const at = Date.now();
  for (const key of fresh) known[key] = at;
  if (first || fresh.length === 0) return;

  // Every key we knew is gone from the directory: not a new device, a different set of
  // devices. Said plainly, because a warning that hedges is a warning people click past.
  const replaced = directory && !keys.some((key) => (known[key] as number) < at);
  const previous = conversation.keyChange;
  conversation.keyChange = {
    at,
    kind: replaced || previous?.kind === "replaced" ? "replaced" : "added",
    keys: [...new Set([...(previous?.keys ?? []), ...fresh])],
  };
}

export async function acknowledgeKeyChange(conversation: Conversation): Promise<void> {
  delete conversation.keyChange;
  await persistVault();
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
