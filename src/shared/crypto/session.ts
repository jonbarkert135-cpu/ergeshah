/**
 * The API the application code actually uses: open a session from a prekey bundle,
 * accept one from an initial message, encrypt, decrypt. Everything below this line is
 * protocol; everything above it is product.
 */
import { fromBase64Url, toBase64Url, utf8, fromUtf8 } from "../encoding.ts";
import {
  decodeMessage,
  encodeMessage,
  initiateSession,
  acceptSession as acceptRatchet,
  ratchetDecrypt,
  ratchetEncrypt,
  type RatchetState,
} from "./ratchet.ts";
import { x3dhInitiate, x3dhRespond, type InitiatorBundle } from "./x3dh.ts";
import type { KeyPair, PreKey } from "./identity.ts";

/** Sent alongside the first ciphertext so the responder can rebuild the same secret. */
export interface SessionInvite {
  identityKey: string;
  ephemeralKey: string;
  signedPreKeyId: number;
  oneTimePreKeyId: number | null;
}

export interface OutgoingSession {
  state: RatchetState;
  invite: SessionInvite;
}

export function openSession(
  identity: KeyPair,
  bundle: InitiatorBundle,
): OutgoingSession {
  const result = x3dhInitiate(identity, bundle);
  const state = initiateSession(result.sharedSecret, bundle.signedPreKey, result.associatedData);
  result.sharedSecret.fill(0);
  return {
    state,
    invite: {
      identityKey: toBase64Url(identity.publicKey),
      ephemeralKey: toBase64Url(result.ephemeralPublicKey),
      signedPreKeyId: result.usedSignedPreKeyId,
      oneTimePreKeyId: result.usedOneTimePreKeyId,
    },
  };
}

export function acceptSession(
  identity: KeyPair,
  signedPreKey: PreKey,
  oneTimePreKey: PreKey | null,
  invite: SessionInvite,
): RatchetState {
  const { sharedSecret, associatedData } = x3dhRespond({
    identity,
    signedPreKey: signedPreKey.keyPair,
    oneTimePreKey: oneTimePreKey ? oneTimePreKey.keyPair : null,
    initiatorIdentityKey: fromBase64Url(invite.identityKey),
    initiatorEphemeralKey: fromBase64Url(invite.ephemeralKey),
  });
  const state = acceptRatchet(sharedSecret, signedPreKey.keyPair, associatedData);
  sharedSecret.fill(0);
  return state;
}

export function encryptText(state: RatchetState, text: string): string {
  return encodeMessage(ratchetEncrypt(state, utf8(text)));
}

export function decryptText(state: RatchetState, payload: string): string {
  return fromUtf8(ratchetDecrypt(state, decodeMessage(payload)));
}
