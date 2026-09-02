/**
 * Session establishment, modelled on the published X3DH specification (Signal, rev. 1,
 * 2016) using X25519 and HKDF-SHA256.
 *
 * Properties inherited from the specification: mutual authentication of both identity
 * keys, forward secrecy once the one-time prekey is consumed, and cryptographic
 * deniability (no signature over the message itself). Deviations from the spec are
 * listed in `docs/CRYPTO.md`; the protocol is *not* a drop-in Signal implementation and
 * does not interoperate with Signal.
 */
import { concat, utf8 } from "../encoding.ts";
import { hkdf } from "./hkdf.ts";
import {
  dh,
  generateX25519KeyPair,
  identityToX25519Private,
  identityToX25519Public,
  verifySignedPreKey,
  type KeyPair,
} from "./identity.ts";

const INFO = utf8("ergeshah-x3dh-v1");
const F = new Uint8Array(32).fill(0xff);
const ZERO_SALT = new Uint8Array(32);

export interface InitiatorBundle {
  identityKey: Uint8Array; // Ed25519 public identity of the responder
  signedPreKeyId: number;
  signedPreKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKeyId?: number | null;
  oneTimePreKey?: Uint8Array | null;
}

export interface InitiatorResult {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  usedSignedPreKeyId: number;
  usedOneTimePreKeyId: number | null;
}

export interface ResponderInput {
  identity: KeyPair; // responder Ed25519 identity keypair
  signedPreKey: KeyPair; // X25519
  oneTimePreKey?: KeyPair | null; // X25519, consumed and destroyed after use
  initiatorIdentityKey: Uint8Array; // Ed25519 public
  initiatorEphemeralKey: Uint8Array; // X25519 public
}

export function x3dhInitiate(
  initiatorIdentity: KeyPair,
  bundle: InitiatorBundle,
): InitiatorResult {
  if (
    !verifySignedPreKey(
      bundle.identityKey,
      bundle.signedPreKey,
      bundle.signedPreKeyId,
      bundle.signedPreKeySignature,
    )
  ) {
    throw new Error("x3dh: signed prekey signature is invalid — refusing to start session");
  }

  const ephemeral = generateX25519KeyPair();
  const initiatorPrivateX = identityToX25519Private(initiatorIdentity.privateKey);
  const responderIdentityX = identityToX25519Public(bundle.identityKey);

  const dh1 = dh(initiatorPrivateX, bundle.signedPreKey);
  const dh2 = dh(ephemeral.privateKey, responderIdentityX);
  const dh3 = dh(ephemeral.privateKey, bundle.signedPreKey);
  const parts = [F, dh1, dh2, dh3];
  if (bundle.oneTimePreKey) parts.push(dh(ephemeral.privateKey, bundle.oneTimePreKey));

  const sharedSecret = hkdf(concat(...parts), ZERO_SALT, INFO, 32);
  return {
    sharedSecret,
    associatedData: concat(initiatorIdentity.publicKey, bundle.identityKey),
    ephemeralPublicKey: ephemeral.publicKey,
    usedSignedPreKeyId: bundle.signedPreKeyId,
    usedOneTimePreKeyId: bundle.oneTimePreKey ? (bundle.oneTimePreKeyId ?? null) : null,
  };
}

export function x3dhRespond(input: ResponderInput): {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
} {
  const responderPrivateX = identityToX25519Private(input.identity.privateKey);
  const initiatorIdentityX = identityToX25519Public(input.initiatorIdentityKey);

  const dh1 = dh(input.signedPreKey.privateKey, initiatorIdentityX);
  const dh2 = dh(responderPrivateX, input.initiatorEphemeralKey);
  const dh3 = dh(input.signedPreKey.privateKey, input.initiatorEphemeralKey);
  const parts = [F, dh1, dh2, dh3];
  if (input.oneTimePreKey) {
    parts.push(dh(input.oneTimePreKey.privateKey, input.initiatorEphemeralKey));
  }

  return {
    sharedSecret: hkdf(concat(...parts), ZERO_SALT, INFO, 32),
    associatedData: concat(input.initiatorIdentityKey, input.identity.publicKey),
  };
}
