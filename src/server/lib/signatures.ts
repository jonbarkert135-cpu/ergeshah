/**
 * Ed25519 signature verification, from Node's standard library.
 *
 * The browser signs with libsodium; Node verifies with OpenSSL through `node:crypto`.
 * Both implement the same RFC 8032 signature scheme, so no third library is needed and
 * libsodium's WASM never has to be loaded into the server process.
 *
 * `crypto` wants a key object, and an Ed25519 public key is 32 raw bytes, so the bytes
 * are wrapped in the fixed 12-byte SPKI header for `id-Ed25519` (RFC 8410). The header is
 * a constant, not a parser: nothing here interprets attacker-supplied structure.
 */
import { createPublicKey, verify } from "node:crypto";

const SPKI_ED25519_HEADER = Buffer.from("302a300506032b6570032100", "hex");
const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

export function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== PUBLIC_KEY_BYTES || signature.length !== SIGNATURE_BYTES) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_HEADER, Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    return verify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    // A malformed key or signature is a failed verification, never an exception upstream.
    return false;
  }
}
