/**
 * Authenticated encryption: XChaCha20-Poly1305-IETF.
 *
 * Chosen over AES-GCM because it is constant-time in software everywhere (no AES-NI
 * dependency in WASM), and its 24-byte nonce makes random nonces safe. Every message key
 * is used exactly once, so nonce reuse would require a protocol bug, not a birthday bound.
 */
import { sodium } from "./sodium.ts";

export const NONCE_BYTES = 24;
const KEY_BYTES = 32;

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_BYTES) throw new Error("aead: bad key length");
  if (nonce.length !== NONCE_BYTES) throw new Error("aead: bad nonce length");
  return sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    associatedData,
    null,
    nonce,
    key,
  );
}

export function aeadDecrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_BYTES) throw new Error("aead: bad key length");
  if (nonce.length !== NONCE_BYTES) throw new Error("aead: bad nonce length");
  return sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    associatedData,
    nonce,
    key,
  );
}
