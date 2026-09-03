/**
 * File encryption for blind blobs: marketplace deliveries and message attachments.
 *
 * A delivery is one file, encrypted once, for one buyer; an attachment is one file,
 * encrypted once, for one conversation. Same shape, same code, same guarantee — the
 * `context` below is the order id or the attachment id, and it is authenticated, so a blob
 * served under the wrong id fails to open instead of decrypting into confusing garbage. That makes the simplest possible
 * construction the right one: a fresh random 32-byte key, a fresh random nonce, the same
 * XChaCha20-Poly1305 the messaging layer uses, and the key handed to the buyer through the
 * encrypted channel that already carries the conversation — where forward secrecy and
 * deniability are solved. No new key exchange, no key derivation hierarchy, no second
 * protocol to review, and in particular no reliance on TLS: the transport is not what is
 * protecting these bytes (point 78).
 *
 * The file is padded with the message padding scheme before encryption, so the stored
 * length is a multiple of 4 KB rather than the exact size of the artefact.
 *
 * What this does not do: chunking or streaming. A delivery is held in memory on both
 * sides, which is why the size cap is small and honest rather than large and aspirational.
 */
import { aeadDecrypt, aeadEncrypt, NONCE_BYTES } from "./aead.ts";
import { pad, unpad } from "./padding.ts";
import { randomBytes } from "./sodium.ts";
import { utf8 } from "../encoding.ts";

/** Plaintext cap. The ciphertext, base64url-encoded, must still fit MAX_DELIVERY_BYTES. */
export const MAX_FILE_BYTES = 3 * 1024 * 1024;

export interface EncryptedFile {
  key: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function encryptFile(context: string, plaintext: Uint8Array): EncryptedFile {
  if (plaintext.length > MAX_FILE_BYTES) {
    throw new Error(`file: larger than ${MAX_FILE_BYTES} bytes`);
  }
  if (plaintext.length === 0) throw new Error("file: empty");
  const key = randomBytes(32);
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertext = aeadEncrypt(key, pad(plaintext, MAX_FILE_BYTES), utf8(context), nonce);
  return { key, nonce, ciphertext };
}

export function decryptFile(
  context: string,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return unpad(aeadDecrypt(key, ciphertext, utf8(context), nonce));
}
