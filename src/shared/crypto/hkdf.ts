/**
 * HKDF-SHA256 (RFC 5869) built on libsodium's HMAC-SHA256.
 *
 * We do not invent a KDF: this is the standard extract-and-expand construction, and the
 * implementation is verified against the RFC 5869 test vectors in `test/hkdf.test.ts`.
 */
import { concat } from "../encoding.ts";
import { sodium } from "./sodium.ts";

const HASH_LEN = 32;

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  const s = sodium();
  const state = s.crypto_auth_hmacsha256_init(key);
  s.crypto_auth_hmacsha256_update(state, message);
  return s.crypto_auth_hmacsha256_final(state);
}

export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt, ikm);
}

export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (length > 255 * HASH_LEN) throw new Error("hkdf: requested length too large");
  const blocks: Uint8Array[] = [];
  let previous: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  for (let counter = 1; blocks.reduce((n, b) => n + b.length, 0) < length; counter += 1) {
    previous = hmacSha256(prk, concat(previous, info, Uint8Array.of(counter)));
    blocks.push(previous);
  }
  return new Uint8Array(concat(...blocks).subarray(0, length));
}

export function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdfExpand(hkdfExtract(salt, ikm), info, length);
}
