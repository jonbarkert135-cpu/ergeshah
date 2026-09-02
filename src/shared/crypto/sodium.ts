/**
 * Single place where libsodium is loaded.
 *
 * We use libsodium (via `libsodium-wrappers-sumo`) for every primitive: it is an audited
 * implementation of exactly the primitives this protocol needs, it runs identically in
 * Node and in the browser (WASM), and it is vendored locally — no CDN. See ADR-0003.
 */
import _sodium from "libsodium-wrappers-sumo";

/**
 * The published type definitions omit libsodium's streaming HMAC functions, which we
 * need for RFC 5869 HKDF (its extract step takes a salt of arbitrary length, which the
 * one-shot API rejects). The functions exist in the runtime; we declare their shape here
 * rather than reaching for `any` at every call site.
 */
interface StreamingHmac {
  crypto_auth_hmacsha256_init(key: Uint8Array): unknown;
  crypto_auth_hmacsha256_update(state: unknown, message: Uint8Array): void;
  crypto_auth_hmacsha256_final(state: unknown): Uint8Array;
}

export type Sodium = typeof _sodium & StreamingHmac;

let cached: Sodium | null = null;

export async function sodiumReady(): Promise<Sodium> {
  if (cached) return cached;
  await _sodium.ready;
  cached = _sodium as Sodium;
  return cached;
}

/** Throws if libsodium has not been initialised yet — used by synchronous helpers. */
export function sodium(): Sodium {
  if (!cached) throw new Error("libsodium not initialised: await sodiumReady() first");
  return cached;
}

export function randomBytes(length: number): Uint8Array {
  return sodium().randombytes_buf(length);
}
