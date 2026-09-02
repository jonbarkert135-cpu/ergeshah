/**
 * Single place where libsodium is loaded.
 *
 * We use libsodium (via `libsodium-wrappers-sumo`) for every primitive: it is an audited
 * implementation of exactly the primitives this protocol needs, it runs identically in
 * Node and in the browser (WASM), and it is vendored locally — no CDN. See ADR-0003.
 */
import type _sodiumType from "libsodium-wrappers-sumo";

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

export type Sodium = typeof _sodiumType & StreamingHmac;

let cached: Sodium | null = null;
let loading: Promise<Sodium> | null = null;

/**
 * Loaded on demand, not at import time. libsodium is a megabyte of WebAssembly — most of
 * the weight of this client — and a visitor reading the sign-in page does not need it
 * until they submit. The dynamic import makes esbuild emit it as a separate chunk, so the
 * shell paints while the cryptography is still arriving (ADR-0027).
 *
 * The promise is memoised, so twenty concurrent callers cause one download and one
 * initialisation.
 */
export async function sodiumReady(): Promise<Sodium> {
  if (cached) return cached;
  loading ??= (async () => {
    const module = await import("libsodium-wrappers-sumo");
    const library = (module.default ?? module) as typeof _sodiumType;
    await library.ready;
    cached = library as Sodium;
    return cached;
  })();
  return loading;
}

/** Throws if libsodium has not been initialised yet — used by synchronous helpers. */
export function sodium(): Sodium {
  if (!cached) throw new Error("libsodium not initialised: await sodiumReady() first");
  return cached;
}

export function randomBytes(length: number): Uint8Array {
  return sodium().randombytes_buf(length);
}
