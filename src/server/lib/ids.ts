import { randomBytes, randomUUID, createHash, createHmac, timingSafeEqual } from "node:crypto";

/** Opaque, unguessable identifiers. No sequence numbers: they leak volume and order. */
export function newId(): string {
  return randomUUID();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** Accepts bytes too: link secrets are hashed as bytes, the way the browser hashes them. */
export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function hmac(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

/**
 * Compare two secrets without letting the *time* answer first.
 *
 * `a === b` on strings stops at the first differing byte, so the duration of the comparison
 * is a measurement of how much of the secret the caller guessed. It is the standard
 * mistake, and three places here were about to make it separately — the proof-of-work MAC
 * and the payout worker's bearer token each grew their own copy, and the CSRF token was
 * still compared with `!==` (finding SEC-2026-005). One helper, used by all three, is both
 * the smaller diff and the thing a static check can insist on.
 *
 * The length is compared first and *is* leaked, deliberately: `timingSafeEqual` throws on
 * buffers of different lengths, and the length of a token is not the secret.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
