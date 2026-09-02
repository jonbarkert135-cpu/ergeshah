/**
 * Server-side password handling.
 *
 * The server never sees a password. It receives `authSecret` — 32 bytes the client
 * derived from the password with Argon2id — and hashes *that* before storage, so a
 * database leak yields no password material and a hostile server can never derive the
 * vault key protecting the user's private keys.
 *
 * The stored hash uses scrypt from Node's standard library (RFC 7914, N=2^15, r=8, p=1).
 * Argon2id would be the better choice for hashing a *password*; the input here is already
 * a 256-bit Argon2id-derived secret, so the work factor that actually resists password
 * guessing is the client's, and this layer is defence in depth against a leaked table.
 * Standard-library scrypt buys that with no native dependency and without blocking the
 * event loop, which a WASM Argon2id call would do on every login.
 */
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const COST = { N: 32_768, r: 8, p: 1, keyLength: 32 } as const;
const PREFIX = "scrypt";

function derive(secret: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // maxmem must be raised explicitly: the default rejects N above 2^14.
    scrypt(secret, salt, COST.keyLength, { ...COST, maxmem: 256 * COST.N * COST.r }, (error, key) =>
      error ? reject(error) : resolve(key),
    );
  });
}

export async function hashAuthSecret(authSecret: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(authSecret, salt);
  return `${PREFIX}$${COST.N}$${COST.r}$${COST.p}$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

/**
 * A missing account still spends the derivation, so login timing cannot be used as a
 * user-enumeration oracle.
 */
export async function verifyAuthSecret(
  storedHash: string | null,
  authSecret: string,
): Promise<boolean> {
  const parts = (storedHash ?? "").split("$");
  const salt = parts.length === 6 && parts[0] === PREFIX ? Buffer.from(parts[4]!, "base64url") : randomBytes(16);
  const expected = parts.length === 6 ? Buffer.from(parts[5]!, "base64url") : randomBytes(32);
  const actual = await derive(authSecret, salt);
  return actual.length === expected.length && timingSafeEqual(actual, expected) && parts[0] === PREFIX;
}
