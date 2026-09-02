/**
 * Server-side password handling.
 *
 * The server receives `authSecret` — already stretched by the client with Argon2id — and
 * hashes it *again* with Argon2id before storage. Two reasons:
 *  1. a database leak yields no offline-crackable password material beyond a full
 *     Argon2id-over-Argon2id chain;
 *  2. a hostile server never sees the password itself, so it can never derive the vault
 *     key that protects the user's private keys.
 */
import { hash, verify } from "@node-rs/argon2";

/** OWASP-recommended Argon2id baseline (19 MiB, t=2, p=1), applied to a 32-byte secret. */
const PARAMS = {
  algorithm: 2, // Algorithm.Argon2id — numeric literal keeps the import type-only
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

/**
 * Hash of a constant, used when the username does not exist so that login spends the
 * same work either way and cannot be used as a user-enumeration oracle.
 */
let dummyHash: string | null = null;

export async function hashAuthSecret(authSecret: string): Promise<string> {
  return hash(authSecret, PARAMS);
}

export async function verifyAuthSecret(
  storedHash: string | null,
  authSecret: string,
): Promise<boolean> {
  if (!storedHash) {
    dummyHash ??= await hash("account-does-not-exist", PARAMS);
    await verify(dummyHash, authSecret).catch(() => false);
    return false;
  }
  return verify(storedHash, authSecret).catch(() => false);
}
