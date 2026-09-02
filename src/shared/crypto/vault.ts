/**
 * Password handling and the local key vault.
 *
 * The password never leaves the browser. It is stretched once with Argon2id and split
 * into two independent 32-byte halves:
 *
 *   authSecret  -> sent to the server, which stores only Argon2id(authSecret, random salt)
 *   vaultKey    -> stays on the device and encrypts the private key material
 *
 * Consequence (this is the point): a compromised or hostile server learns nothing that
 * lets it decrypt a vault backup, because the two halves are independent HKDF outputs of
 * the same Argon2id result and the server only ever sees one of them — after a second,
 * server-side Argon2id pass.
 *
 * The salt is derived deterministically from the username so that a client can log in on
 * a new device without the server first telling it a per-user salt (which would be a
 * user-enumeration oracle). Documented cost: usernames are salts, so identical passwords
 * under different usernames still differ, but the salt is not secret.
 */
import { concat, utf8 } from "../encoding.ts";
import { aeadDecrypt, aeadEncrypt } from "./aead.ts";
import { hkdf } from "./hkdf.ts";
import { randomBytes, sodium } from "./sodium.ts";

const SALT_CONTEXT = utf8("ergeshah-password-salt-v1");
const AUTH_INFO = utf8("ergeshah-auth-secret-v1");
const VAULT_INFO = utf8("ergeshah-vault-key-v1");
const ZERO_SALT = new Uint8Array(32);

/** Client-side Argon2id cost. Browser-friendly but far above a bare hash. */
export const CLIENT_ARGON2_OPS = 3;
export const CLIENT_ARGON2_MEMORY = 64 * 1024 * 1024;

export interface AccountKeys {
  authSecret: Uint8Array;
  vaultKey: Uint8Array;
}

export function passwordSalt(username: string): Uint8Array {
  const s = sodium();
  return s.crypto_generichash(
    s.crypto_pwhash_SALTBYTES,
    concat(SALT_CONTEXT, utf8(normalizeUsername(username))),
  );
}

export function normalizeUsername(username: string): string {
  return username.normalize("NFKC").trim().toLowerCase();
}

export function deriveAccountKeys(
  username: string,
  password: string,
  options: { opsLimit?: number; memLimit?: number } = {},
): AccountKeys {
  const s = sodium();
  const stretched = s.crypto_pwhash(
    32,
    password.normalize("NFKC"),
    passwordSalt(username),
    options.opsLimit ?? CLIENT_ARGON2_OPS,
    options.memLimit ?? CLIENT_ARGON2_MEMORY,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  const keys: AccountKeys = {
    authSecret: hkdf(stretched, ZERO_SALT, AUTH_INFO, 32),
    vaultKey: hkdf(stretched, ZERO_SALT, VAULT_INFO, 32),
  };
  stretched.fill(0);
  return keys;
}

/**
 * Version 2: same sealing construction, but the session state inside gained header keys
 * (ADR-0011). A version-1 blob cannot be interpreted by this code, so it is rejected
 * rather than half-read into a session with missing keys.
 */
export interface SealedVault {
  v: 2;
  nonce: string;
  data: string;
}

export function sealVault(vaultKey: Uint8Array, plaintext: Uint8Array): SealedVault {
  const nonce = randomBytes(24);
  const ciphertext = aeadEncrypt(vaultKey, plaintext, utf8("ergeshah-vault"), nonce);
  return { v: 2, nonce: b64(nonce), data: b64(ciphertext) };
}

export function openVault(vaultKey: Uint8Array, sealed: SealedVault): Uint8Array {
  if (sealed.v !== 2) {
    throw new Error("vault: unsupported version — sealed by an incompatible client");
  }
  return aeadDecrypt(vaultKey, unb64(sealed.data), utf8("ergeshah-vault"), unb64(sealed.nonce));
}

function b64(bytes: Uint8Array): string {
  return sodium().to_base64(bytes, sodium().base64_variants.URLSAFE_NO_PADDING);
}

function unb64(text: string): Uint8Array {
  return sodium().from_base64(text, sodium().base64_variants.URLSAFE_NO_PADDING);
}
