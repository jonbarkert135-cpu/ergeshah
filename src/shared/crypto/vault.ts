/**
 * Password handling, recovery material, and the local key vault.
 *
 * Three layers, so that no single leaked secret unlocks everything:
 *
 *   password  --Argon2id--> authSecret  (to the server, hashed again with scrypt)
 *                        \-> wrapKey    (never leaves the device)
 *   phrase    --Argon2id--> recoveryWrapKey + a recovery signing keypair
 *   master key (random 32 bytes)  seals the vault itself
 *
 * The master key is what actually encrypts the vault, and it exists twice on the server
 * as an opaque wrapped blob: once under the password wrap key, once under the recovery
 * wrap key. Changing a password rewraps 32 bytes instead of re-encrypting a vault, and a
 * recovery phrase can restore the *contents*, not merely the account. Neither wrap is
 * openable by the server, which holds no key to either.
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
import { decodePhrase } from "./mnemonic.ts";
import { aeadDecrypt, aeadEncrypt } from "./aead.ts";
import { hkdf } from "./hkdf.ts";
import { randomBytes, sodium } from "./sodium.ts";

// The `ergeshah-` prefix in these labels is the project's first name. Labels are opaque
// domain separators: renaming them would invalidate every derived key and buy nothing, so
// they stay as they are (ADR-0013).
const SALT_CONTEXT = utf8("ergeshah-password-salt-v1");
const AUTH_INFO = utf8("ergeshah-auth-secret-v1");
const VAULT_INFO = utf8("ergeshah-vault-key-v1");
/** Recovery labels are new, so they carry the current project name. */
const RECOVERY_SALT_CONTEXT = utf8("symvolon-recovery-salt-v1");
const RECOVERY_WRAP_INFO = utf8("symvolon-recovery-wrap-key-v1");
const RECOVERY_SIGN_INFO = utf8("symvolon-recovery-sign-seed-v1");
const MASTER_KEY_CONTEXT = utf8("symvolon-master-key-v1");
const ZERO_SALT = new Uint8Array(32);

/** Client-side Argon2id cost. Browser-friendly but far above a bare hash. */
const CLIENT_ARGON2_OPS = 3;
const CLIENT_ARGON2_MEMORY = 64 * 1024 * 1024;

export interface AccountKeys {
  authSecret: Uint8Array;
  /** Wraps the master key. Not the vault key any more: it never touches the vault. */
  wrapKey: Uint8Array;
}

export interface RecoveryKeys {
  /** Wraps the master key, so a phrase restores message history and not just access. */
  wrapKey: Uint8Array;
  /** Ed25519 pair used to answer the server's recovery challenge. */
  signPublicKey: Uint8Array;
  signPrivateKey: Uint8Array;
}

function passwordSalt(username: string): Uint8Array {
  const s = sodium();
  return s.crypto_generichash(
    s.crypto_pwhash_SALTBYTES,
    concat(SALT_CONTEXT, utf8(normalizeUsername(username))),
  );
}

function normalizeUsername(username: string): string {
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
    wrapKey: hkdf(stretched, ZERO_SALT, VAULT_INFO, 32),
  };
  stretched.fill(0);
  return keys;
}

/**
 * Turn a recovery phrase into the two things recovery needs: a key that unwraps the
 * master key, and a signing pair that proves ownership of the account to the server.
 *
 * The phrase's entropy — not its text — is the KDF input, so spacing and case cannot
 * change the result. Argon2id runs at the same cost as the password path: a phrase is
 * far stronger than a password, but the wrapped master key sits in a database that may
 * one day leak, and stretching costs the attacker the same as it costs us.
 */
export function deriveRecoveryKeys(
  username: string,
  phrase: string,
  options: { opsLimit?: number; memLimit?: number } = {},
): RecoveryKeys {
  const s = sodium();
  const entropy = decodePhrase(phrase);
  const salt = s.crypto_generichash(
    s.crypto_pwhash_SALTBYTES,
    concat(RECOVERY_SALT_CONTEXT, utf8(normalizeUsername(username))),
  );
  const stretched = s.crypto_pwhash(
    32,
    entropy,
    salt,
    options.opsLimit ?? CLIENT_ARGON2_OPS,
    options.memLimit ?? CLIENT_ARGON2_MEMORY,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  entropy.fill(0);

  const seed = hkdf(stretched, ZERO_SALT, RECOVERY_SIGN_INFO, s.crypto_sign_SEEDBYTES);
  const pair = s.crypto_sign_seed_keypair(seed);
  const keys: RecoveryKeys = {
    wrapKey: hkdf(stretched, ZERO_SALT, RECOVERY_WRAP_INFO, 32),
    signPublicKey: pair.publicKey,
    signPrivateKey: pair.privateKey,
  };
  stretched.fill(0);
  seed.fill(0);
  return keys;
}

/** Sign a server challenge with the recovery key. The phrase itself is never sent. */
export function signWithRecoveryKey(
  signPrivateKey: Uint8Array,
  challenge: Uint8Array,
): Uint8Array {
  return sodium().crypto_sign_detached(challenge, signPrivateKey);
}

/** The key that actually encrypts the vault. Random, never derived from a password. */
export function generateMasterKey(): Uint8Array {
  return randomBytes(32);
}

/** A master key sealed under some wrapping key: what the server stores, twice. */
export interface KeyEnvelope {
  nonce: string;
  data: string;
}

export function wrapMasterKey(wrapKey: Uint8Array, masterKey: Uint8Array): KeyEnvelope {
  const nonce = randomBytes(24);
  return {
    nonce: b64(nonce),
    data: b64(aeadEncrypt(wrapKey, masterKey, MASTER_KEY_CONTEXT, nonce)),
  };
}

export function unwrapMasterKey(wrapKey: Uint8Array, envelope: KeyEnvelope): Uint8Array {
  return aeadDecrypt(wrapKey, unb64(envelope.data), MASTER_KEY_CONTEXT, unb64(envelope.nonce));
}

/**
 * Version 3: the vault is sealed with the master key rather than with a password-derived
 * key, and travels inside a `VaultBackup` that carries the wrapped master key alongside
 * it. Older versions are refused rather than half-read (ADR-0011, ADR-0014).
 */
export interface SealedVault {
  v: 3;
  nonce: string;
  data: string;
}

/**
 * What the browser stores locally and backs up to the server: the sealed vault plus one
 * wrapped copy of the master key per unlocking route. `recovery` is absent when the user
 * declined a recoverable backup, in which case a lost password means lost history — a
 * choice the UI makes explicit rather than a default nobody was told about.
 */
export interface VaultBackup {
  v: 3;
  vault: SealedVault;
  password: KeyEnvelope;
  recovery?: KeyEnvelope | null;
}

export function sealVault(masterKey: Uint8Array, plaintext: Uint8Array): SealedVault {
  const nonce = randomBytes(24);
  const ciphertext = aeadEncrypt(masterKey, plaintext, utf8("ergeshah-vault"), nonce);
  return { v: 3, nonce: b64(nonce), data: b64(ciphertext) };
}

export function openVault(masterKey: Uint8Array, sealed: SealedVault): Uint8Array {
  if (sealed.v !== 3) {
    throw new Error("vault: unsupported version — sealed by an incompatible client");
  }
  return aeadDecrypt(masterKey, unb64(sealed.data), utf8("ergeshah-vault"), unb64(sealed.nonce));
}

function b64(bytes: Uint8Array): string {
  return sodium().to_base64(bytes, sodium().base64_variants.URLSAFE_NO_PADDING);
}

function unb64(text: string): Uint8Array {
  return sodium().from_base64(text, sodium().base64_variants.URLSAFE_NO_PADDING);
}
