/**
 * Recovery, from the browser's side.
 *
 * A recovery phrase is generated here, shown once, and never sent anywhere. What the
 * server receives is the *public* half of a signing key derived from it, and later a
 * signature over a challenge. What the phrase unlocks is the wrapped master key inside
 * the vault backup, which is why a recovered account still has its conversations.
 *
 * The phrase is the strongest secret in the system by design: whoever holds it can take
 * the account and read its history. There is no email and no support desk that can undo
 * that, which the interface says out loud rather than in a tooltip.
 */
import { api } from "./api.ts";
import {
  deriveAccountKeys,
  deriveRecoveryKeys,
  signWithRecoveryKey,
  unwrapMasterKey,
  wrapMasterKey,
  type VaultBackup,
} from "../shared/crypto/vault.ts";
import { fromBase64Url, toBase64Url, utf8 } from "../shared/encoding.ts";
import type { Account } from "./state.ts";

export interface RecoveryResult {
  account: Account;
  backup: VaultBackup | null;
  masterKey: Uint8Array | null;
}

/**
 * Use a phrase to take back an account and set a new password.
 *
 * Order matters: the server verifies the signature, rotates the password and destroys
 * every old session before it hands back the vault backup. Only then can this code
 * unwrap the master key with the phrase and rewrap it under the new password.
 */
export async function recoverAccount(
  username: string,
  phrase: string,
  newPassword: string,
): Promise<RecoveryResult> {
  const recovery = deriveRecoveryKeys(username, phrase);
  const next = deriveAccountKeys(username, newPassword);
  try {
    const challenge = await api<{ challengeId: string; challenge: string }>(
      "/api/auth/recovery/challenge",
      { method: "POST", body: { username } },
    );
    const signature = signWithRecoveryKey(
      recovery.signPrivateKey,
      utf8(challenge.challenge),
    );

    const completed = await api<{
      id: string;
      username: string;
      role: string;
      sealedVault: VaultBackup | null;
    }>("/api/auth/recovery/complete", {
      method: "POST",
      body: {
        challengeId: challenge.challengeId,
        signature: toBase64Url(signature),
        newAuthSecret: toBase64Url(next.authSecret),
      },
    });

    const account: Account = {
      id: completed.id,
      username: completed.username,
      role: completed.role as Account["role"],
    };
    if (!completed.sealedVault?.recovery) {
      // Access is back, history is not: either no backup existed or the account was
      // created without a recoverable copy of its keys.
      return { account, backup: null, masterKey: null };
    }

    const masterKey = unwrapMasterKey(recovery.wrapKey, completed.sealedVault.recovery);
    const backup: VaultBackup = {
      v: 3,
      vault: completed.sealedVault.vault,
      password: wrapMasterKey(next.wrapKey, masterKey),
      recovery: completed.sealedVault.recovery,
    };
    await api("/api/keys/vault", { method: "PUT", body: { sealedVault: backup } });
    return { account, backup, masterKey };
  } finally {
    recovery.wrapKey.fill(0);
    recovery.signPrivateKey.fill(0);
    next.authSecret.fill(0);
    next.wrapKey.fill(0);
  }
}

/** Attach (or replace) a recovery phrase on an account that already exists. */
export async function setRecoveryPhrase(
  username: string,
  password: string,
  phrase: string,
  masterKey: Uint8Array,
  backup: VaultBackup,
): Promise<VaultBackup> {
  const account = deriveAccountKeys(username, password);
  const recovery = deriveRecoveryKeys(username, phrase);
  try {
    const updated: VaultBackup = {
      ...backup,
      recovery: wrapMasterKey(recovery.wrapKey, masterKey),
    };
    await api("/api/auth/recovery/key", {
      method: "POST",
      body: {
        authSecret: toBase64Url(account.authSecret),
        recoveryPublicKey: toBase64Url(recovery.signPublicKey),
        sealedVault: updated,
      },
    });
    return updated;
  } finally {
    account.authSecret.fill(0);
    account.wrapKey.fill(0);
    recovery.wrapKey.fill(0);
    recovery.signPrivateKey.fill(0);
  }
}

/** The public key the server may keep, and the wrap key it must never see. */
export function recoveryMaterial(username: string, phrase: string) {
  const keys = deriveRecoveryKeys(username, phrase);
  return {
    publicKey: toBase64Url(keys.signPublicKey),
    wrapKey: keys.wrapKey,
    forget: () => {
      keys.wrapKey.fill(0);
      keys.signPrivateKey.fill(0);
    },
  };
}

/** Decode a base64url signature the way the server expects to receive it. */
export function decodeSignature(signature: string): Uint8Array {
  return fromBase64Url(signature);
}
