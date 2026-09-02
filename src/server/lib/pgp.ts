/**
 * OpenPGP public keys and detached signatures.
 *
 * The server only ever sees public keys and signatures: it hands out a random challenge,
 * the user signs it with `gpg` on their own machine, and this file checks the signature.
 * A private key has no reason to arrive here, so one that does is rejected loudly rather
 * than quietly ignored.
 *
 * Parsing OpenPGP is a packet format with decades of edge cases and a long CVE history;
 * it is exactly the kind of code not to write by hand. `openpgp` (LGPL-3.0+, no
 * dependencies of its own, audited by Cure53) does it — see ADR-0015.
 */
import { createMessage, readKey, readSignature, verify } from "openpgp";

/** Armour is text; a megabyte of it is not a key, it is a parser stress test. */
const MAX_ARMOUR_BYTES = 64 * 1024;

export class PgpError extends Error {}

function checkArmour(value: string, what: string): string {
  const armour = value.trim();
  if (armour.length > MAX_ARMOUR_BYTES) throw new PgpError(`that ${what} is too large`);
  if (armour.includes("PRIVATE KEY BLOCK")) {
    throw new PgpError("that is a private key — keep it, never send it anywhere");
  }
  if (!armour.startsWith("-----BEGIN PGP")) {
    throw new PgpError(`that does not look like an armoured ${what}`);
  }
  return armour;
}

export interface PgpKeyFacts {
  /** Lower-case hex, no spaces: what goes in the database. */
  fingerprint: string;
  /** The same fingerprint in the grouped form people compare out loud. */
  readable: string;
  algorithm: string;
  /** Whatever the key says about itself. Unverified, and displayed as such. */
  identities: string[];
}

/** Group a fingerprint the way `gpg --fingerprint` does, so the two can be compared. */
export function readableFingerprint(fingerprint: string): string {
  return (fingerprint.toUpperCase().match(/.{1,4}/g) ?? []).join(" ");
}

/**
 * Accept a public key, or explain why not. A key that cannot sign is refused here rather
 * than later: enabling a key nobody can use would only lock the account out of itself.
 */
export async function inspectPublicKey(armored: string): Promise<PgpKeyFacts> {
  const armour = checkArmour(armored, "public key");
  let key;
  try {
    key = await readKey({ armoredKey: armour });
  } catch (error) {
    throw new PgpError(`that public key could not be read: ${(error as Error).message}`);
  }
  if (key.isPrivate()) throw new PgpError("that is a private key — keep it, never send it anywhere");
  try {
    await key.getSigningKey();
  } catch (error) {
    throw new PgpError(`that key cannot sign: ${(error as Error).message}`);
  }

  const fingerprint = key.getFingerprint().toLowerCase();
  return {
    fingerprint,
    readable: readableFingerprint(fingerprint),
    algorithm: key.getAlgorithmInfo().algorithm,
    identities: key.getUserIDs().slice(0, 4),
  };
}

/**
 * True only if `signature` is a detached signature over exactly `challenge`, made by
 * `armoredKey`, valid at the time it was made. Anything else — a signature over other
 * text, from another key, from a revoked or expired key — is false, never an exception,
 * because callers treat a failed proof and a malformed proof identically.
 */
export async function verifyDetachedSignature(
  armoredKey: string,
  challenge: string,
  armoredSignature: string,
): Promise<boolean> {
  try {
    const armour = checkArmour(armoredSignature, "signature");
    const key = await readKey({ armoredKey });
    const result = await verify({
      message: await createMessage({ text: challenge }),
      signature: await readSignature({ armoredSignature: armour }),
      verificationKeys: key,
      expectSigned: true,
    });
    // `expectSigned` makes the promise reject unless a signature verified against a key
    // we supplied, so reaching here with a settled promise is the whole check.
    await result.signatures[0]?.verified;
    return result.signatures.length > 0;
  } catch {
    return false;
  }
}
