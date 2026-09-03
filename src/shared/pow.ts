/**
 * Proof of work: the anti-automation measure that asks nothing about you.
 *
 * A CAPTCHA asks a third party to look at your browser; a phone number asks for an
 * identity document with extra steps; both are surveillance sold as a spam filter. This
 * asks for arithmetic instead. It costs a person a fraction of a second once, and it costs
 * someone registering ten thousand accounts exactly ten thousand times that — which is the
 * asymmetry the defence is made of. It learns nothing, stores nothing about the client and
 * involves nobody else.
 *
 * The rule: find a nonce such that SHA-256 of the preimage starts with `bits` zero bits.
 * This file holds the two halves both sides must agree on byte for byte; the hash itself
 * comes from the caller, because the browser has libsodium loaded and the server
 * deliberately does not (see `src/server/lib/signatures.ts`).
 */

/** Versioned so that a future change of rule cannot be confused with the current one. */
export const POW_PREFIX = "symvolon-pow-v1";

export function powPreimage(challenge: string, nonce: number): string {
  return `${POW_PREFIX}:${challenge}:${nonce}`;
}

/** Does this digest begin with `bits` zero bits? */
export function meetsDifficulty(digest: Uint8Array, bits: number): boolean {
  let remaining = bits;
  for (const byte of digest) {
    if (remaining >= 8) {
      if (byte !== 0) return false;
      remaining -= 8;
      continue;
    }
    return remaining === 0 || byte >>> (8 - remaining) === 0;
  }
  return remaining <= 0;
}

/**
 * Search for a nonce. `hash` must be a synchronous SHA-256 — WebCrypto's is asynchronous,
 * and awaiting a promise per attempt costs more than the hashing does.
 *
 * ponytail: this blocks the thread that calls it. At the default difficulty that is a
 * fraction of a second; if the difficulty is ever raised to where it is felt, move the
 * loop into a Web Worker rather than making the search itself cleverer.
 */
export function solveProofOfWork(
  challenge: string,
  bits: number,
  hash: (input: Uint8Array) => Uint8Array,
  limit = 1 << 26,
): number {
  const encoder = new TextEncoder();
  for (let nonce = 0; nonce < limit; nonce += 1) {
    if (meetsDifficulty(hash(encoder.encode(powPreimage(challenge, nonce))), bits)) return nonce;
  }
  // Reaching this means the difficulty was raised beyond what a client can pay, which is a
  // configuration mistake, not a puzzle to keep grinding at.
  throw new Error(`no proof of work found for ${bits} bits within ${limit} attempts`);
}
