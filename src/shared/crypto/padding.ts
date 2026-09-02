/**
 * Length hiding for message plaintexts.
 *
 * An encrypted message still has a size, and size is content: "yes" and a 4 KB paste are
 * trivially distinguishable to anyone holding the ciphertext, and a sequence of sizes is
 * a fingerprint of a conversation. Padding to a small set of buckets replaces the exact
 * length with a coarse one, so an observer learns the bucket rather than the byte count.
 *
 * Scheme: append the marker byte 0x80, then zero bytes up to the next bucket boundary
 * (ISO/IEC 7816-4 padding). It is unambiguous — strip trailing zeros, expect the marker —
 * and, unlike a length prefix, adds no field an attacker can lie about: the padding is
 * inside the AEAD, so a modified length fails authentication before it is ever parsed.
 *
 * What this does *not* hide: the bucket itself, how many messages are sent, and when.
 * See `docs/THREAT_MODEL.md` for the traffic-analysis residual risk.
 */

/** Bucket boundaries, in bytes of padded output. Beyond the last one, multiples of it. */
const BUCKETS = [64, 256, 1024, 4096] as const;
const BUCKET_STEP = 4096;
const MARKER = 0x80;

/** Larger plaintexts are a file transfer, not a chat message, and get their own path. */
export const MAX_PLAINTEXT_BYTES = 32 * 1024;

export function paddedLength(plaintextLength: number): number {
  const withMarker = plaintextLength + 1;
  for (const bucket of BUCKETS) {
    if (withMarker <= bucket) return bucket;
  }
  return Math.ceil(withMarker / BUCKET_STEP) * BUCKET_STEP;
}

/**
 * `limit` exists for the file path: a delivery is padded by the same scheme (multiples of
 * 4 KB once past the small buckets), it is simply allowed to be much larger than a chat
 * message. Everything else — the marker, `unpad`, the guarantees — is shared.
 */
export function pad(plaintext: Uint8Array, limit = MAX_PLAINTEXT_BYTES): Uint8Array {
  if (plaintext.length > limit) {
    throw new Error(`padding: plaintext exceeds ${limit} bytes`);
  }
  const padded = new Uint8Array(paddedLength(plaintext.length));
  padded.set(plaintext, 0);
  padded[plaintext.length] = MARKER;
  return padded;
}

export function unpad(padded: Uint8Array): Uint8Array {
  let index = padded.length - 1;
  while (index >= 0 && padded[index] === 0x00) index -= 1;
  if (index < 0 || padded[index] !== MARKER) {
    // Only reachable for authenticated-but-malformed plaintext, i.e. a peer bug or a
    // deliberate probe from someone who already holds the message key.
    throw new Error("padding: malformed padding");
  }
  return padded.subarray(0, index);
}
