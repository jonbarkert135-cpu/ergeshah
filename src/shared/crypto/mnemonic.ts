/**
 * Recovery phrases, in the BIP-39 encoding.
 *
 * Only the *encoding* is borrowed: entropy from the OS CSPRNG is split into 11-bit
 * indexes into a fixed 2048-word list, with a SHA-256 checksum in the trailing bits so a
 * mistyped or misread phrase is rejected instead of silently deriving the wrong key. The
 * user never invents a phrase, and the words never leave the device.
 *
 * What is deliberately *not* borrowed is BIP-39's seed derivation (PBKDF2-HMAC-SHA512,
 * 2048 iterations), which is far too weak for a secret that must survive an offline
 * attack on a stolen backup. The phrase feeds Argon2id instead — see `recovery.ts`.
 *
 * 24 words carry 256 bits of entropy and 12 words carry 128. Both are beyond brute force;
 * 24 is the default because the cost of the extra twelve words is one line on paper.
 */
import { sodium } from "./sodium.ts";
import { WORDLIST } from "./bip39-wordlist.ts";

export type PhraseLength = 12 | 24;

const ENTROPY_BYTES: Record<PhraseLength, number> = { 12: 16, 24: 32 };

/** Generate a phrase from the OS CSPRNG. Never from a timestamp, a name or a password. */
export function generatePhrase(words: PhraseLength = 24): string {
  const entropy = sodium().randombytes_buf(ENTROPY_BYTES[words]);
  const phrase = encodePhrase(entropy);
  entropy.fill(0);
  return phrase;
}

export function encodePhrase(entropy: Uint8Array): string {
  if (entropy.length !== 16 && entropy.length !== 32) {
    throw new Error("mnemonic: entropy must be 16 or 32 bytes");
  }
  const checksumBits = entropy.length / 4; // 4 bits per 16 bytes, as BIP-39 defines
  const checksum = sodium().crypto_hash_sha256(entropy);
  const bits = [...toBits(entropy), ...toBits(checksum).slice(0, checksumBits)];

  const words: string[] = [];
  for (let index = 0; index + 11 <= bits.length; index += 11) {
    const value = bits.slice(index, index + 11).reduce((sum, bit) => (sum << 1) | bit, 0);
    words.push(WORDLIST[value] as string);
  }
  return words.join(" ");
}

/** Recover the entropy behind a phrase, rejecting unknown words and bad checksums. */
export function decodePhrase(phrase: string): Uint8Array {
  const words = normalizePhrase(phrase).split(" ").filter(Boolean);
  if (words.length !== 12 && words.length !== 24) {
    throw new Error("recovery phrase must be 12 or 24 words");
  }

  const bits: number[] = [];
  for (const word of words) {
    const index = WORDLIST.indexOf(word);
    if (index < 0) throw new Error(`"${word}" is not a word from the recovery list`);
    for (let bit = 10; bit >= 0; bit -= 1) bits.push((index >> bit) & 1);
  }

  const entropyBits = (words.length * 11 * 32) / 33;
  const entropy = fromBits(bits.slice(0, entropyBits));
  const expected = toBits(sodium().crypto_hash_sha256(entropy)).slice(0, entropyBits / 32);
  const actual = bits.slice(entropyBits);
  if (expected.join("") !== actual.join("")) {
    throw new Error("that phrase has a typo in it — the checksum does not match");
  }
  return entropy;
}

export function phraseIsValid(phrase: string): boolean {
  try {
    decodePhrase(phrase).fill(0);
    return true;
  } catch {
    return false;
  }
}

/** Lowercase, single-spaced, no stray punctuation from a copy-paste. */
export function normalizePhrase(phrase: string): string {
  return phrase
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z\s]/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function toBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit -= 1) bits.push((byte >> bit) & 1);
  }
  return bits;
}

function fromBits(bits: number[]): Uint8Array {
  const bytes = new Uint8Array(bits.length / 8);
  for (let index = 0; index < bits.length; index += 8) {
    bytes[index / 8] = bits.slice(index, index + 8).reduce((sum, bit) => (sum << 1) | bit, 0);
  }
  return bytes;
}
