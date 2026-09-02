# Cryptography

- [`../CRYPTO.md`](../CRYPTO.md) — the primitives, the key hierarchy, X3DH, the Double
  Ratchet with encrypted headers, the vault, padding, and the deviations from the published
  specifications with their reasons.
- [`../THREAT_MODEL.md`](../THREAT_MODEL.md#cryptographic-attacker) — what the protocol is
  claimed to resist, and what it is not (harvest-now-decrypt-later is real).
- [`../SECURITY_REVIEW.md`](../SECURITY_REVIEW.md) — PASS 3 reviews the *composition*,
  which is where protocols usually break rather than in their primitives.

**Code:** `src/shared/crypto/` — `aead.ts`, `hkdf.ts`, `identity.ts`, `x3dh.ts`,
`ratchet.ts`, `session.ts`, `vault.ts`, `mnemonic.ts`, `padding.ts`, `file.ts`. One
implementation, imported unchanged by the browser and by the tests.

**Kept honest by:** `test/cryptography.test.ts` (published vectors — RFC 8439, RFC 7748,
draft-irtf-cfrg-xchacha-03 — plus negative, malformed, replay, corrupted-ciphertext,
wrong-key, wrong-identity, nonce and session-reset tests), `test/hkdf.test.ts` (RFC 5869),
`test/protocol.test.ts` (forward secrecy, post-compromise security, out-of-order delivery),
`test/recovery.test.ts` (BIP-39 against an independent implementation),
`test/padding.test.ts`, `test/verification.test.ts`.
