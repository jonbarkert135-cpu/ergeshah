# Roadmap

Ordered by how much risk each item removes, not by how impressive it looks. Everything
here is *not implemented today*; the README table says what is.

## Cryptography

- **PQ-1 — Hybrid post-quantum handshake.** X25519 + ML-KEM-768 in the PQXDH style, so a
  recorded session is not decryptable by a future quantum adversary. Blocked on an
  audited, browser-capable ML-KEM implementation; a hand-rolled one would violate the
  rule that keeps this project honest.
- **MD-3 — Header encryption.** Encrypt the ratchet header with a header key chain, so
  the server cannot count messages per chain.
- **CRY-1 — External audit.** The property tests are necessary and not sufficient.

## Metadata

- **MD-1 — Message padding.** Pad ciphertext to size buckets so length stops leaking.
- **MD-2 — Delivery timing noise.** Randomised polling intervals and optional delayed
  delivery to blur send/fetch correlation.
- **MD-4 — Sealed sender.** Today the sender is hidden from the database; the *sending
  request* is still authenticated. A sender-anonymity token would close that gap.

## Accounts

- **AUTH-1 — PAKE login (OPAQUE).** Removes the last theoretical benefit a hostile server
  gets from observing login.
- **AUTH-2 — Password change and vault re-encryption.** Currently a password change would
  orphan the vault; the flow needs to re-seal it atomically.
- **AUTH-3 — Multi-device linking.** QR-based device linking with a per-device identity,
  instead of restoring a sealed vault.
- **AUTH-4 — Account deletion.** Self-service deletion with immediate envelope purge.

## Marketplace

- **PAY-1 — Optional payment adapters.** Isolated, replaceable, never required; the first
  candidate is a self-hosted Monero payment gateway, precisely because it needs no
  third-party identity.
- **MKT-1 — Escrow and dispute evidence.** Evidence exchanged in the encrypted channel,
  with only a hash committed server-side.
- **MKT-2 — Digital delivery.** Client-encrypted file delivery with server-side blind
  storage.
- **MKT-3 — Categories, pagination and search quality.** Currently a `LIKE` query.

## Operations

- **OPS-1 — Reproducible client builds** published with hashes, so a user can verify the
  JavaScript they were served. This is the mitigation for the largest residual risk in
  the threat model.
- **OPS-2 — SQLite driver for the `Db` interface in tests against PostgreSQL in CI**, so
  both drivers are exercised on every commit.
- **OPS-3 — Container image signing and an SBOM.**
- **OPS-4 — Rate-limit tuning under real traffic**, and a `429` backoff hint in the UI.

## Client

- **UI-1 — Safety-number verification flow** with a scannable code, not just a string.
- **UI-2 — Offline queue** for messages composed without connectivity.
- **UI-3 — Accessibility pass** (keyboard traps, focus management, screen-reader labels).
