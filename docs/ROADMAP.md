# Roadmap

Ordered by how much risk each item removes, not by how impressive it looks. Everything
here is *not implemented today*; the README table says what is.

## Cryptography

- **PQ-1 — Hybrid post-quantum handshake.** X25519 + ML-KEM-768 in the PQXDH style, so a
  recorded session is not decryptable by a future quantum adversary. Blocked on an
  audited, browser-capable ML-KEM implementation; a hand-rolled one would violate the
  rule that keeps this project honest.
- **CRY-1 — External audit.** The property tests are necessary and not sufficient.

## Metadata

*Shipped: MD-3 header encryption and MD-1 message padding (PR #2). What remains here is
timing and volume, which padding cannot touch.*

*Shipped (points 74–80): disappearing messages with a server-side expiry the sender can
shorten, client-side deletion of messages and conversations, skipped message keys that
expire, typing indicators and read receipts as opt-in encrypted signals with no server
state, client-encrypted attachments in blind storage, and client-side message search. The
decision not to ship presence or push is in ADR-0042 and ADR-0044.*

- **MD-2 — Delivery timing noise.** Randomised polling intervals and optional delayed
  delivery to blur send/fetch correlation.
- **MD-4 — Sealed sender.** Today the sender is hidden from the database; the *sending
  request* is still authenticated. A sender-anonymity token would close that gap.

## Accounts

*Shipped: AUTH-2 password change (now a 32-byte rewrap), AUTH-4 self-service deletion
(PR #5), AUTH-3 device linking with a per-device identity (PR #6), recovery phrases over a
wrapped master key (PR #7), and AUTH-7 PGP challenge–response as a second factor (PR #8).*

- **AUTH-5 — Camera capture for the device code.** Linking works by reading a code across
  devices; scanning it needs either the browser's own `BarcodeDetector` (Chromium only) or
  a QR library, and rendering one needs an encoder. Neither is worth a dependency or 200
  lines of Reed–Solomon until someone asks for the camera flow.
- **AUTH-6 — Identity-key change warnings.** A username that is deleted can be registered
  again by someone else. The defence is a client that notices a peer's identity key
  changed and says so, rather than a tombstone in the database.

- **AUTH-1 — PAKE login (OPAQUE).** Removes the last theoretical benefit a hostile server
  gets from observing login.

## Marketplace

*Shipped (points 81–84): reviews published without their author, a client-side block list,
the moderation lanes separated and asserted by tests, and the payment architecture written
down before the feature exists (`docs/PAYMENTS.md`).*

- **PAY-1 — Optional payment adapters.** Isolated, replaceable, never required; the first
  candidate is a self-hosted Monero payment gateway, precisely because it needs no
  third-party identity.
*Shipped: MKT-2, client-encrypted digital delivery with blind server-side storage. MKT-4,
physical orders whose delivery details are a message rather than a database column.*

*Shipped (points 45–46): deliveries that are not files (`manual: true`, and any encrypted
bytes with the kind carried in the channel), disputes filed with a reason into the moderation
queue with the order's public facts and the seller's record, per-buyer ratings with the buyer
count published, and an audited `order.settled` action.*

- **MKT-1 — Escrow and dispute evidence.** Today a moderator reads the buyer's stated reason
  and the public facts; evidence stays in the encrypted channel, described in words. What
  remains: a hash of exchanged evidence committed server-side, so a party cannot later
  claim a different file was sent. Escrow is blocked on PAY-1.
- **MKT-3 — Categories, pagination and search quality.** Currently a `LIKE` query.

## Operations

*Shipped: the zero-cost audit pipeline — `audit:bundle`, `audit:secrets` and
`docs/AUDIT.md`. Reproducible client builds (OPS-1) with published digests, subresource
integrity and `npm run audit:deployment`.*

- **OPS-2 — SQLite driver for the `Db` interface in tests against PostgreSQL in CI**, so
  both drivers are exercised on every commit.
- **OPS-3 — Container image signing and an SBOM.**
- **OPS-4 — Rate-limit tuning under real traffic**, and a `429` backoff hint in the UI.

## Client

*Shipped: UI-1, the safety-number verification flow — a scannable code, a per-device
verified state, and a warning when an unverified device appears.*

- **UI-2 — Offline queue** for messages composed without connectivity.
- **UI-3 — Accessibility pass** (keyboard traps, focus management, screen-reader labels).
