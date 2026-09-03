# Roadmap

Ordered by how much risk each item removes, not by how impressive it looks. Everything
here is *not implemented today*; the README table says what is.

## Cryptography

- **PQ-1 — Hybrid post-quantum handshake.** X25519 + ML-KEM-768 in the PQXDH style, so a
  recorded session is not decryptable by a future quantum adversary. Blocked on an
  audited, browser-capable ML-KEM implementation; a hand-rolled one would violate the
  rule that keeps this project honest.
- **CRY-1 — External audit.** The property tests are necessary and not sufficient. The
  scoping brief is written and ready to send with the repository
  (`docs/EXTERNAL_REVIEW.md`); what is missing is the money, not the preparation.

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

*Shipped (2026-09-03): prices are XMR-native — piconero integers, no `currency` column, no
exchange rate anywhere (ADR-0064) — and the Monero settlement design in `docs/PAYMENTS.md`
(ADR-0065).*

- **PAY-1 — A self-hosted Monero gateway.** Designed in `docs/PAYMENTS.md`; four things are
  needed before code is worth writing, and two of them are not engineering:
  1. **A custody decision.** Buyer-pays-seller (non-custodial, no node, works today) or an
     operator wallet that receives and forwards (custody, commission possible, hot wallet,
     jurisdiction-dependent). The two produce different schemas.
  2. **A wallet tier in the deployment**: `monerod` plus `monero-wallet-rpc` on the internal
     network, the daemon holding the only egress, ideally over Tor — the application container
     still reaches nothing but them (`docs/NETWORK.md`).
  3. **A view-key-only wallet** on that tier. The spend key stays off this machine.
  4. Then: `payments` table, subaddress per order, a poll inside the housekeeping timer, a
     confirmation gate, a quote that expires, an admin view, and refunds that are *recorded*
     rather than sent (a Monero transaction has no sender address to send one to).
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

*Shipped (OPS-2): the suite runs against a real PostgreSQL in CI as well as SQLite
(`docs/TESTING.md`), which is how findings 8 and 9 in `docs/SELF_CRITIQUE.md` were found —
the PostgreSQL driver had never worked, and the one-time prekey claim was not atomic outside
SQLite's write queue (ADR-0059, ADR-0060).*

*Shipped (points 96–100): the mechanism register with a threat and a failure mode per row
(`docs/MECHANISMS.md`), the quality bar and the development cycle in `docs/CHANGE_REVIEW.md`, a
700-line ceiling on source files, a free-space floor in front of uploads, `TRUST_PROXY` that can
name the proxy, and `docs/SELF_CRITIQUE.md` — seven findings this project made against itself,
three of them fixed in the same commit (ADR-0056, ADR-0057, ADR-0058).*

*Shipped (points 90–95): migrations that declare whether they can be undone, with the rollback
plan written down instead of improvised (ADR-0052); three environments that fail loudly at the
boundary between them (ADR-0053); every ADR indexed by area under `docs/adr/` (ADR-0054); and
the two regression questions plus the priority order that settles a conflict between
requirements, in `docs/CHANGE_REVIEW.md` (ADR-0055).*

*Shipped (points 85–89): an administrator-only health endpoint with uptime, CPU, memory,
disk, database latency, error rate and latency percentiles, over in-memory counters that hold
nothing but numbers (`docs/OBSERVABILITY.md`, ADR-0048); connection, timeout and PostgreSQL
statement ceilings (ADR-0049); `/api/v1` in the path with `X-API-Version`, a documented error
catalogue and `Retry-After` on every 429 (ADR-0050); and the WebSocket checklist for a socket
this project does not have (ADR-0051).*

*Shipped: the zero-cost audit pipeline — `audit:bundle`, `audit:secrets` and
`docs/AUDIT.md`. Reproducible client builds (OPS-1) with published digests, subresource
integrity and `npm run audit:deployment`.*

- **OPS-3 — Container image signing and an SBOM.**
- **OPS-6 — The first real deployment.** Every step in `docs/DEPLOYMENT.md` has been
  rehearsed locally, including a restore drill on a production-mode instance
  (`npm run backup:drill`), but this service has never run on a VPS with a domain, a
  certificate and a proxy in front of it. Until it has, the guide is tested and the
  deployment is not.
- **OPS-5 — Storage accounting for blobs.** The free-space floor keeps the service alive
  (ADR-0057); it does not stop one account consuming the allowance. Wanted: a shorter default
  lifetime for attachments, and a way to charge storage without an owner column
  (`docs/SELF_CRITIQUE.md`, finding 1).
- **OPS-4 — Rate-limit tuning under real traffic.** The backoff hint shipped with point 89:
  a 429 carries `retryAfterSeconds` and the client shows it. What remains is the tuning
  itself, which needs traffic to tune against.

## Client

*Shipped: UI-1, the safety-number verification flow — a scannable code, a per-device
verified state, and a warning when an unverified device appears.*

- **UI-2 — Offline queue** for messages composed without connectivity.
- **UI-3 — Accessibility pass** (keyboard traps, focus management, screen-reader labels).
