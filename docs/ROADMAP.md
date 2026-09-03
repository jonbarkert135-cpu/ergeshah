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

*Shipped (PAY-2, 2026-09-03, ADR-0070): the Monero tier. A view-only wallet beside the
application with three calls and no others (`create_address`, `get_transfers`,
`get_balance`), one permanent subaddress per account, a watcher on its own clock that credits
confirmed transfers exactly once, a solvency comparison published on the treasury endpoint and
logged when it diverges, and a payout worker on another host that pulls the queue, holds the
only spend key and refuses anything above its float. `deploy/docker-compose.yml` carries the
node and wallet services; `docs/DEPLOYMENT.md` §The Monero tier is the operator's path.*

- **PAY-6 — Run it against a node.** Every Monero test in this repository speaks to a fake
  `monero-wallet-rpc` (`test/monero.test.ts`). What that proves is this code's behaviour, not
  that the wallet's answers have the shape assumed: `subaddr_index.minor`, atomic-unit
  amounts, `confirmations` on an incoming transfer. A stagenet pass — sync, address, top-up,
  order, payout — is the first thing to do before any of this touches mainnet.
- **PAY-7 — A stuck `sending` payout needs a screen.** Nothing re-queues one automatically and
  that is deliberate (ADR-0070), but today resolving it means reading the wallet's history and
  an `UPDATE`. An admin view that shows the row, the amount and the address hint, and lets a
  human mark it sent or failed with an audit entry, is the missing half.

*Shipped (PAY-3, 2026-09-03): the guarantee is escrow and only escrow, and the interface says
so on every listing before an order is placed. A seller's level (0–3) is computed from settled
on-platform orders alone and the catalogue is sorted by it (ADR-0068); a listing may not carry
a wallet address, an email address, another messenger or a "pay me directly" offer (ADR-0069);
and the deposit minimum is enforced, with a smaller transfer recorded uncredited and refunded
by hand rather than credited or kept (ADR-0067). The chat is untouched and stays unread.*

*Shipped (PAY-4, 2026-09-03, ADR-0071): `POST /api/wallet/refunds`. An uncredited top-up goes
back to an address its owner names, all of it as one payout in the ordinary queue, claimed out
of `below_minimum` before it is credited so it cannot be refunded twice. `MIN_REFUND_XMR`
(0.001) is the floor, because the platform pays the network fee; below it the money waits on
the owner's screen and an operator settles it by hand. Uncredited dust is now counted as a
liability on the treasury, which it always was.*

*Shipped (PAY-5, 2026-09-03, ADR-0072): a level that falls. One step per
`SELLER_LEVEL_DECAY_DAYS` (90) without a settled sale — reversible, because one sale restores
the level the volume already paid for — and one step per suspension that reinstatement does not
return. `sellers.last_settled_day` and `sellers.level_penalty` decide how much of the earned
level the catalogue shows; the earned level itself is still a sum of real money movements and
is never rewritten. Swept hourly from the housekeeping interval, idempotent, with the level and
`listings.rank_key` written by one function so they cannot drift.*

*Shipped: MKT-2, client-encrypted digital delivery with blind server-side storage. MKT-4,
physical orders whose delivery details are a message rather than a database column.*

*Shipped (points 45–46): deliveries that are not files (`manual: true`, and any encrypted
bytes with the kind carried in the channel), disputes filed with a reason into the moderation
queue with the order's public facts and the seller's record, per-buyer ratings with the buyer
count published, and an audited `order.settled` action.*

- **MKT-1 — Escrow and dispute evidence.** Today a moderator reads the buyer's stated reason
  and the public facts; evidence stays in the encrypted channel, described in words. What
  remains: a hash of exchanged evidence committed server-side, so a party cannot later
  claim a different file was sent. Escrow shipped with ADR-0066: the price is held from the buyer's balance while the order runs.
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
