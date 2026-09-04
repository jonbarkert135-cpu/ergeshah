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

*Shipped: MD-2 timing noise (ADR-0085) — a poll interval redrawn from the CSPRNG after every
fetch, and an opt-in delivery delay of 15 s to 2 min held by `envelopes.available_at`. The
defence this section still lacks is cover traffic, which is a whole design and its own cost,
not a knob: see the ADR for why it is not sprinkled in.*
*Shipped: MD-4 sealed sender (ADR-0084) — the send request carries a single-use token and
no cookie, so the sender is absent from the data at rest as well as from the schema. An
operator watching the running server still sees who mints tokens; unlinkable issuance needs
a blind signature and is not planned.*

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

- **AUTH-8 — A round trip through real `gpg`.** Every PGP test here signs with OpenPGP.js and
  verifies with OpenPGP.js, which proves the flow and not the interoperability. Before the
  first deployment, sign a challenge statement with `gpg --detach-sign --armor` from a
  hardware-backed key and check enrolment, login and rotation accept it — and that the
  statement is legible in the terminal, since a user who cannot read what they are signing is
  not exercising a factor, only clicking one.

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
*Shipped (PAY-7, 2026-09-03, ADR-0073): a stuck payout has a screen. `withdrawals.claimed_at`
(migration 017) is stamped when the worker takes a row, the payout queue reports
`sendingForMinutes` and a `stuck` flag over two hours, and
`POST /api/moderation/withdrawals/:id/resolve` lets an admin record the one thing this server
cannot work out for itself — sent, with its transaction id, or never left, which returns the
money. Audited as `withdrawal.resolved`; refused for any row the worker has not taken.*

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

*Shipped (MKT-1, 2026-09-03, ADR-0074): dispute evidence, without the evidence. A party
commits `HMAC-SHA256(order id, file bytes)` — computed in the browser, keyed so that a
stranger holding the same file recognises nothing — and the record carries the date and
whether it was published before the dispute. The moderation queue shows both sides' digests
with a caption saying exactly what they prove: that a story has not changed, and nothing more.
The file never leaves the encrypted channel. Escrow shipped earlier with ADR-0066.*

- **MKT-3 — Search quality.** Pagination and the index are done (ADR-0030: an inverted index,
  prefix-matched terms, keyset pages), and categories are folded and browsable (ADR-0082).
  What is left is relevance: results come back in catalogue order — seller level, then age —
  so a listing whose *title* is the search term sits below an older one that merely mentions
  it. Ranking by match quality conflicts with the keyset cursor, which is the listing's stored
  rank key; doing both needs either a second sort key computed per query or an accepted limit
  on how deep a relevance-ordered search can page.
*Shipped: MKT-6 the seller bond (ADR-0086) — staked from the seller's own balance, shown on
their listings, released after a cool-off with no open dispute, and claimable by a moderator
for a buyer harmed on a completed order. Never burnt, never the platform's.*

- **MKT-5 — A scoped, revocable read token for a seller's own scripts.** Sellers automate by
  polling (ADR-0081: this server makes no outbound requests), and today that means a script
  holding a full browser session. What is wanted: a token a seller creates and revokes
  themselves, read-only, scoped to their own orders and notifications, rate-limited on its own
  bucket, and never able to move money or read a message.

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

- **OPS-7 — A canary (ADR-0083).** A short statement the operator signs and refreshes on a
  schedule — no warrant received, no key handed over — published with the date it was signed
  and the date the next one is due. The client shows its age, so a canary nobody has refreshed
  in six weeks is visible to every user rather than to nobody. Needs: a signed text an admin
  posts, a public endpoint, a line in the footer, and no cleverness at all — the value is in
  the operator's signature and in users noticing it went stale.
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
