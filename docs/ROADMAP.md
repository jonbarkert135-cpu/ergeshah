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

- **MD-5 — A revocation epoch for sealed-sender tokens. _Closed._** A token has no owner column
  by design, so a suspension cannot select it, and an unspent stockpile posted envelopes until
  `SEND_TOKEN_TTL_MS` ran out (SEC-2026-023). Now every token carries a single global epoch in
  its own string, and `scripts/incident.mjs send-tokens:revoke` raises the floor
  (`send_token_epoch.min_epoch`) to invalidate every outstanding token at once (ADR-0111). The
  epoch stayed clear of the owner-column-by-another-name trap by being global and coarse — not
  per-batch, not on a timer — so it holds no account and is no grouping key. The tail is now an
  operator action rather than a seven-day wait; the price is that a bump is all-or-nothing, the
  only revocation an ownerless token admits.
- **MD-6 — Refuse an invite whose identity key is not in the peer's directory. _Closed._** A
  sender chooses the channel id, so a third account that learned an order's channel could post an
  invite into that conversation under a chosen display name (SEC-2026-024). Now a key the
  conversation has never seen may open a session in it only if `GET /api/keys/identity/:username`
  lists it for the conversation's peer; anything else is acknowledged and dropped (ADR-0112). The
  new route publishes the identity keys the bundle already publishes, without spending a one-time
  prekey or the tight `key_bundle` bucket. The directory stays untrusted in ADR-0091's sense: it
  gained a veto a hostile server already had by dropping envelopes, and no new say over which key
  is accepted for a peer this side has never talked to. An unreachable directory leaves the
  envelope unacknowledged for the next poll rather than losing a legitimate new device.

## Accounts

*Shipped: AUTH-2 password change (now a 32-byte rewrap), AUTH-4 self-service deletion
(PR #5), AUTH-3 device linking with a per-device identity (PR #6), recovery phrases over a
wrapped master key (PR #7), and AUTH-7 PGP challenge–response as a second factor (PR #8).*

- **AUTH-5 — Camera capture for the device code.** Linking works by reading a code across
  devices; scanning it needs either the browser's own `BarcodeDetector` (Chromium only) or
  a QR library, and rendering one needs an encoder. Neither is worth a dependency or 200
  lines of Reed–Solomon until someone asks for the camera flow.
*Shipped: AUTH-6 identity-key change warnings (ADR-0091) — every peer key a conversation has
used is recorded in the vault, a key that arrives later raises a banner, and a directory that
answers with none of the keys the conversation knew is reported as a replacement rather than a
new device. What it cannot do is notice a change while this device is not talking to that peer.*

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

*Shipped (OPS-7, 2026-09-04, ADR-0099): the canary. The operator signs a short statement on
their own machine with the key named by `CANARY_FINGERPRINT`, posts it to
`POST /api/admin/canary`, and it appears in the footer of every screen with its age —
`GET /api/canary` is public, so a reader needs no account. Both dates live inside the signed
text, an older statement cannot be replayed over a newer one, and an admin session alone
cannot publish anything, because the private key is not on this machine. What it still cannot
do is prove anything when it *is* refreshed; that limit is written into the client's own
wording.*
- **OPS-11 — The authorisation matrix as data (point 132). _Closed._** `docs/AUTHZ_MATRIX.json`
  has one row per route — `who` may reach it (`public`, `account`, `staff`, `admin`, the payout
  `worker`), the `resource` and `action` it touches, and the ownership or state `scope` the
  handler enforces afterwards. `test/authz_matrix.test.ts` sends an anonymous caller, a user, a
  moderator and an admin to every route and compares both directions with the table: a caller
  the row admits must get past the gate, a caller it excludes must be stopped by the gate itself
  and not by a later validation step. A moderator gaining an admin action, an admin route
  slipping to staff, or a route missing from the table each fail with the route's name — checked
  by widening one `requireRole` and by deleting one row, before the file was committed. The
  sweep in `test/authorization.test.ts` stays: it is the proof that nothing is missing a check,
  this is the proof that no check has quietly moved (ADR-0114).
- **OPS-3 — Container image signing and an SBOM.**
- **OPS-8 — Authenticate the wallet RPC, not just its network position.** `app` reaches the
  view-only wallet over the internal network with `--disable-rpc-login`, which is the one
  "inside Docker, therefore trusted" assumption left in the deployment
  (`docs/NETWORK.md` §Internal callers). Enabling `--rpc-login` means HTTP digest
  authentication written here and verified against nothing, so it waits for the stagenet pass
  (PAY-6) where it can be tested against a real `monero-wallet-rpc` rather than a fake.
- **OPS-9 — A PostgreSQL backup script and drill.** `docs/BACKUPS.md` describes `pg_dump` with
  the same encryption, retention and off-host key rules, but only the SQLite path has a script
  (`scripts/backup.mjs`) and a boot drill in CI. A deployment on PostgreSQL is following prose
  today, which is exactly the gap `backup:drill` exists to close for the other driver.
- **OPS-10 — An advisory lock around boot-time migrations. _Closed._** `migrate()` runs on
  every start, and two instances booting together (scale mode) did run it at once — on
  PostgreSQL the loser died on `CREATE TABLE IF NOT EXISTS schema_migrations` with a
  `pg_type` duplicate, or on the ledger's primary key one file later. Now every transaction the
  runner opens takes `pg_advisory_xact_lock` first and re-reads the ledger before applying, so
  the second instance waits for one file at a time and skips what the first one recorded
  (ADR-0113). SQLite is unchanged: one writer, `BEGIN IMMEDIATE` already queues. The test runs
  two runners concurrently on PostgreSQL and fails without the lock on every attempt.
- **OPS-6 — The first real deployment.** Every step in `docs/DEPLOYMENT.md` has been
  rehearsed locally, including a restore drill on a production-mode instance
  (`npm run backup:drill`), but this service has never run on a VPS with a domain, a
  certificate and a proxy in front of it. Until it has, the guide is tested and the
  deployment is not.
- **OPS-5 — Storage accounting for blobs. _Closed._** *Shipped in two halves (2026-09-04):
  uploads are charged in bytes against a daily-rotating bucket (ADR-0093), so an account pays for
  the disk it fills without an owner column ever existing; and chat attachments now expire at a
  shorter default (`ATTACHMENT_TTL_MS`, 14 days) than order deliveries (ADR-0110), so an account
  spending its allowance every day no longer accumulates thirty days of blobs. Fetching a chat
  attachment is lazy, so the shorter window is a deliberate tradeoff: a recipient who waits past
  it loses the file, not the message.*
- **OPS-4 — Rate-limit tuning under real traffic.** The backoff hint shipped with point 89:
  a 429 carries `retryAfterSeconds` and the client shows it. What remains is the tuning
  itself, which needs traffic to tune against.

## Security process

*Shipped: the pipeline itself (ADR-0103) — twelve source rules inside `npm run audit`, a
findings register that blocks a release on an open CRITICAL or HIGH, suppressions with owners
and review dates, fuzzed parsers, an authorisation matrix generated from the route table, and
`skills/vulnerability-remediation/SKILL.md` for the loop from a report to a regression test.*

- **SEC-1 — A dynamic scan against a real deployment.** OWASP ZAP is the one stage of point 150
  that cannot run in CI honestly: an instance with no Tor, no reverse proxy, no TLS and an empty
  database is not the system whose dynamic behaviour matters. The pipeline prints NOT RUN for
  the stage until an operator runs `zap.sh -cmd -quickurl <origin>` against staging and the
  findings are triaged into `docs/SECURITY_FINDINGS.md`. Blocked on OPS-6, the first real
  deployment.
- **SEC-2 — OSV-Scanner and Trivy in CI, if they can be pinned without a new install path.**
  Both are optional today: used when present on `PATH`, never required (`npm run security:tools`).
  Adding them to CI means pinning a binary by digest in the workflow — which costs a human
  re-copy of `.github/workflows/ci.yml` — so it waits until there is a second reason to touch
  that file. `npm audit` plus the dependency freeze covers the same ground more narrowly.
- **SEC-3 — Coverage-guided fuzzing for the container walker.** `test/fuzz.test.ts` is a seeded
  corpus: it covers shapes, not paths. A real fuzzer over `stripImageMetadata` (and the ratchet
  frame decoder) would need a harness and a corpus directory, which is a dependency and a
  workflow. UI-4 has now added the ISO base media box walker to that same entry point, which
  raises the value of coverage-guided fuzzing over it.
- **SEC-4 — Semgrep rules for this codebase.** The twelve patterns in `scripts/security.mjs`
  are regular expressions and say so; a handful of them (mass assignment, URL sinks) would be
  more precise as Semgrep rules with real dataflow. The rules would live in the repository and
  run only where the binary exists, so the tree keeps its own answer either way.
  *Run once so far (2026-09-04, Semgrep 1.176.1, rulesets `p/security-audit`, `p/typescript`,
  `p/nodejs`, `p/owasp-top-ten`, `p/secrets` over `src`, `scripts`, `deploy`): one finding,
  `gcm-no-tag-length` in `scripts/backup.mjs` — not exploitable, since the tag handed to the
  decipher is always the file's last 16 bytes, but `authTagLength` is now pinned on both sides.
  Nothing else; the twelve regex patterns and the test suite had already covered what the public
  rulesets look for. A rerun is one command and belongs at the end of every audit block.*

## Client

*Shipped: UI-1, the safety-number verification flow — a scannable code, a per-device
verified state, and a warning when an unverified device appears.*

- **UI-4 — Metadata stripping for the formats the walker did not know. _Closed._** JPEG, PNG
  and WebP are rewritten before encryption (ADR-0092); HEIC/HEIF (an iPhone's default), AVIF and
  MP4/MOV are now stripped by the ISO base media walker (`src/shared/isobmff.ts`, ADR-0109),
  which zeroes `udta`/GPS, the header timestamps and a still image's `Exif`/XMP items in place —
  the box-walker route, chosen over decode-and-re-encode so no quality is lost and no DOM enters
  shared code. TIFF and raw, GIF, PDF and SVG remain disclosed-not-stripped: no single container
  unifies them and each is its own parser for little gain. What survives every format — faces,
  screens, the compression fingerprint, the pixels themselves — is the residual this never
  claimed to touch (`docs/STORAGE.md`).
  *Disclosure closed (2026-09-04): both upload paths warn for the formats still not stripped.
  The chat screen says after the fact that a file's format was not cleaned; the delivery screen
  asks the seller to confirm before the bytes leave the browser, since a delivery is a
  deliberate act with a Cancel. Both read the same `metadataUnhandled` check and the same
  `METADATA_KEPT_NOTE` wording in `src/shared/media.ts`, so the two screens cannot drift.*
  *Stripping closed (2026-09-04): the ISO base media walker landed, so the four container
  formats are cleaned rather than only disclosed.*
- **UI-2 — Offline queue** for messages composed without connectivity.
*Shipped: UI-3 accessibility pass (ADR-0097) — focus is anchored across every redraw, form
refusals name the field they are about and move the keyboard to it, results the page shows by
changing shape are said out loud, and the rules are enforced by `test/accessibility.test.ts`
rather than by remembering them. What a test still cannot judge — reading order, whether a
label says something useful — stays the browser pass in `docs/DESIGN.md`.*
