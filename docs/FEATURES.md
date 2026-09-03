# Features, and whether they are actually finished

Point 106. A feature here is not "the screen exists". It is finished when it has a client, a
server, whatever storage it needs, an authorisation rule, validation at the boundary, error
handling, a security property somebody can name, tests that fail when the property
disappears, and documentation — every part that applies to it.

This page is the completeness matrix. It is the answer to "is this a product or a
demonstration", and the honest column is the last one.

Two parts of the list are deliberately missing from the table because they are not per-feature
in this codebase: **error handling** goes through one catalogue (`src/server/lib/errors.ts`,
`docs/API.md` §"Errors" — every failure is a code, a status and a safe message, and
`test/api.test.ts` sweeps the route table for anything that leaks a driver message), and
**validation** goes through one module (`src/server/lib/validate.ts`, enforced at the trust
boundary by `test/security.test.ts`, which walks every route with hostile input). A feature
that needed its own error style or its own parser would be a defect, not a row.

| Feature | Client | Server | Storage | Authorisation | Tests | Documentation |
| --- | --- | --- | --- | --- | --- | --- |
| Registration, login, sessions | `views/auth.ts`, `state.ts` | `routes/auth.ts` (9 routes) | `users`, `sessions`, `devices` | Public by allowlist; everything else needs a session cookie + CSRF | `auth.test.ts`, `sessions.test.ts`, `authorization.test.ts` | `docs/API.md`, `docs/PRIVACY.md` |
| Password change and account deletion | `views/account.ts` | `routes/auth.ts` | `users`, `vaults`, cascade | Current password required; owner only | `auth.test.ts`, `deletion.test.ts` | `docs/DELETION.md` |
| Recovery phrase | `recovery.ts`, `views/account.ts` | `routes/recovery.ts` | `vaults`, `auth_challenges` | Signature over a server challenge; rate-limited | `recovery.test.ts` | `docs/CRYPTO.md`, `docs/PRIVACY.md` |
| PGP second factor | `views/account.ts` | `routes/recovery.ts` | `users.pgp_public_key`, `auth_challenges` | Password *and* signature; server-side OpenPGP only | `pgp.test.ts` | `docs/CRYPTO.md` |
| Device linking | `linking.ts` | `routes/recovery.ts` | `device_links`, `devices` | One-time code, short expiry, owner only | `linking.test.ts` | `docs/CRYPTO.md`, `docs/PRIVACY.md` |
| Key directory and prekeys | `messaging.ts` | `routes/keys.ts` (6 routes) | `devices`, `one_time_prekeys`, `vaults` | Session required to publish; bundles readable by any account, rate-limited | `protocol.test.ts`, `verification.test.ts`, `trust.test.ts` | `docs/CRYPTO.md`, `docs/API.md` |
| Messaging (X3DH + Double Ratchet) | `views/chat.ts`, `messaging.ts` | `routes/messages.ts` | `envelopes` | Sender authenticated; envelopes readable only by the addressed device | `messaging.test.ts`, `protocol.test.ts`, `delivery.test.ts`, `padding.test.ts` | `docs/CRYPTO.md`, `docs/METADATA.md` |
| Safety numbers and key-change warnings | `verification.ts`, `views/chat.ts` | (client-side; keys come from the directory) | `devices` | n/a — a comparison the user performs | `verification.test.ts`, `trust.test.ts` | `docs/CRYPTO.md` §Safety numbers |
| Attachments | `views/chat.ts` | `routes/deliveries.ts` | `attachments` | Owner or addressee; size, rate and free-space limits | `attachments.test.ts`, `uploads.test.ts`, `limits.test.ts` | `docs/API.md`, `docs/THREAT_MODEL.md` §Hostile uploads |
| Marketplace: seller applications, listings | `views/market.ts` | `routes/market.ts` (12 routes) | `sellers`, `seller_applications`, `listings`, `listing_terms` | Seller role for writes, ownership per row | `market.test.ts`, `search.test.ts` | `docs/API.md`, `docs/PRIVACY.md` |
| Orders, delivery, disputes | `views/orders.ts` | `routes/market.ts`, `routes/deliveries.ts` | `orders`, `order_events`, `deliveries` | Buyer or seller, and a state machine on the server | `market.test.ts`, `payments.test.ts` | `docs/PAYMENTS.md` |
| Balances, escrow and payouts | `views/wallet.ts` | `routes/wallet.ts` (5 routes), `lib/ledger.ts` | `balances`, `ledger_entries`, `deposits`, `deposit_addresses`, `withdrawals` | Owner only for a balance; escrow moves with the order's own state machine; payouts above an account's limit need an admin, and the app holds no spend key | `wallet.test.ts`, `payments.test.ts` | `docs/PAYMENTS.md`, ADR-0066 |
| Signed prekey rotation on a live session | `views/account.ts` (age, and "rotating on next load") | `routes/keys.ts` (the `signedPreKeyStale` flag), `client/state.ts` (`rotateStaleKeys`), `client/main.ts` (on load, then daily) | `devices.rotated_day` | The threshold is the client's own constant, imported not restated; the private half never leaves the browser | `linking.test.ts` | ADR-0078, `docs/CRYPTO.md` |
| Lockdown: every write frozen, every read kept | (none — the API answers 503 with an explanation) | `lib/lockdown.ts`, the hook in `app.ts`, `scripts/incident.mjs lockdown:on` | `lockdown` | Checked before CSRF and authentication, so it covers admins, registration and the payout worker; no route can engage or lift it | `lockdown.test.ts`, `incident.test.ts` | ADR-0080, `docs/INCIDENT_RESPONSE.md` |
| Background sweeps, ordered and isolated | (none — a timer) | `lib/jobs.ts`, the list in `main.ts` | — | Each job has its own `try` and its own log line; `runJobs` never throws, because its caller is a timer | `jobs.test.ts` | ADR-0079 |
| Monero tier: deposit addresses, the watcher, solvency | `views/wallet.ts` (the address and the notice when there is none) | `lib/monero.ts`, `lib/deposits.ts`, watcher interval in `main.ts` | `deposit_addresses`, `deposits` | No route creates money: a credit needs a confirmed transfer the wallet saw, and the wallet holds a view key only | `monero.test.ts`, `payments.test.ts` | `docs/PAYMENTS.md`, ADR-0070 |
| Refund of an uncredited top-up | `views/wallet.ts` (the card that appears only when there is dust) | `routes/wallet.ts` → `lib/refunds.ts` | `deposits`, `withdrawals`, `ledger_entries` | The claim moves the rows out of `below_minimum` before crediting them, so two requests cannot refund the same dust; under `MIN_REFUND_XMR` the whole transaction rolls back | `refunds.test.ts` | ADR-0071, `docs/PAYMENTS.md` §Limits |
| Two-administrator approval for a large payout | `views/admin.ts` (the "1 of 2" notice) | `routes/moderation.ts` → `lib/ledger.ts` | `withdrawal_approvals`, `withdrawals` | Distinct admin accounts, counted by primary key; the payout stays parked until the quorum is met, and refusing needs one | `wallet.test.ts` | ADR-0076, `docs/PAYMENTS.md` |
| Payout queue for the worker | (none — another host, not a browser) | `routes/payouts.ts` (3 routes), `scripts/payout-worker.mjs` | `withdrawals` | Bearer token compared in constant time; closed entirely when unset. A session is not accepted | `monero.test.ts`, `authorization.test.ts` | `docs/API.md` §The payout queue, ADR-0070 |
| Dispute evidence commitments | `views/orders.ts` (commit a file's digest, check a file against the record) | `routes/evidence.ts`, `lib/evidence.ts` | `order_evidence` | The browser keys the digest with the order id, so a stranger with the same file recognises nothing; the server validates 64 hex characters and stores them. A moderator may read and never commit | `evidence.test.ts` | ADR-0074, `docs/MODERATION.md` |
| Reviews and reputation | `views/market.ts` | `routes/market.ts`, `lib/listings.ts` | `reviews` | One per completed order; author never published | `market.test.ts`, `abuse.test.ts` | `docs/MODERATION.md`, ADR-0045 |
| Seller level and catalogue rank | `views/market.ts` (the level beside a seller) | `lib/reputation.ts`, settled inside `routes/market.ts`, swept hourly from `main.ts` | `sellers.settled_pico`, `sellers.level`, `sellers.last_settled_day`, `sellers.level_penalty`, `listings.rank_key` | Written only by an order settling, by the dormancy sweep, or by a suspension; no route sets a level, and every writer goes through one function so the level and the sort key cannot drift | `market.test.ts`, `standing.test.ts` | `docs/PAYMENTS.md` §Guarantee, ADR-0068, ADR-0072 |
| Listing publishing rules | error shown on the listing form | `lib/listing_policy.ts` | none — a refusal stores nothing | Applies to listings and seller statements; never to messages | `market.test.ts` | `docs/MODERATION.md`, ADR-0069 |
| Reports, moderation queue and money oversight | `views/admin.ts` (the payout queue, the treasury and the stuck-payout rescue) | `routes/moderation.ts` (14 routes) | `reports`, `audit_log`, `withdrawals`, `balances` | Moderator or admin, and moving money is admin-only; every action audited. A payout can be resolved by hand only while it is `sending`, and "sent" needs its transaction id | `moderation.test.ts`, `monero.test.ts`, `abuse.test.ts`, `authorization.test.ts` | `docs/MODERATION.md`, ADR-0073 |
| Notifications | `views/notifications.ts` | `routes/notifications.ts` | `notifications` | Owner only; no message content stored | `notifications.test.ts` | ADR-0032, `docs/PRIVACY.md` |
| Search | `views/market.ts` (in-browser) | `routes/market.ts` (indexed listing query) | `listings` index | Public listings only | `search.test.ts` | ADR-0030, ADR-0044 |
| Sealed sender (single-use send tokens) | `client/api.ts`, `client/messaging.ts` (the token pouch) | `routes/messages.ts`, `lib/send_tokens.ts` | `send_tokens` (hash, expiry) | Token minting needs a session; sending needs an unspent token, and carries no cookie | `sealed_sender.test.ts` | ADR-0084 |
| Dispute decision support: both parties' records | `views/admin.ts` (the queue) | `routes/moderation.ts`, `lib/reputation.ts` (`sellerReputation`, `buyerRecord`) | derived from `orders`, `order_events`, `reviews` | Staff only; nothing new is recorded about anybody | `moderation.test.ts` | ADR-0083 |
| Category browsing | `views/market.ts` (chips beside the search box) | `routes/market.ts` (`GET /api/market/categories`), `lib/validate.ts` (`asCategory`) | `listings.category`, `listings_category_idx` | Public: active listings of unsuspended sellers only | `categories.test.ts` | ADR-0082 |
| Rate limits and anti-automation | `main.ts` (proof of work) | `lib/limits.ts` on every route | `rate_limits` | n/a — applies before authorisation | `limits.test.ts`, `antiautomation.test.ts`, `resources.test.ts` | `docs/API.md`, ADR-0025 |
| Health and metrics | (none — operator only) | `routes/health.ts`, `lib/metrics.ts` | in memory | Admin only | `observability.test.ts` | `docs/OBSERVABILITY.md` |
| Backups and restore | (none — operator only) | `scripts/backup.mjs` | the database file | Filesystem and the key file | `backup.test.ts` | `docs/BACKUPS.md`, ADR-0061 |

## What is missing, per the same standard

Stated here rather than left for a reader to notice:

- **Metrics are in memory** (`docs/SELF_CRITIQUE.md` finding 6): a restart loses them, and
  they are per-process. Acceptable for one VPS, wrong the day there are two.
- **Storage accounting is per-write, not per-account** (roadmap OPS-5): the free-space floor
  protects the disk; nothing yet caps how much of it one account can occupy.
- **Attachments are fetched by id** (finding 4): the id is a capability, and a leaked id is a
  leaked file. A deliberate trade, recorded rather than hidden.
- **The onion address and the deployment itself have never run outside a rehearsal**
  (roadmap OPS-6).
- **No feature has been through an external security review** (roadmap CRY-1).
- **The Monero tier has never met Monero** (roadmap PAY-6): the watcher, the deposit
  addresses, the solvency comparison and the payout queue are built and tested against a fake
  `monero-wallet-rpc` (`test/monero.test.ts`), not against a node. Until a stagenet run
  happens, what is proven is the behaviour of this code, not the shape of the wallet's
  answers. The custody risk is stated in `docs/PAYMENTS.md` §Custody.

`test/features.test.ts` keeps this page from drifting: every route file, every view and every
table in the schema has to appear somewhere in the matrix, and every file the matrix names has
to exist. A new feature therefore cannot be finished without either a row or a reason.
