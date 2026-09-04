# Database

Two drivers behind one small interface (`src/server/db/index.ts`): **SQLite** (`node:sqlite`,
built into Node 22, no package) for a single machine or an onion service, and **PostgreSQL**
via `pg` for anything larger. Application code writes portable SQL with `?` placeholders and
the Postgres driver rewrites them to `$n`. There is no ORM and no query builder — every
statement in this codebase can be read as SQL, which is the point when the question is
"what exactly does the server store?".

`test/docs.test.ts` fails if a table exists that this page does not describe.

## The rule that shapes the schema

> The server stores what it needs to route and to enforce rules, and nothing that describes
> a person.

Two consequences visible in every table below:

- **Days, not timestamps.** Most tables record `created_day` — days since the epoch — rather
  than a millisecond timestamp. A timestamp is a behavioural fingerprint (when you sleep,
  where you live); a day is enough to expire a row or sort a list. Where a precise time is
  operationally necessary (sessions, envelope expiry, order events) it is kept, and said so.
- **Ciphertext columns are opaque.** `vaults.sealed`, `envelopes.payload`, `deliveries.*` hold
  base64url the server cannot decrypt. No column derived from them exists: no length bucket,
  no content type, no preview.

## Migrations

`src/server/db/migrations/NNN_name.sql`, applied in order, once each, inside a transaction,
automatically on boot. Applied names are recorded in `schema_migrations`.

A migration named `NNN_name.postgres.sql` or `NNN_name.sqlite.sql` runs on that driver only.
The escape hatch exists for one reason — the two databases disagree about *types*, not about
the schema — and a dialect-scoped migration that is not about a dialect difference is a bug
(ADR-0059). There is exactly one so far: 012, which widens every millisecond timestamp to
`BIGINT` on PostgreSQL, where `INTEGER` is 32 bits.

A released migration is **never edited**: `src/server/db/migrations/CHECKSUMS.txt` records a
digest of each, `npm run audit:migrations` fails if one changes, and `npm run migrate:checksums`
is how a *new* one is registered. Destructive statements require a `-- destructive: why`
comment. `test/migrations.test.ts` applies the whole set to an empty database, runs it twice
to prove the runner is idempotent, and checks the indexes hot queries depend on.

### Rolling back (point 90)

A migration that has shipped is never edited, so "rolling back" means one of three things,
and which one applies is decided *before* the deployment, not during it. From migration 012
on, every new file declares the answer in its own header — `-- reversible: yes — <the
statements that undo it>` or `-- reversible: no — <why>` — and `npm run audit:migrations`
refuses a new migration that does not say (a released one cannot be edited to add it, which
is why the rule applies to unreleased files only).

| Kind of change | Reversible? | How it is undone |
| --- | --- | --- |
| A new table or index (001–005, 008, 009, 011) | yes | `DROP` it. Nothing else read it, and the rows are the feature |
| A new column with a default (006, 010) | in practice | `ALTER TABLE … DROP COLUMN` on PostgreSQL; on SQLite the column is left in place and ignored, which is cheaper than a table rebuild and harmless |
| A new constraint over existing rows (007) | yes, structurally | Dropping the constraint restores the old shape; rows that were rejected while it was in force are not restored, because they were never written |
| Anything that deletes or rewrites data | no | Restore from a backup (`npm run backup:restore`, `docs/BACKUPS.md`). This is why destructive statements need a `-- destructive: why` comment: they are the migrations whose rollback plan is the backup |

The runner applies each migration inside a transaction, so a migration that fails leaves the
schema as it was; there is no half-applied state to unwind by hand. What there is no support
for — deliberately — is a `down` script per migration: a down script is code that runs once,
under pressure, having never been tested against production data, and it invites editing a
released migration to "fix" its reverse. The backup is the tested path, and it is exercised
quarterly (`docs/HARDENING.md`).

## Tables

### Identity

| Table | What it holds | Notes |
| --- | --- | --- |
| `users` | id, username, `password_hash`, role, status, `created_day`, optional `recovery_public_key`, `pgp_public_key`, `pgp_fingerprint` | No email, no phone, no display name, no address. Argon2id hash of a client-derived secret — the password never reaches the server |
| `sessions` | id, user, `token_hash`, `previous_token_hash`, `rotated_at`, optional label, created/expires, `last_seen_day` | Only the hash of the cookie value is stored. The previous hash is accepted for one minute after a rotation, for requests already in flight; `last_seen_day` is a day, and it both ends idle sessions and triggers the daily rotation (ADR-0038) |
| `vaults` | user, `sealed`, `updated_day` | The user's private keys, encrypted client-side |
| `devices` | id, user, label, identity key, signed prekey and signature, created/rotated day, `revoked_at` | Public key material only |
| `one_time_prekeys` | id, device, key id, public key, `claimed_at` | Consumed one at a time when someone starts a conversation |
| `device_links` | `link_hash`, user, label, expiry | Short-lived, hashed one-time secrets for adding a second device |
| `auth_challenges` | challenge material for recovery and PGP logins, with expiry; also the spent-proof receipts for the anti-automation gate (`kind = 'pow'`, no user) | Deleted on use. A recovery challenge is written for every username asked about, with a null `user_id` when nobody is behind the name, so that the table does not grow only for accounts that exist (point 70) |

### Messaging

| Table | What it holds | Notes |
| --- | --- | --- |
| `envelopes` | id, recipient **device**, channel, `payload`, optional `invite`, created, expires | Addressed to a device, not a person. Deleted on acknowledgement, and expired by housekeeping regardless. No sender column — who sent it is inside the ciphertext. `expires_at` may be sooner than the default when the sender asked for disappearing messages (point 74). `available_at` is when the fetch route may return the row: zero unless the sender asked for a delivery delay (ADR-0085) |
| `attachments` | id, `ciphertext`, created, expires | Blind blobs for messages (point 78): no sender, no recipient, no conversation, no filename, no media type, no plaintext length. The id is chosen by the client and *is* the capability; the key never reaches the server. Expired by `DELIVERY_TTL_MS`, and deletable by anyone who holds the id |

### Money

Custodial balances, in piconero, with an append-only ledger behind them (migration 014,
ADR-0066). Nothing in this group can be written without its ledger entry in the same
transaction, and `test/wallet.test.ts` re-adds the entries to check.

| Table | What it holds | Notes |
| --- | --- | --- |
| `balances` | `account_id`, optional user, `available_pico`, `held_pico`, optional `payout_limit_pico`, updated | One row per account, plus the single `'platform'` row that receives fees — so revenue reconciles like any other balance. CHECK constraints refuse a negative balance; `payout_limit_pico` is the hand-set ceiling above which a payout waits for an administrator |
| `ledger_entries` | id, account, `kind`, `available_delta`, `held_delta`, optional order/deposit/withdrawal, created | Append-only. Every movement, signed, in two columns: `available` is spendable, `held` is committed to an open order or a queued payout. A hold sums to zero across the two |
| `deposit_addresses` | user, `subaddress_index`, `address`, created | One Monero subaddress per account, never reused: a shared address would make an incoming payment unattributable |
| `deposits` | id, user, `amount_pico`, `txid`, subaddress index, `confirmations`, status (`credited` \| `below_minimum`), detected/credited | A confirmed transfer, credited once — a transfer under `MIN_DEPOSIT_XMR` is recorded with no ledger entry and shown to its owner rather than kept (ADR-0067) — unique on (txid, subaddress index, amount), so a watcher that re-reads a transfer cannot pay twice. A Monero transaction names no sender, so `txid` is the whole of what can be recorded about where money came from |
| `order_evidence` | id, order, user, `kind`, `digest`, `created_at` | A commitment, not the evidence: `digest` is `HMAC-SHA256(order id, file bytes)` computed in the browser (ADR-0074), `kind` is a word from a fixed list, and there is no column a file or a sentence could go in. Unique on (order, user, digest), deleted with the order |
| `send_tokens` | `token_hash`, `expires_at` | Sealed sender (ADR-0084). Unspent single-use tokens, hashed like sessions, with **no owner column and no issued-at**: nothing here can be joined to an account. A token is deleted by the request that spends it, so this table holds what is unspent and no history. Expiries carry per-token jitter, because one shared `expires_at` would group a person's batch |
| `lockdown` | single row: `engaged_at`, `note` | The operator's freeze (ADR-0080). While the row exists every write is refused with 503 and every read works. Written by `scripts/incident.mjs`, never by a route — there is no API that can freeze or thaw the platform |
| `withdrawal_approvals` | payout, admin, `created_at` | One row per (payout, administrator): above `DUAL_APPROVAL_ABOVE_XMR` a payout needs two distinct rows here before it is queued (ADR-0076). The primary key makes the same admin clicking twice one signature |
| `withdrawals` | id, user, `amount_pico`, `address` (until sent), `address_hint`, status, `txid`, `network_fee_pico`, requested/`claimed_at`/decided/settled | The destination is deleted when the payout leaves; the hint (first and last six characters) is what support needs. A Monero address appears nowhere on the chain, so a hint correlates with nothing. `claimed_at` is the moment the payout worker took the row: the clock an operator reads when a payout is stuck in `sending` (ADR-0073), and it dies with the row |

### Marketplace

| Table | What it holds | Notes |
| --- | --- | --- |
| `sellers` | user, display name, bio, status, `joined_day`, `settled_pico`, `level`, `last_settled_day`, `level_penalty`, `bond_pico`, `bond_posted_at` | A seller is a role on an account, not a separate identity. `settled_pico` is on-platform earnings, written only by an order settling; `level` (0–3) is derived from it and from completed orders (ADR-0068), less one step per `SELLER_LEVEL_DECAY_DAYS` of dormancy and one per suspension (ADR-0072). The earned level is never deleted — these two columns decide how much of it the catalogue shows. `bond_pico` is the stake (ADR-0086); the money itself is `held_pico` on their account, and `bond_posted_at` starts the release cool-off |
| `seller_applications` | applicant, display name, statement, status, decision note, decider, days | |
| `listings` | seller, title, description, category, kind, `price_pico`, status, days, `rank_key` | Piconero (10⁻¹² XMR) as a `BIGINT` integer; one currency, no `currency` column, no floating-point money (ADR-0064). `rank_key` is `level * 100000 + created_day`, the catalogue's sort key, kept on the listing so pagination stays a seek on one index (ADR-0068) |
| `orders` | listing, buyer, seller, price at the time, status, `channel`, created/updated | `channel` is the encrypted conversation the order lives in. **No address column** — a shipping address is a message (ADR-0021) |
| `order_events` | order, actor, from/to status, `created_at` | The state machine's history, with a real timestamp because dispute questions are "in what order" |
| `deliveries` | order, encrypted digital goods, expiry | Ciphertext, capped by `MAX_DELIVERY_BYTES`, expired by `DELIVERY_TTL_MS` |
| `reviews` | order (unique), listing, seller, author, rating, body, status, `created_day` | One review per order, enforced by the schema |
| `reports` | target type and id, reporter, reason, details, status, resolution note, resolver, days | |

### Operations

| Table | What it holds | Notes |
| --- | --- | --- |
| `audit_log` | actor, action, target, `result` (`ok`/`denied`/`failed`), short note, `created_at` | Security-relevant administrative actions, refusals included. Never plaintext, secrets or keys; the note is capped at 64 characters; pruned after `AUDIT_RETENTION_MS` (default one year) |
| `security_events` | account, event kind, day, count | The account's *own* history — sign-ins, refused sign-ins, password and key changes, recoveries, revocations. One row per kind per day, upserted, so a flood of failed attempts is a counter and not a timeline. No address, no user agent, no session or device id, no free text; readable only by the owner (`GET /api/auth/security-events`), with no staff route over it; pruned after `SECURITY_EVENT_RETENTION_DAYS` (ADR-0090) |
| `bootstrap_claims` | `id` (the name of the thing claimed, `admin` today), `claimed_at` | The genesis administrator, claimed by one statement instead of decided by an empty `users` table (ADR-0104, finding SEC-2026-002). One row per deployment, inserted with `ON CONFLICT DO NOTHING RETURNING` inside the transaction that writes the first account, so two racing registrations cannot both win and a failed registration releases the claim. Operational: it describes the deployment and joins to no account |
| `canary_statements` | the signed text, the armoured signature, the key and its `pgp_fingerprint`, the day it was signed, the day the next is due, the day it arrived | The operator's canary (ADR-0099). Both dates are parsed *out of the signed statement*, never chosen by the server, so a row whose dates were rewritten no longer verifies. Append-only in practice — every statement stays, so a reader can check the series — and one row per period, which is a handful a year. Public through `GET /api/canary`; nothing in it belongs to a user |
| `rate_limits` | bucket key, tokens, updated | The key is an HMAC of the subject with a daily-rotating pepper — **no address is stored**, and yesterday's buckets cannot be linked to today's |
| `schema_migrations` | migration name, applied at | |

## Invariants the database holds by itself

Application checks (a `SELECT`, then an `INSERT`) are only as strong as the gap between the
two statements; on PostgreSQL that gap is a network round trip. Since migration 007 the rules
that matter under concurrency are also constraints, and a constraint violation is answered
with `409` rather than logged as an incident (`isConstraintViolation` in `lib/errors.ts`):

| Rule | Enforced by |
| --- | --- |
| One review per order | `reviews.order_id UNIQUE` |
| One application under review per account | partial unique index `seller_applications_one_pending` |
| One *open* order per buyer per listing (a double-click is one order) | partial unique index `orders_one_open_per_listing` |
| One seller per display name, one device per identity key, one session per token | `UNIQUE` columns |
| An order moves only from the state its caller saw | every transition is `UPDATE … WHERE id = ? AND status = ? RETURNING id`; no row returned → `409 stale_status` |
| A delivery exists only for an order that is `delivered`, and vice versa | the blob insert and the status change share one transaction, and the status change is conditional |
| Nothing references a deleted account | foreign keys on (`PRAGMA foreign_keys = ON` in SQLite), `ON DELETE CASCADE` |

`test/integrity.test.ts` fires the same request several times at once and asserts exactly one
winner for each rule above.

What is *not* there, and why: `CHECK` constraints on the status and enum columns of the
original tables. SQLite cannot add a constraint to an existing table — the table has to be
rebuilt, which with foreign keys enabled inside a transaction cascades a delete through every
child table (reproduced, not theorised; ADR-0028). Enum values are validated at the trust
boundary by `asEnum`, the only path a request has to a status column; tables created after
007 carry `CHECK` from birth.

## Search index (008)

`listings_category_idx` on `(status, category)` serves `GET /api/market/categories`, which is
a grouped count over the active catalogue; category values are folded on write, so the index
holds one entry per category rather than one per spelling of it (ADR-0082).

`listing_terms` is an inverted index: one row per (word, listing), primary key
`(term, listing_id)`. Words come from `tokenize()` in `src/server/lib/search.ts` — NFKD,
accents dropped, lowercased, letters and digits only, 2–32 characters, at most 200 distinct
words per listing. It is written in the same transaction as the listing it describes, dropped
with it by `ON DELETE CASCADE`, and rebuilt for anything that predates it by
`backfillSearchIndex()` at boot. `listings_page_idx (status, created_day, id)` carries both
the filter and the sort order for keyset pagination, so a page is a seek rather than an
`OFFSET` scan.

## Notifications (009)

`notifications` is an inbox: `user_id`, a `kind` from a closed set, an optional subject
(`order`, `listing`, `review`, `user`) and a `detail` of at most 32 characters, constrained by
`CHECK` so no free text can ever be stored there. There is no sender column, no channel
column and no body. The partial unique index `notifications_one_unread_message` allows one
unread `message` row per account, so the table cannot become a per-conversation message
counter; `notifications_inbox_idx (user_id, created_at, id)` serves the paginated read.

## Retention, and what deletes what

- Envelopes: on acknowledgement, or at `ENVELOPE_TTL_MS` (30 days).
- Deliveries: at `DELIVERY_TTL_MS` (30 days).
- Attachments: at `DELIVERY_TTL_MS` (30 days), or when someone holding the id deletes them.
  They are **not** removed by account deletion, because there is no owner column to remove
  them by — the absence of that column is the point, and the expiry is what bounds it
  (`docs/DELETION.md`).
- Sessions: at expiry, and immediately on logout.
- Audit entries: at `AUDIT_RETENTION_MS` (one year).
- Notifications: at `NOTIFICATION_RETENTION_MS` (90 days), read or unread.
- Rate-limit buckets: keys change daily; stale rows are pruned.
- Account deletion: `ON DELETE CASCADE` from `users` through every table above.
  `test/auth.test.ts` deletes an account and then reads every table to prove nothing is left.

Housekeeping runs on an interval in `src/server/main.ts`, so an idle deployment still forgets.

## Operating notes

- **SQLite**: WAL mode, foreign keys on, one file (`SQLITE_PATH`). Back it up with
  `sqlite3 … ".backup"`, not `cp`. Encrypt the backup — it contains the ciphertext and the
  metadata, which is exactly what an attacker who cannot break the crypto wants.
- **PostgreSQL**: set `DATABASE_URL` (or `DATABASE_URL_FILE`). Give the application its own
  role with rights on its own schema only; migrations run as that role. Every millisecond
  timestamp is `BIGINT` (migration 012) and the driver parses `BIGINT` into a number rather
  than the string `pg` returns by default, so both drivers hand the application the same
  types; a value too large to represent exactly throws instead of rounding
  (`src/server/db/postgres.ts`).
- **Both drivers run the whole test suite** on every commit — SQLite by default,
  PostgreSQL in the `postgres` CI job (`TEST_DATABASE_URL`, `docs/TESTING.md`). The first
  run of that job found two real defects, which is the argument for having it.
- Neither driver ever interpolates a value into SQL. The lint rule `sql-interpolation`
  enforces it, and the one place that builds a column list from literals is marked and
  explained.
