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

A released migration is **never edited**: `src/server/db/migrations/CHECKSUMS.txt` records a
digest of each, `npm run audit:migrations` fails if one changes, and `npm run migrate:checksums`
is how a *new* one is registered. Destructive statements require a `-- destructive: why`
comment. `test/migrations.test.ts` applies the whole set to an empty database, runs it twice
to prove the runner is idempotent, and checks the indexes hot queries depend on.

## Tables

### Identity

| Table | What it holds | Notes |
| --- | --- | --- |
| `users` | id, username, `password_hash`, role, status, `created_day`, optional `recovery_public_key`, `pgp_public_key`, `pgp_fingerprint` | No email, no phone, no display name, no address. Argon2id hash of a client-derived secret — the password never reaches the server |
| `sessions` | id, user, `token_hash`, optional label, created/expires, `last_seen_day` | Only the hash of the cookie value is stored. Last seen is a day |
| `vaults` | user, `sealed`, `updated_day` | The user's private keys, encrypted client-side |
| `devices` | id, user, label, identity key, signed prekey and signature, created/rotated day, `revoked_at` | Public key material only |
| `one_time_prekeys` | id, device, key id, public key, `claimed_at` | Consumed one at a time when someone starts a conversation |
| `device_links` | `link_hash`, user, label, expiry | Short-lived, hashed one-time secrets for adding a second device |
| `auth_challenges` | challenge material for recovery and PGP logins, with expiry | Deleted on use |

### Messaging

| Table | What it holds | Notes |
| --- | --- | --- |
| `envelopes` | id, recipient **device**, channel, `payload`, optional `invite`, created, expires | Addressed to a device, not a person. Deleted on acknowledgement, and expired by housekeeping regardless. No sender column — who sent it is inside the ciphertext |

### Marketplace

| Table | What it holds | Notes |
| --- | --- | --- |
| `sellers` | user, display name, bio, status, `joined_day` | A seller is a role on an account, not a separate identity |
| `seller_applications` | applicant, display name, statement, status, decision note, decider, days | |
| `listings` | seller, title, description, category, kind, `price_minor`, currency, status, days | Integer minor units; no floating-point money |
| `orders` | listing, buyer, seller, price at the time, status, `channel`, created/updated | `channel` is the encrypted conversation the order lives in. **No address column** — a shipping address is a message (ADR-0021) |
| `order_events` | order, actor, from/to status, `created_at` | The state machine's history, with a real timestamp because dispute questions are "in what order" |
| `deliveries` | order, encrypted digital goods, expiry | Ciphertext, capped by `MAX_DELIVERY_BYTES`, expired by `DELIVERY_TTL_MS` |
| `reviews` | order (unique), listing, seller, author, rating, body, status, `created_day` | One review per order, enforced by the schema |
| `reports` | target type and id, reporter, reason, details, status, resolution note, resolver, days | |

### Operations

| Table | What it holds | Notes |
| --- | --- | --- |
| `audit_log` | actor, action, target, `result` (`ok`/`denied`/`failed`), short note, `created_at` | Security-relevant administrative actions, refusals included. Never plaintext, secrets or keys; the note is capped at 64 characters; pruned after `AUDIT_RETENTION_MS` (default one year) |
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

`listing_terms` is an inverted index: one row per (word, listing), primary key
`(term, listing_id)`. Words come from `tokenize()` in `src/server/lib/search.ts` — NFKD,
accents dropped, lowercased, letters and digits only, 2–32 characters, at most 200 distinct
words per listing. It is written in the same transaction as the listing it describes, dropped
with it by `ON DELETE CASCADE`, and rebuilt for anything that predates it by
`backfillSearchIndex()` at boot. `listings_page_idx (status, created_day, id)` carries both
the filter and the sort order for keyset pagination, so a page is a seek rather than an
`OFFSET` scan.

## Retention, and what deletes what

- Envelopes: on acknowledgement, or at `ENVELOPE_TTL_MS` (30 days).
- Deliveries: at `DELIVERY_TTL_MS` (30 days).
- Sessions: at expiry, and immediately on logout.
- Audit entries: at `AUDIT_RETENTION_MS` (one year).
- Rate-limit buckets: keys change daily; stale rows are pruned.
- Account deletion: `ON DELETE CASCADE` from `users` through every table above.
  `test/auth.test.ts` deletes an account and then reads every table to prove nothing is left.

Housekeeping runs on an interval in `src/server/main.ts`, so an idle deployment still forgets.

## Operating notes

- **SQLite**: WAL mode, foreign keys on, one file (`SQLITE_PATH`). Back it up with
  `sqlite3 … ".backup"`, not `cp`. Encrypt the backup — it contains the ciphertext and the
  metadata, which is exactly what an attacker who cannot break the crypto wants.
- **PostgreSQL**: set `DATABASE_URL` (or `DATABASE_URL_FILE`). Give the application its own
  role with rights on its own schema only; migrations run as that role.
- Neither driver ever interpolates a value into SQL. The lint rule `sql-interpolation`
  enforces it, and the one place that builds a column list from literals is marked and
  explained.
