# Architecture

## Shape of the system

```
browser (all cryptography lives here)
   │  HTTPS / onion service, same-origin only
   ▼
reverse proxy (Caddy)  ── last component that sees a client IP address
   │  X-Forwarded-For, used for rate limiting and then discarded
   ▼
application server (Fastify, Node 22)
   │  parameterised SQL only
   ▼
database (SQLite by default, PostgreSQL optional)
```

There is no message broker, no cache server, no object storage, no external API, and no
background worker. Every feature in this repository runs inside those four boxes, which
is what makes the deployment fit on one VPS and the attack surface small enough to read
end to end.

## Trust boundaries

| Boundary | What crosses it | What is assumed |
| --- | --- | --- |
| user ↔ browser | password, plaintext | The device and the browser are trusted. If they are not, nothing below matters. |
| browser ↔ proxy | TLS records | The network is hostile: passive observation, MITM and injection are assumed. |
| proxy ↔ app | HTTP + client IP | The proxy is operated by the same person as the app. It is the only component that sees addresses. |
| app ↔ database | SQL | The database is *not* trusted with plaintext messages or with anything that would let it read them. |
| app ↔ moderator | public content only | Staff can act on listings, reviews, applications and accounts. Staff cannot read messages: no code path exists. |

The strong claim this architecture makes is narrow and precise: **a full compromise of
the server (application, database, backups) does not yield the plaintext of past or
future private messages**, because the keys required to produce that plaintext never
exist on the server. Everything else the server *can* see is enumerated in
[`PRIVACY.md`](PRIVACY.md).

That claim is about *this* code, and this code is closed (`LICENSE`). An outsider can
confirm the shape of it — inspect the client their browser runs, watch the requests it
makes, compare the published build digest with other users — but not read the source. See
residual risk #1 in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Module layout

```
src/shared/crypto/   protocol: hkdf, aead, identity, x3dh, ratchet, vault, session, file
src/shared/          encoding helpers and the QR encoder used by both sides
src/server/
  app.ts             Fastify wiring, authentication, CSRF, rate limiting
  security.ts        CSP and the rest of the browser-level hardening
  config.ts          configuration, refuses weak secrets in production
  db/                driver interface + sqlite/postgres drivers + migrations
  lib/               sessions, password hashing, validation, audit, rate limiting
  routes/            auth, recovery, keys, messages, market, deliveries, moderation,
                     health, static
src/client/
  state.ts           encrypted vault, device publication
  messaging.ts       sessions, send/receive/acknowledge
  verification.ts    safety numbers, per-device verified state
  views/             auth, chat, market, orders, account, moderation
test/                RFC vectors, protocol properties, API behaviour, authorization
```

`src/shared` is imported by both sides unchanged; the protocol has exactly one
implementation, and the tests exercise that implementation, not a copy of it.

## Domain boundaries (a modular monolith)

One process, one container, one database: on a single VPS a network hop between services
is latency, an attack surface and an operations burden, and buys nothing. The boundaries are
still real — they are module boundaries, and `test/architecture.test.ts` reads every import
in `src/` and fails if one crosses a line in the table below.

| Domain | Where it lives | Owns |
| --- | --- | --- |
| AUTH | `routes/auth.ts`, `routes/recovery.ts`, `lib/sessions.ts`, `lib/password.ts`, `lib/pgp.ts`, `lib/auth_flow.ts` | accounts and sessions in the first module; the paths that bypass the password — a second device, a recovery phrase, a PGP key — in the second, because they share one rule set and one failure sentence |
| IDENTITY | `routes/keys.ts`, `shared/crypto/identity.ts`, `vault.ts` | devices, prekeys, the sealed vault, device linking |
| MESSAGING | `routes/messages.ts`, `lib/send_tokens.ts`, `client/messaging.ts` | store-and-forward envelopes, delivery, acknowledgement, disappearing-message expiry, and the single-use tokens that let a client post an envelope without a session (ADR-0084). Typing indicators, read receipts and search live entirely on the client side of this line (`docs/METADATA.md`) |
| CRYPTO | `shared/crypto/*` | the protocol: one implementation, imported by both sides, imports neither |
| MARKETPLACE / SELLERS / ORDERS / REVIEWS | `routes/market.ts`, `routes/evidence.ts`, `lib/reputation.ts`, `lib/search.ts`, `lib/evidence.ts` | listings, applications, the order state machine, reviews and reputation, and the digests a disputing party commits to without uploading the file (ADR-0074) |
| STORAGE (BLIND BLOBS) | `routes/deliveries.ts` | ciphertext the server cannot open: order deliveries and message attachments (point 78), and their deletion |
| MONEY | `routes/wallet.ts`, `lib/ledger.ts`, `lib/refunds.ts` | balances, the append-only ledger, escrow on an order, deposits, payouts, and the refund of a top-up that was never credited (ADR-0071). Knows nothing about Monero itself: no address, no node, no key |
| MONERO | `lib/monero.ts`, `lib/deposits.ts`, `routes/payouts.ts` | the view-only side of the chain: a subaddress per account, a scan that credits confirmed transfers, a solvency comparison, and the queue the payout worker pulls from. It can see money and cannot move it; sending lives in `scripts/payout-worker.mjs`, on another host (ADR-0070) |
| MODERATION / ADMIN | `routes/moderation.ts`, `lib/audit.ts` | reports and disputes, decisions, roles, the audit trail, and money oversight (the payout queue, per-account limits, the treasury total) |
| BACKGROUND WORK | `lib/jobs.ts`, the job list in `main.ts` | hourly sweeps, ordered by importance and isolated from each other (ADR-0079). No scheduler and no job table: the durable queues are `withdrawals` and `deposits` |
| SECURITY | `app.ts`, `security.ts`, `lib/rate_limit.ts`, `lib/validate.ts` | authentication of requests, CSRF, CSP, limits, input validation at the boundary |
| INFRASTRUCTURE | `db/*`, `config.ts`, `main.ts`, `routes/static.ts` | drivers, migrations, configuration, the built client and its digests |
| OBSERVABILITY | `routes/health.ts`, `lib/metrics.ts` | uptime, resources, database latency and aggregate request counters, for an administrator only. Counts and times, never a route, an account or a body (point 85, `docs/OBSERVABILITY.md`) |
| NOTIFICATIONS | `routes/notifications.ts`, `lib/notify.ts`, `client/views/notifications.ts` | the internal inbox: which of *your* records changed, never what a message said. No push, no email, no device token — the client polls (point 48, ADR-0032) |

Rules the test enforces: `shared/` imports no side; the client never imports the server and
vice versa; `lib/` never imports `routes/`; `db/` knows no domain; and one route module never
imports another — what two domains share goes to `lib/` (validation constants, reputation,
audit), and the only place they meet is `app.ts`, which wires them.

## Request lifecycle

1. The reverse proxy terminates TLS and forwards the request with `X-Forwarded-For`.
2. Fastify runs with request logging disabled. Nothing about the request is written to
   disk unless it produces a 500, and then only method, route and error message.
3. `enforceCsrf` checks Origin against Host and a double-submit token for any unsafe
   method.
4. The route resolves the session cookie to a user (`SHA-256` lookup, no plaintext token
   stored), rejects suspended accounts, and applies a token-bucket rate limit whose key
   is `HMAC(pepper ‖ day, address ‖ scope)`.
5. Input is validated field by field before it reaches SQL, which is always
   parameterised.
6. The response carries `default-src 'self'` CSP, `no-referrer`, `no-store` and friends.

## Data model in one paragraph

`users` holds a username, a scrypt hash of the already-Argon2id-stretched secret, a role and a
status. `devices` and `one_time_prekeys` hold public key material only. `envelopes` hold
ciphertext addressed to a device, with a channel id the clients chose and no sender
column. `vaults` hold a blob the server cannot open. The marketplace tables
(`sellers`, `listings`, `orders`, `order_events`, `reviews`) hold public or two-party
commercial data with day-granularity timestamps. `deliveries` holds at most one encrypted
file per order — ciphertext, order id and two timestamps, deleted on pickup, completion or
expiry. `reports` and `audit_log` support
moderation. `rate_limits` holds rotating HMACs, never addresses. Full field-by-field
justification: [`PRIVACY.md`](PRIVACY.md).

## Linking a second device

Each device has its own key pair. Two browsers sharing one identity would mean two copies
of the same ratchet advancing independently, which desynchronises every conversation, so
linking never copies keys.

1. The new browser generates an identity and a 32-byte secret, and shows both as a code,
   together with the fingerprint of its identity key.
2. A signed-in device reads the code, shows the same fingerprint for the person to compare,
   publishes the new device's public bundle (it is authenticated; the new device is not),
   and stores a one-time authorisation keyed by SHA-256 of the secret, valid five minutes.
3. The new browser redeems the authorisation once and receives a session. The row is
   deleted in the same transaction, so a photographed code is worthless afterwards, and no
   token is stored in plaintext anywhere: the session is minted at redemption.
4. The new browser seals its own local vault under a password chosen for that device, and
   does *not* upload it — the account has exactly one sealed backup, owned by the device
   that knows the account password.

Senders already encrypt per recipient device, so both devices receive their own ciphertext
from then on. History is not transferred: the server has no plaintext to replay.

## Why these technologies

Recorded as decisions with alternatives and trade-offs in [`DECISIONS.md`](DECISIONS.md).
The short version: Node 22 (native TypeScript execution, bundled SQLite), Fastify (small,
no implicit middleware), libsodium (audited primitives, identical in browser and server),
`openpgp` for verifying PGP signatures on the server only (ADR-0015), esbuild (one-step self-hosted client bundle), no framework on the client, no ORM on the
server, and no service that requires an API key for any core feature.
