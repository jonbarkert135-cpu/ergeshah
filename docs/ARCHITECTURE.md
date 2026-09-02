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

## Module layout

```
src/shared/crypto/   protocol: hkdf, aead, identity, x3dh, ratchet, vault, session
src/shared/          encoding helpers used by both sides
src/server/
  app.ts             Fastify wiring, authentication, CSRF, rate limiting
  security.ts        CSP and the rest of the browser-level hardening
  config.ts          configuration, refuses weak secrets in production
  db/                driver interface + sqlite/postgres drivers + migrations
  lib/               sessions, password hashing, validation, audit, rate limiting
  routes/            auth, keys, messages, market, moderation, static
src/client/
  state.ts           encrypted vault, device publication
  messaging.ts       sessions, send/receive/acknowledge
  views/             auth, chat, market, orders, account, moderation
test/                RFC vectors, protocol properties, API behaviour, authorization
```

`src/shared` is imported by both sides unchanged; the protocol has exactly one
implementation, and the tests exercise that implementation, not a copy of it.

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
commercial data with day-granularity timestamps. `reports` and `audit_log` support
moderation. `rate_limits` holds rotating HMACs, never addresses. Full field-by-field
justification: [`PRIVACY.md`](PRIVACY.md).

## Why these technologies

Recorded as decisions with alternatives and trade-offs in [`DECISIONS.md`](DECISIONS.md).
The short version: Node 22 (native TypeScript execution, bundled SQLite), Fastify (small,
no implicit middleware), libsodium (audited primitives, identical in browser and server),
esbuild (one-step self-hosted client bundle), no framework on the client, no ORM on the
server, and no service that requires an API key for any core feature.
