# HTTP API

Every path below is real: `test/docs.test.ts` walks Fastify's route table and fails if an
endpoint exists that is not documented here, or if this page documents one that does not
exist. Drifted API documentation is worse than none, because people trust it.

## Conventions

- **Transport.** JSON in, JSON out, `Content-Type: application/json`. One origin; no CORS
  headers are sent, so no other site can call this API from a browser.
- **Authentication.** A `session` cookie: `HttpOnly`, `SameSite=Strict`, `Secure` (except on
  a `.onion` origin, where there is no TLS layer to require — see `docs/ARCHITECTURE.md`).
  There are no bearer tokens and no API keys.
- **CSRF.** Every `/api/` request must carry `X-Requested-With: symvolon`. A cross-site form
  post cannot set a header, and `SameSite=Strict` already withholds the cookie.
- **Errors.** `{ "error": "code", "message": "human text" }` with a 4xx status. A 500 returns
  `{ "error": "internal_error", "message": "internal error", "ref": "…" }` — the `ref` is the
  only thing shared between the log line and the user (point 29).
- **Rate limits.** Each endpoint below names its bucket; see `docs/DEPLOYMENT.md` for
  `RATE_LIMITS`. Exhausting one returns `429` with `Retry-After`.
- **Ciphertext.** Anything called `payload`, `sealed`, `envelope` or `ciphertext` is base64url
  of bytes the server cannot read and never tries to parse.

## Public pages and assets

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `GET /` | — | The application shell, with SRI digests for the bundle |
| `GET /assets/app.js`, `GET /assets/app.css` | — | The client bundle. Immutable, digest-addressed |
| `GET /favicon.svg` | — | Icon |
| `GET /build.txt` | — | Digests of exactly these files, so a visitor can verify the build (`npm run audit:deployment`) |
| `GET /healthz` | — | Liveness for the container healthcheck. Reveals nothing |

## Accounts and sessions

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/auth/register` | — | `register` | Create an account: username, `authSecret` (derived client-side), initial device and sealed vault |
| `POST /api/auth/login` | — | `login` | Exchange username + `authSecret` for a session cookie. Identical response and timing whether or not the account exists |
| `POST /api/auth/logout` | session | `sensitive` | End this session |
| `POST /api/auth/logout-everywhere` | session | `sensitive` | End every session of this account |
| `GET /api/auth/me` | session | `read` | Who am I: username, role, seller status, whether recovery and PGP are configured |
| `GET /api/auth/sessions` | session | `read` | This account's sessions, by day rather than timestamp |
| `DELETE /api/auth/sessions/:id` | session (owner) | `sensitive` | Revoke one session |
| `POST /api/auth/password` | session | `sensitive` | Change the password: new `authSecret` and re-sealed vault, in one transaction |
| `POST /api/auth/delete` | session | `sensitive` | Delete the account. Cascades to every table that references it (`test/auth.test.ts` proves nothing is left) |

## Recovery, device linking and PGP

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/auth/recovery/key` | session | `sensitive` | Register the public half of a recovery phrase |
| `POST /api/auth/recovery/challenge` | — | `recovery` | Get a challenge to sign with the recovery key |
| `POST /api/auth/recovery/complete` | — | `recovery` | Prove the signature, set a new `authSecret` and vault |
| `POST /api/auth/link` | session | `sensitive` | Start linking a second device; returns a one-time link secret |
| `POST /api/auth/link/claim` | — | `sensitive` | Claim a link secret from the new device |
| `POST /api/auth/pgp/key` | session | `sensitive` | Attach a PGP public key to the account |
| `POST /api/auth/pgp/challenge` | session | `sensitive` | Challenge to sign with that key |
| `POST /api/auth/pgp/complete` | — | `sensitive` | Log in with a PGP signature |
| `POST /api/auth/pgp/remove` | session | `sensitive` | Detach the PGP key |

## Keys

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/keys/device` | session | `sensitive` | Publish a device: identity key, signed prekey, signature |
| `POST /api/keys/one-time` | session | `write` | Top up one-time prekeys |
| `GET /api/keys/status` | session | `read` | How many prekeys are left, which devices are active |
| `GET /api/keys/bundle/:username` | session | `read` | A prekey bundle for starting a session with someone (consumes one one-time key) |
| `POST /api/keys/revoke` | session | `sensitive` | Revoke a device |
| `PUT /api/keys/vault`, `GET /api/keys/vault` | session | `sensitive` / `read` | The sealed vault: private keys encrypted under a key derived from the password. Opaque to the server |

## Messages

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/messages` | session | `message_send` | Deliver an envelope to a recipient device. Padded ciphertext only |
| `GET /api/messages` | session | `read` | Fetch envelopes addressed to this account's devices |
| `POST /api/messages/ack` | session (owner) | `write` | Acknowledge envelopes, which deletes them |

## Marketplace

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `GET /api/market/listings` | — | `search` | Browse and search. The one query that scans, hence its own bucket |
| `GET /api/market/listings/:id` | — | `read` | One listing |
| `GET /api/market/sellers/:username` | — | `read` | A seller's public profile and reviews |
| `POST /api/market/seller-applications` | session | `seller_application` | Apply to sell |
| `GET /api/market/seller-applications/mine` | session | `read` | The state of my own application |
| `POST /api/market/listings` | session (seller) | `listing_write` | Create a listing |
| `PATCH /api/market/listings/:id` | session (owner) | `listing_write` | Edit or pause a listing |
| `POST /api/market/orders` | session | `order_write` | Place an order; opens an encrypted channel with the seller |
| `GET /api/market/orders` | session (party) | `read` | My orders, as buyer or as seller |
| `POST /api/market/orders/:id/status` | session (party) | `order_write` | Advance the order state machine; illegal transitions are refused server-side |
| `POST /api/market/orders/:id/review` | session (buyer) | `review` | Review a completed order, once |
| `POST /api/market/orders/:id/delivery` | session (seller) | `message_send` | Upload the encrypted digital goods for this order |
| `GET /api/market/orders/:id/delivery` | session (buyer) | `read` | Download that ciphertext |
| `DELETE /api/market/orders/:id/delivery` | session (seller) | `write` | Withdraw it before collection |

Physical orders have no address column: the shipping address is an ordinary encrypted
message in the order channel (ADR-0021).

## Moderation and administration

Staff routes verify the role server-side on every request and write an audit entry with the
result, including refusals (`docs/PRIVACY.md`, ADR-0024).

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `GET /api/moderation/queue` | staff | `moderation` | Open reports and pending applications |
| `POST /api/moderation/reports` | session | `moderation` | Report a listing, review or user |
| `POST /api/moderation/reports/:id/resolve` | staff | `moderation` | Close a report with a note |
| `POST /api/moderation/seller-applications/:id/decide` | staff | `moderation` | Approve or reject an application |
| `POST /api/moderation/listings/:id/remove` | staff | `moderation` | Remove a listing |
| `POST /api/moderation/reviews/:id/hide` | staff | `moderation` | Hide a review |
| `POST /api/moderation/users/:username/status` | staff | `moderation` | Suspend or reinstate an account |
| `GET /api/moderation/audit` | staff | `moderation` | Read the administrative log |
| `POST /api/admin/users/:username/role` | admin | `moderation` | Grant or remove staff roles |

## What the API deliberately does not have

No endpoint returns another user's address, timestamps finer than a day where a day is
enough, a message plaintext, a private key, or a list of who talks to whom. There is no
search over users, no "who is online", no read receipts and no typing indicators — each is a
metadata channel with no way to make it private.
