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
- **CSRF.** Three independent layers on every unsafe method (`security.ts`):
  `SameSite=Strict` on the session cookie, the `Origin` header checked against `Host` when
  the browser sends one, and a double-submit token — the `csrf` cookie repeated in an
  `X-CSRF-Token` header, which a cross-site page can neither read nor set. Safe methods
  need none of it, and a request without a matching token is answered `403`.
- **Errors.** `{ "error": "code", "message": "human text" }` with a 4xx status. A 500 returns
  `{ "error": "internal_error", "message": "internal error", "ref": "…" }` — the `ref` is the
  only thing shared between the log line and the user (point 29).
- **Rate limits.** Each endpoint below names its bucket; see `docs/DEPLOYMENT.md` for
  `RATE_LIMITS`. Exhausting one returns `429` with `Retry-After`.
- **Proof of work.** The three unauthenticated account endpoints (`register`, `login`,
  `recovery/challenge`) answer `428` when a request arrives without one:

  ```json
  { "error": "pow_required",
    "message": "…",
    "pow": { "challenge": "…", "mac": "…", "bits": 16, "expiresInSeconds": 300 } }
  ```

  Find a `nonce` such that `SHA-256("symvolon-pow-v1:" + challenge + ":" + nonce)` starts
  with `bits` zero bits, then repeat the request with `pow: { challenge, mac, nonce }`
  added to the body. A solution is single use (`400 pow_spent` on reuse) and valid for five
  minutes; the difficulty is covered by the MAC, so a client cannot choose it. There is no
  endpoint to fetch a challenge from — the refusal carries it, so no round trip is wasted
  and there is nothing to poll. The browser client does this transparently
  (`src/client/api.ts`); so does the test client (ADR-0039).
- **Ciphertext.** Anything called `payload`, `sealed`, `envelope` or `ciphertext` is base64url
  of bytes the server cannot read and never tries to parse.

## Public pages and assets

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `GET /` | — | The application shell, with SRI digests for the bundle |
| `GET /assets/*` | — | The built client: `app-<hash>.js`, its lazily loaded crypto chunk, `app-<hash>.css`. Content-addressed names, pre-compressed, `Cache-Control: immutable` |
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
| `GET /api/auth/sessions` | session | `read` | This account's sessions, by day rather than timestamp. No token, no address, no user agent — there is nothing else stored to show |
| `DELETE /api/auth/sessions/:id` | session (owner) | `sensitive` | Revoke one session. A session belonging to somebody else answers exactly like one that does not exist |
| `POST /api/auth/password` | session | `sensitive` | Change the password: new `authSecret` and re-sealed vault, in one transaction |
| `POST /api/auth/delete` | session | `sensitive` | Delete the account. Cascades to every table that references it (`test/auth.test.ts` proves nothing is left) |

## Recovery, device linking and PGP

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/auth/recovery/key` | session | `sensitive` | Register the public half of a recovery phrase |
| `POST /api/auth/recovery/challenge` | — | `recovery` | Get a challenge to sign with the recovery key. Answered for every username, including ones nobody registered, and issuing one invalidates the account's previous challenge |
| `POST /api/auth/recovery/complete` | — | `recovery` | Prove the signature, set a new `authSecret` and vault. Every way of failing — unknown challenge, expired, wrong signature, no recovery key, suspended account — returns one message |
| `POST /api/auth/link` | session | `sensitive` | Start linking a second device; returns a one-time link secret |
| `POST /api/auth/link/claim` | — | `sensitive` | Claim a link secret from the new device |
| `POST /api/auth/pgp/key` | session | `sensitive` | Attach a PGP public key to the account |
| `POST /api/auth/pgp/challenge` | session | `sensitive` | Challenge to sign with that key |
| `POST /api/auth/pgp/complete` | — | `sensitive` | Log in with a PGP signature |
| `POST /api/auth/pgp/remove` | session | `sensitive` | Detach the PGP key |

## Keys

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/keys/device` | session | `sensitive` | Publish a device: identity key, signed prekey, signature. Re-publishing the same identity key rotates its prekeys; an identity key that was **revoked** is refused for good (`409 device_revoked`) |
| `POST /api/keys/one-time` | session | `write` | Top up one-time prekeys |
| `GET /api/keys/status` | session | `read` | How many prekeys are left, which devices are active |
| `GET /api/keys/bundle/:username` | session | `key_bundle` | A prekey bundle for starting a session with someone (consumes one one-time key per device, which is why this read has its own tight bucket — ADR-0035) |
| `POST /api/keys/revoke` | session | `sensitive` | Revoke a device |
| `PUT /api/keys/vault`, `GET /api/keys/vault` | session | `sensitive` / `read` | The sealed vault: private keys encrypted under a key derived from the password. Opaque to the server |

## Messages

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/messages` | session | `message_send` | Deliver an envelope to a recipient device. Padded ciphertext only. Optional `ttlHours` (1–720) asks for an expiry shorter than `ENVELOPE_TTL_MS` — disappearing messages, whole hours, applied to every envelope in the conversation so the expiry cannot single out a control message (point 74) |
| `GET /api/messages` | session | `read` | Fetch envelopes addressed to this account's devices |
| `POST /api/messages/ack` | session (owner) | `write` | Acknowledge envelopes, which deletes them |

## Attachments

Blind blob storage for anything a conversation carries that is not text — a picture, a
recording, a document (point 78). The client encrypts before uploading, chooses the id, and
sends the key inside the encrypted message; the server stores bytes it cannot open and is
told nothing about them. No filename, no media type, no sender, no recipient.

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/attachments` | session | `attachment` | Store one blob: `{ id, ciphertext }` and nothing else — any other field is refused with `unexpected_field`. `id` is the client's own 192-bit random handle and the value the ciphertext is authenticated against; a colliding id is refused with `id_taken`. `ciphertext` is capped in decoded bytes by `MAX_DELIVERY_BYTES` |
| `GET /api/attachments/:id` | session | `read` | Fetch the ciphertext. Deliberately not scoped to a party: scoping needs a recipient column, and that column is the social graph. The id is the capability, and the key is still needed to open it |
| `DELETE /api/attachments/:id` | session | `write` | Delete it early. Whoever holds the id may delete: the sender and the people they sent it to |

## Notifications

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `GET /api/notifications` | session | `read` | The account's inbox, newest first. `?limit=` (1–50, default 20), `?cursor=` from `nextCursor`. Each item is `{ id, kind, subjectType, subjectId, detail, at, read }`; `unread` is the badge count |
| `POST /api/notifications/read` | session | `write` | `{ all: true }` or `{ ids: [...] }` (at most 50). Ids belonging to another account match nothing |

`kind` is one of `message`, `order`, `seller_application`, `moderation`, `review`, `dispute`.
`detail` is a status word this server chose (`placed`, `accepted`, `approved`, `suspended`,
`removed`, `hidden`…) — never text a user typed. A `message` notification carries no subject,
no sender, no channel and no count: it says that something arrived, and the client learns
what by fetching and decrypting its envelopes (ADR-0032). The wording a reader sees lives in
the client.

## Marketplace

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `GET /api/market/listings` | — | `search` | Browse and search. `?q=` (words, 2+ characters each, ANDed, prefix-matched against the `listing_terms` index), `?category=`, `?kind=`, `?limit=` (1–50, default 20), `?cursor=` from the previous page's `nextCursor`. Returns `{ listings, nextCursor }`; `nextCursor` is `null` on the last page. No offsets and no total count — see ADR-0030 |
| `GET /api/market/listings/:id` | — | `read` | One listing |
| `GET /api/market/sellers/:username` | — | `read` | A seller's public profile and reviews |
| `POST /api/market/seller-applications` | session | `seller_application` | Apply to sell |
| `GET /api/market/seller-applications/mine` | session | `read` | The state of my own application |
| `POST /api/market/listings` | session (seller) | `listing_write` | Create a listing |
| `PATCH /api/market/listings/:id` | session (owner) | `listing_write` | Edit or pause a listing |
| `POST /api/market/orders` | session | `order_write` | Place an order; opens an encrypted channel with the seller |
| `GET /api/market/orders` | session (party) | `read` | My orders, as buyer or as seller |
| `POST /api/market/orders/:id/status` | session (party) | `order_write` | Advance the order state machine; illegal and stale transitions are refused server-side (`409 stale_status`). `disputed` requires a `reason` (10–2000 chars), which is filed as a report for moderation; a moderator settling a dispute closes that report and is audited |
| `POST /api/market/orders/:id/review` | session (buyer) | `review` | Review a completed order, once |
| `POST /api/market/orders/:id/delivery` | session (seller) | `message_send` | Deliver: exactly one of `{ ciphertext }` for anything the seller encrypted in the browser (file, licence key, credentials, link — the server does not know which), or `{ manual: true }` for a delivery that happened outside the platform. Either moves the order to `delivered`. No other field is accepted — a body carrying `filename`, `mimeType` or `path` is refused with `unexpected_field`, and `ciphertext` is capped in decoded bytes by `MAX_DELIVERY_BYTES` |
| `GET /api/market/orders/:id/delivery` | session (buyer) | `read` | Download that ciphertext. Answered as JSON with `nosniff` and no `Content-Disposition`: the server never serves stored bytes as a document (ADR-0033) |
| `DELETE /api/market/orders/:id/delivery` | session (seller) | `write` | Withdraw it before collection |

Physical orders have no address column: the shipping address is an ordinary encrypted
message in the order channel (ADR-0021).

## Moderation and administration

Staff routes verify the role server-side on every request and write an audit entry with the
result, including refusals (`docs/PRIVACY.md`, ADR-0024).

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `GET /api/moderation/queue` | staff | `moderation` | Open reports and pending applications. A report about an order carries the order's public facts and the seller's record (completed and disputed orders, distinct reviewers) — never its channel |
| `POST /api/moderation/reports` | session | `moderation` | Report a listing, review, user or order. `reason: dispute` is refused here — disputes are opened on the order by its buyer |
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
search over users and no search over messages: private search happens in the browser, over
what that device has already decrypted, because a server-side index of end-to-end encrypted
messages either does nothing or requires the plaintext (point 79).

There is no presence, no "last seen" and no delivery-state route. Typing indicators and read
receipts exist only as ordinary encrypted messages between two clients, off by default —
the server has no state for either and cannot tell such an envelope from any other
(`docs/METADATA.md`). There is no push endpoint, no device token and no third-party
notification service: the client polls, and the inbox says only that something arrived.

Reviews are returned without their author. A review proves a completed order happened;
naming the buyer would publish what someone bought to everyone who can read the page
(point 81).
