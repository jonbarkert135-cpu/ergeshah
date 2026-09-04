# HTTP API

Every path below is real: `test/docs.test.ts` walks Fastify's route table and fails if an
endpoint exists that is not documented here, or if this page documents one that does not
exist. Drifted API documentation is worse than none, because people trust it.

## Versioning

The current version is **v1**. `/api/v1/messages` and `/api/messages` are the same
endpoint — the prefix is stripped before routing, so there is one route table and nothing
that can drift between the two spellings — and every response under `/api/` carries
`X-API-Version: 1`.

A change that would break a client that has not been updated ships as `/api/v2` next to v1,
never as an edit to v1. A change that only adds a field, an optional parameter or a new
endpoint stays in v1, because a client that ignores it keeps working. When v2 exists, this
page says how long v1 answers and what replaced it.

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
  `RATE_LIMITS`. Exhausting one returns `429` with a `Retry-After` header *and*
  `retryAfterSeconds` in the body — the number of seconds until the bucket has a token
  again, so a client waits instead of inventing a backoff.
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
| `GET /api/admin/health` | admin | Operational health: uptime, CPU, memory, disk, database latency, storage and housekeeping state, request count, error rate and latency percentiles. Numbers, booleans and four fixed words only — see `docs/OBSERVABILITY.md` |

## Accounts and sessions

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/auth/register` | — | `register` | Create an account: username, `authSecret` (derived client-side), initial device and sealed vault |
| `POST /api/auth/login` | — | `login` | Exchange username + `authSecret` for a session cookie. Identical response and timing whether or not the account exists |
| `POST /api/auth/logout` | session | `sensitive` | End this session |
| `POST /api/auth/logout-everywhere` | session | `sensitive` | End every session of this account |
| `GET /api/auth/me` | session | `read` | Who am I: username, role, seller status, whether recovery and PGP are configured |
| `GET /api/auth/security-events` | session (owner) | `read` | This account's own security history: a kind, a day and a count, for a fixed list of events (ADR-0090). No addresses, no times of day, no staff route over the same table |
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
| `POST /api/auth/pgp/key` | session | `sensitive` | Enrol a PGP public key, or replace the one that is there. Enrolling needs the password and a signature from the key arriving; **replacing needs a `currentSignature` from the key being replaced** (ADR-0088) |
| `POST /api/auth/pgp/challenge` | session | `sensitive` | A challenge to sign. `intent: "key"` (default) yields `pgp-enroll` or `pgp-rotate` depending on whether a key is already set; `intent: "remove"` yields `pgp-remove`. The reply names the `purpose` and whether a current-key signature is required |
| `POST /api/auth/pgp/complete` | — | `sensitive` | Log in with a PGP signature |
| `POST /api/auth/pgp/remove` | session | `sensitive` | Detach the PGP key: password, a `pgp-remove` challenge, and a signature from the key being removed. Lost the key? Use the recovery phrase, which clears the factor |

### What a challenge says (ADR-0087)

Every signed challenge in this API is a single line of text, and the signature is over
exactly those bytes:

```
symvolon-auth-v1 service=<SERVICE_ID> purpose=<recovery|pgp-enroll|pgp-rotate|pgp-remove|pgp-login> id=<challenge id> expires=<ISO 8601> nonce=<32 random bytes, base64url>
```

The nonce gives freshness; the rest gives *binding*. A signature made to add a key is not a
signature that removes one, a signature made for this deployment does not verify against
another `SERVICE_ID`, and a signature made five minutes ago is over a statement that says so.
Challenges remain single-use: the row is deleted when it is answered, valid or not.

## Keys

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/keys/device` | session | `sensitive` | Publish a device: identity key, signed prekey, signature. Re-publishing the same identity key rotates its prekeys; an identity key that was **revoked** is refused for good (`409 device_revoked`) |
| `POST /api/keys/one-time` | session | `write` | Top up one-time prekeys |
| `GET /api/keys/status` | session | `read` | How many prekeys are left, which devices are active, each device's `signedPreKeyAgeDays` and `signedPreKeyStale` — the flag the browser acts on to rotate a week-old signed prekey mid-session (ADR-0078) |
| `GET /api/keys/bundle/:username` | session | `key_bundle` | A prekey bundle for starting a session with someone (consumes one one-time key per device, which is why this read has its own tight bucket — ADR-0035) |
| `POST /api/keys/revoke` | session | `sensitive` | Revoke a device |
| `PUT /api/keys/vault`, `GET /api/keys/vault` | session | `sensitive` / `read` | The sealed vault: private keys encrypted under a key derived from the password. Opaque to the server |

## Messages

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `POST /api/messages` | session **or** an unspent `x-send-token` (ADR-0084) | `message_send` | Deliver an envelope to a recipient device. Padded ciphertext only. Optional `delaySeconds` (0–`MAX_DELIVERY_DELAY_SECONDS`, rounded up to a multiple of 15) holds the envelope before it can be fetched (ADR-0085). Optional `ttlHours` (1–720) asks for an expiry shorter than `ENVELOPE_TTL_MS` — disappearing messages, whole hours, applied to every envelope in the conversation so the expiry cannot single out a control message (point 74) |
| `POST /api/messages/tokens` | session | `send_tokens` | Mint a batch of single-use sealed-sender tokens (ADR-0084). The server stores only their hashes, with no owner: this is the one call in the sending path that knows who you are |
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
| `GET /api/market/categories` | — | `read` | The categories that have something in them, `{ categories: [{ category, listings }] }`, most populated first, at most 50. Counts only active listings of unsuspended sellers, so a category page never promises more than it shows. Category names are folded (ADR-0082): lowercase, accent-normalised, one space between words |
| `GET /api/market/sellers/:username` | — | `read` | A seller's public profile and reviews |
| `POST /api/market/seller/bond` | session (seller) | `write` | Stake XMR against your own conduct (ADR-0086). Minimum `BOND_MIN_XMR`; the cool-off restarts |
| `POST /api/market/seller/bond/release` | session (seller) | `write` | Return the whole bond. 409 while the cool-off runs or one of your orders is disputed |
| `GET /api/market/seller/bond` | session (seller) | `read` | What is staked, how many disputes are open, and when it can be released |
| `POST /api/market/moderation/orders/:id/bond-claim` | staff | — | Pay a harmed buyer out of the seller's bond: completed orders that were disputed or reported, once each, capped at the price. `amountXmr` and a `note` for the audit log |
| `POST /api/market/seller-applications` | session | `seller_application` | Apply to sell |
| `GET /api/market/seller-applications/mine` | session | `read` | The state of my own application |
| `POST /api/market/listings` | session (seller) | `listing_write` | Create a listing |
| `PATCH /api/market/listings/:id` | session (owner) | `listing_write` | Edit or pause a listing |
| `POST /api/market/orders` | session | `order_write` | Place an order; opens an encrypted channel with the seller. The price is held from the buyer's balance in the same transaction — an unfunded buyer is refused with `402 insufficient_balance` and no order exists (ADR-0066) |
| `GET /api/market/orders` | session (party) | `read` | My orders, as buyer or as seller |
| `POST /api/market/orders/:id/status` | session (party) | `order_write` | Advance the order state machine; illegal and stale transitions are refused server-side (`409 stale_status`). `disputed` requires a `reason` (10–2000 chars), which is filed as a report for moderation; a moderator settling a dispute closes that report and is audited |
| `POST /api/market/orders/:id/review` | session (buyer) | `review` | Review a completed order, once |
| `POST /api/market/orders/:id/delivery` | session (seller) | `message_send` | Deliver: exactly one of `{ ciphertext }` for anything the seller encrypted in the browser (file, licence key, credentials, link — the server does not know which), or `{ manual: true }` for a delivery that happened outside the platform. Either moves the order to `delivered`. No other field is accepted — a body carrying `filename`, `mimeType` or `path` is refused with `unexpected_field`, and `ciphertext` is capped in decoded bytes by `MAX_DELIVERY_BYTES` |
| `GET /api/market/orders/:id/delivery` | session (buyer) | `read` | Download that ciphertext. Answered as JSON with `nosniff` and no `Content-Disposition`: the server never serves stored bytes as a document (ADR-0033) |
| `DELETE /api/market/orders/:id/delivery` | session (seller) | `write` | Withdraw it before collection |

Physical orders have no address column: the shipping address is an ordinary encrypted
message in the order channel (ADR-0021).

## Balance

Money is Monero, held by the marketplace (`docs/PAYMENTS.md`). Amounts in and out are decimal
strings of XMR; the server stores piconero as integers.

| Endpoint | Auth | Limit | Notes |
| --- | --- | --- | --- |
| `POST /api/market/orders/:id/evidence` | session (buyer or seller) | `order_write` | Commit a digest of bytes the party says were exchanged: `{ digest, kind }`. `digest` is 64 lower-case hex characters — `HMAC-SHA256(order id, file bytes)`, computed in the browser (ADR-0074). The server stores it and never sees the file. Errors: `invalid_digest` (400), `already_committed` (409), `evidence_full` (409, ten per party), `stale_status` (409, the order is finished). A moderator gets 404: they may read, never add |
| `GET /api/market/orders/:id/evidence` | session (parties or staff) | `read` | Every commitment on the order, oldest first: `{ id, by: "buyer" \| "seller", kind, digest, on, beforeDispute }`. Same list for both parties and the moderator |
| `GET /api/wallet` | session | `read` | Available and held balance, this account's deposit address (`null` until the deployment has a wallet), the minimums (with `fastCreditMaxXmr` and `confirmations`, the tiered wait from ADR-0077), `belowMinimumXmr` (top-ups that arrived under `MIN_DEPOSIT_XMR`, recorded and not credited — ADR-0067) with `minRefundXmr` and `canRefund` beside it, the amount above which a payout waits for approval, and the marketplace fee |
| `GET /api/wallet/entries` | session | `read` | This account's ledger: every movement, signed, with the order it belongs to and a day-granularity date |
| `POST /api/wallet/withdrawals` | session | `wallet_write` | Request a payout: `{ amountXmr, address }`. The amount leaves the spendable balance at once; the answer says whether it was `queued` or needs approval. One pending payout per account (`payout_pending`) |
| `POST /api/wallet/refunds` | session | `wallet_write` | Send an uncredited top-up back: `{ address }`. Everything below the minimum goes at once, as one payout through the ordinary queue — `{ id, status, amountXmr, deposits, addressHint }`. Errors: `nothing_to_refund` (409), `refund_too_small` (400, under `MIN_REFUND_XMR`), `payout_pending` (400) — ADR-0071 |
| `GET /api/wallet/withdrawals` | session | `read` | This account's payouts, with the destination shown as a hint and the transaction id once sent |
| `POST /api/wallet/withdrawals/:id/cancel` | session (owner) | `wallet_write` | Cancel one that has not been sent; the money returns to the balance |

There is no endpoint that credits a balance, and no transfer between accounts: money enters
only as a confirmed Monero deposit seen by a wallet this server cannot spend from, and leaves
only as a payout row a separate process picks up.

### The payout queue (worker only)

Three endpoints that belong to the payout worker, not to any browser: they authenticate with
`Authorization: Bearer $PAYOUT_WORKER_TOKEN`, compared in constant time, and they answer 401 to
everything else — including a perfectly valid staff session. With no token configured the queue
is closed and answers 401 to every caller, which is the state of a deployment with no payout
tier (ADR-0070).

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/payouts/claim` | worker token | Takes the oldest `queued` payout and marks it `sending` in the same statement, so two workers cannot be given the same row. Answers `{ payout: null }` when the queue is empty. The destination address is returned here and nowhere else |
| `POST /api/payouts/:id/sent` | worker token | `{ txid, networkFeeXmr }`. The transaction id must be 64 hex characters (`invalid_txid`); the destination is deleted and the hold leaves the balance |
| `POST /api/payouts/:id/failed` | worker token | The payout was not sent: the money returns to the owner's spendable balance. No reason is stored |

Nothing re-queues a payout automatically. A row left in `sending` because the worker died is
an operator reading their own wallet history — the alternative pays somebody twice. Since
ADR-0073 the row carries `claimed_at`, so `GET /api/moderation/withdrawals` reports
`sendingForMinutes` and a `stuck` flag (over two hours), and an admin resolves it with
`POST /api/moderation/withdrawals/:id/resolve`.

The deposit minimum is enforced (ADR-0067). A transfer smaller than `MIN_DEPOSIT_XMR` is
recorded as a `below_minimum` deposit and not credited — it is not kept quietly either: the
total appears on the owner's own wallet response, and its owner can send it back to an address
they name with `POST /api/wallet/refunds` (ADR-0071) — one payout for all of it, subject to
`MIN_REFUND_XMR`, because the platform pays the network fee on the way out. Below that floor an
operator still settles it by hand.

## Moderation and administration

Staff routes verify the role server-side on every request and write an audit entry with the
result, including refusals (`docs/PRIVACY.md`, ADR-0024).

| Method & path | Auth | Limit | Purpose |
| --- | --- | --- | --- |
| `GET /api/moderation/queue` | staff | `moderation` | Open reports and pending applications. A report about an order carries the order's public facts and both parties' records — the seller's (completed and disputed orders, distinct reviewers) and the buyer's (orders, completed, disputed, and disputes as a share of their orders; ADR-0083) — never its channel |
| `POST /api/moderation/reports` | session | `moderation` | Report a listing, review, user or order. `reason: dispute` is refused here — disputes are opened on the order by its buyer |
| `POST /api/moderation/reports/:id/resolve` | staff | `moderation` | Close a report with a note |
| `POST /api/moderation/seller-applications/:id/decide` | staff | `moderation` | Approve or reject an application |
| `POST /api/moderation/listings/:id/remove` | staff | `moderation` | Remove a listing |
| `POST /api/moderation/reviews/:id/hide` | staff | `moderation` | Hide a review |
| `POST /api/moderation/users/:username/status` | staff | `moderation` | Suspend or reinstate an account |
| `GET /api/moderation/withdrawals` | session (staff) | `moderation` | Payouts awaiting approval or waiting to be sent, oldest first, destinations as hints. Each carries `approvals`/`approvalsRequired` (ADR-0076) and, for a row the worker took, `sendingForMinutes` and `stuck` (ADR-0073) |
| `POST /api/moderation/withdrawals/:id/decide` | session (admin) | `moderation` | `{ decision: "approved" \| "rejected" }`. Approving queues it — this process cannot send. Above `DUAL_APPROVAL_ABOVE_XMR` an approval is a signature: the payout stays parked until two different admins have approved, and the answer carries `{ status, approvals, approvalsRequired }` (ADR-0076). Refusing takes one admin and returns the money to the owner. Audited |
| `POST /api/admin/users/:username/payout-limit` | session (admin) | `moderation` | `{ limitXmr }` or `{ limitXmr: "default" }`: how much this account may withdraw without approval, per request and per 24 hours. Audited with the amount |
| `POST /api/moderation/withdrawals/:id/resolve` | session (admin) | `moderation` | Resolve by hand a payout the worker took and never reported: `{ outcome: "sent" \| "failed", txid?, networkFeeXmr? }`. `sent` requires the 64-hex transaction id (`invalid_txid`); only a `sending` row can be resolved (`stale_status`). Sends nothing — it records which of the two things happened, and is audited as `withdrawal.resolved` (ADR-0073) |
| `GET /api/admin/treasury` | session (admin) | `moderation` | The books as five totals (uncredited top-ups among them) plus liabilities, and — when a wallet tier exists — what the wallet actually holds and the shortfall between them (`null` otherwise). Names nobody |
| `GET /api/moderation/audit` | staff | `moderation` | Read the administrative log |
| `POST /api/admin/users/:username/role` | admin | `moderation` | Grant or remove staff roles |

## Error codes

Every code this server can answer with. `test/api.test.ts` extracts them from the source and
fails if one is missing here, or if this table names one that no longer exists.

| Code | Status | Means |
| --- | --- | --- |
| `bad_request` | 400 | A value is missing, malformed or too long. The message names the field |
| `invalid_characters` | 400 | Invisible, control or direction-reversing characters in a field |
| `invalid_username` | 400 | Not 3–32 characters of `a-z0-9._-`, starting and ending alphanumeric |
| `invalid_cursor` | 400 | The pagination cursor was not one this API issued |
| `query_too_vague` | 400 | A search term shorter than two characters |
| `unexpected_field` | 400 | A body carried a field this endpoint refuses to accept — silently dropping it is how a client comes to depend on storage that does not exist (ADR-0033) |
| `pow_spent` | 400 | That proof-of-work solution has already been used |
| `below_dust` | 400 | A price above zero but under 0.001 XMR — smaller than the network fee it would take to pay or refund it |
| `below_minimum` | 400 | An amount under a configured floor — a payout below `MIN_WITHDRAWAL_XMR` |
| `invalid_txid` | 400 | The payout worker reported something that is not a 64-character Monero transaction hash |
| `bad_address` | 400 | Not a Monero address: wrong length, a character base58 does not contain, or a prefix no Monero network uses. The wallet's own `validate_address` is the authority before anything is sent |
| `payout_pending` | 400 | This account already has a payout queued or awaiting approval |
| `invalid_digest` | 400 | An evidence commitment was not 64 lower-case hex characters. The shape is the only thing this server can check about a digest — whether it is the digest of anything is between the two parties, who both have the file |
| `already_committed` | 409 | The same digest is already on the record for this party and this order. Committing twice is one commitment |
| `evidence_full` | 409 | Ten commitments from one party on one order is the limit: enough for any honest dispute, too few to use this as storage or as a channel |
| `bad_category` | 400 | A listing's category folded away to fewer than two letters or digits — it was punctuation, or emoji |
| `locked_down` | 503 | The operator has frozen the deployment (ADR-0080): every write is refused and every read still works. Nothing has been deleted; the message says so, because a bare 503 on a marketplace reads as "they have taken my money" |
| `nothing_to_refund` | 409 | A refund was asked for and this account has no uncredited top-up — already refunded, already settled by an operator, or never there |
| `refund_too_small` | 400 | The uncredited total is under `MIN_REFUND_XMR`, which is less than the network fee to return it is worth. It stays on the account, visible, until there is more of it |
| `off_platform_offer` | 400 | A listing, or a seller application, carried a wallet address, an email address, another messenger or an offer to be paid outside the escrow (ADR-0069). The message names the rule, never the pattern that matched |
| `balance_not_empty` | 409 | Account deletion, with money still on the balance or held in an open order. Withdraw first — deleting must not silently keep it |
| `unauthorized` | 401 | No session, or an expired one |
| `forbidden` | 403 | Authenticated, but not allowed: a missing role, a failed CSRF check, or a suspended account |
| `not_found` | 404 | No such route, or no such object *for this caller* — the two are deliberately indistinguishable |
| `insufficient_balance` | 402 | The request is well formed and the account has not got the money: placing an order with an unfunded balance, or a movement that would overdraw one |
| `conflict` | 409 | The request lost a race with one that arrived first |
| `username_taken`, `display_name_taken`, `id_taken`, `identity_key_taken` | 409 | The name, id or key is already in use |
| `already_applied`, `already_seller`, `already_ordered`, `already_reviewed` | 409 | The action has already happened once, and once is the limit |
| `device_revoked` | 409 | A revoked identity key cannot be re-published |
| `stale_status` | 409 | The order moved on before this transition arrived |
| `current_key_signature_required` | 400 | Replacing a PGP key without a signature from the key being replaced. A session and a password are not enough to swap the second factor (ADR-0088) |
| `pgp_absent` | 400 | A removal challenge was asked for on an account with no PGP key |
| `vault_required` | 409 | The account has no sealed vault yet, and the operation needs one |
| `too_large` | 413 | The body exceeds the configured cap |
| `pow_required` | 428 | Solve the enclosed challenge and repeat the request |
| `rate_limited` | 429 | The bucket is empty; `retryAfterSeconds` says for how long |
| `storage_full` | 503 | The server is low on disk and refuses new blobs; deliveries and attachments only, and retryable |
| `internal_error` | 500 | A fault on this side. The body carries a `ref` that matches one log line and nothing else |

An error never names a table, a column, a driver, a path or a stack. The message is written
for the person who has to fix their request; the code is what a client branches on.

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
