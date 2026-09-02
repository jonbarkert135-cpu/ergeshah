# What is stored, and why

Every column in the database is listed here. If a field is not in this document, it is
not in the schema.

## Accounts

| Field | Why it exists | Granularity |
| --- | --- | --- |
| `users.id` | Primary key | Random UUID, not sequential |
| `users.username` | You are addressed by it | As chosen, lowercased |
| `users.password_hash` | scrypt over the client-derived `authSecret` (itself Argon2id) | — |
| `users.role`, `status`, `status_reason` | Moderation | — |
| `users.created_day` | Account age for anti-abuse | **Day**, not timestamp |

Not collected: email, phone number, real name, address, date of birth, gender, IP
address, user agent, device fingerprint, referrer, or any third-party identifier.

## Sessions

`id`, `user_id`, `token_hash` (SHA-256 of the token — the token itself is never stored),
an optional label you set, `created_at`, `expires_at`, and `last_seen_day` (day
granularity: enough to expire idle sessions, useless as an activity timeline).

## Cryptographic material

`devices` and `one_time_prekeys` hold public keys, key ids and signatures only. A
one-time prekey row is **deleted** the moment it is claimed. `vaults` holds one
XChaCha20-Poly1305 blob per user that the server cannot open.

## Messages

`envelopes`: `id`, `recipient_device_id`, `channel` (an opaque random id chosen by the
clients), `payload` (ciphertext), `invite` (public handshake values), `created_at`,
`expires_at`.

- There is **no sender column**. The sender's name is inside the ciphertext.
- The ciphertext is a version-2 envelope: a sealed 80-byte header and a padded body. The
  ratchet public key, chain length and message counter are encrypted, so the rows cannot
  be grouped into sessions, and the length is a bucket (64/256/1024/4096·n), not the
  message's real size.
- Rows are deleted when the recipient acknowledges delivery, and unconditionally after
  `ENVELOPE_TTL_MS` (30 days by default).
- The server can still see: which device an envelope is for, how large it is, and when it
  arrived and was collected. That is metadata we do not currently hide (see
  THREAT_MODEL.md).

## Marketplace

`sellers`, `listings`, `orders`, `order_events`, `reviews` hold ordinary commercial data:
titles, descriptions, prices, statuses, ratings, and day-granularity dates. Orders store
`buyer_user_id`, `seller_user_id` and an opaque `channel` for the encrypted order chat —
no address, no payment identifier, no invoice, because payments are deliberately not part
of this system.

`order_events` keeps millisecond timestamps: a dispute needs an ordered record of who did
what, and both parties already know it.

## Moderation

`reports` (target, reason, free text from the reporter, day) and `audit_log` (actor,
action, subject, note, timestamp). The audit log records *staff* actions only. Ordinary
browsing, reading, searching and messaging are never logged anywhere.

## Rate limiting

`rate_limits` stores `HMAC-SHA256(pepper ‖ unix-day, address ‖ scope)`, a token count and
a timestamp. Rows older than a day are deleted. There is no reverse lookup from a row to
an address without the address, and the key rotates daily.

## Logs

- Application access logs: **disabled**.
- Application error logs: method, route, error message. No bodies, no ids, no addresses.
- Proxy access logs: disabled in the shipped `Caddyfile`.
- Container logs therefore contain startup lines and errors, nothing else.

## Retention summary

| Data | Kept |
| --- | --- |
| Undelivered envelope | Until acknowledged, at most 30 days |
| Delivered envelope | Deleted immediately |
| Session | Until logout or 30 days |
| Rate-limit bucket | 24 hours |
| One-time prekey | Until claimed |
| Account, listings, orders, reviews | Until deleted by the user or moderation |
| Audit entry | Indefinitely (it exists to be reviewable) |

## Deleting an account

`POST /api/auth/delete` (password required) removes, in one transaction: the account row,
the sealed vault, every device and its prekeys, every undelivered envelope addressed to
those devices, sessions, listings, orders, order events, reviews and reports. There is no
tombstone and no soft-delete flag, so **the username becomes available to someone else**.

Three references are unlinked rather than deleted, because they are records of what a
*moderator* did and are not the deleted user's to erase: `audit_log.actor_user_id`,
`reports.resolved_by` and `seller_applications.decided_by` are set to NULL. The action, its
subject and its day remain.

Two consequences worth stating plainly:

- A counterparty loses shared history. Deleting an account deletes its orders and reviews,
  including the other side's copy of them. A marketplace that kept them would be keeping
  the deleted user's data, and we chose deletion over bookkeeping.
- Messages already delivered to other people stay with them. The server cannot reach into
  another user's device, and E2EE means it could not read them to delete them anyway.

## Recovery material

| Field | What it is | What it is not |
| --- | --- | --- |
| `users.recovery_public_key` | Ed25519 public key derived from the phrase | not the phrase, not the private half, not reversible |
| `vaults.sealed.recovery` | the master key wrapped with a phrase-derived key | not openable by the server |
| `auth_challenges` | a random challenge, its account, an expiry | deleted on use; no signature, no phrase |

The phrase itself never reaches the server — not in a request body, not in a log, not in a
backup. Nothing in the database can be turned back into it, which is also why nobody here
can restore an account whose phrase and password are both gone.

## PGP material

`users.pgp_public_key` holds the armoured public key exactly as pasted, and
`users.pgp_fingerprint` its fingerprint. Both are public by nature — a public key is meant
to be published. Nothing about the private half is stored, requested or logged; a private
key block sent to `/api/auth/pgp/key` is rejected before anything is written.

A key usually carries user IDs — often a name and an email address. That is data the user
chose to attach and can strip with `gpg --export-options export-minimal`; the interface
shows the identities a key claims and marks them unverified. This is the one place where a
user can voluntarily put an email address into the database, and nothing here requires it.

## Linked devices

`device_links` holds, per pending authorisation: SHA-256 of the secret, the account id, an
optional label and an expiry. No token, no address, nothing about the device beyond what
the key directory already stores. Rows are deleted on redemption, or on the first claim
attempt after they expire.

A linked device keeps its vault locally only. It never uploads a sealed vault, because the
account has one backup and it belongs to the device that knows the account password.

## Changing the password

The password derives both the server-side auth secret and the vault key. `POST
/api/auth/password` therefore takes the current secret, the new secret and the vault
re-sealed under the new key, and writes the hash and the vault in one transaction: there is
no window in which the account authenticates but its keys are unreadable. Every other
session is destroyed, because each was authorised under a password that no longer exists.

## Cookies and browser storage

| Name | Purpose | Flags |
| --- | --- | --- |
| `session` | Opaque session token | HttpOnly, Secure, SameSite=Strict |
| `csrf` | Double-submit CSRF token | Secure, SameSite=Strict, readable by our own script |
| `localStorage["symvolon.vault.v2"]` | Encrypted key vault and message history | Client-side only |

No other cookie, no `sessionStorage`, no IndexedDB, no service worker, no web beacon.
