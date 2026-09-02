# What is stored, and why

Every column in the database is listed here. If a field is not in this document, it is
not in the schema.

## Accounts

| Field | Why it exists | Granularity |
| --- | --- | --- |
| `users.id` | Primary key | Random UUID, not sequential |
| `users.username` | You are addressed by it | As chosen, lowercased |
| `users.password_hash` | Argon2id over the client-derived `authSecret` | — |
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

## Cookies and browser storage

| Name | Purpose | Flags |
| --- | --- | --- |
| `session` | Opaque session token | HttpOnly, Secure, SameSite=Strict |
| `csrf` | Double-submit CSRF token | Secure, SameSite=Strict, readable by our own script |
| `localStorage["ergeshah.vault.v1"]` | Encrypted key vault and message history | Client-side only |

No other cookie, no `sessionStorage`, no IndexedDB, no service worker, no web beacon.
