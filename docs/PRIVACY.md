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
an optional label you set, `created_at`, `expires_at`, `rotated_at`, and `last_seen_day` (day
granularity: enough to expire idle sessions, useless as an activity timeline).

## How you are identified

Three identifiers, kept apart on purpose (point 72):

| Layer | What it is | Who sees it |
| --- | --- | --- |
| **Public username** | What you chose, what people address you by, what appears on a listing | Everyone |
| **Internal identifier** | A random UUIDv4 in `users.id`, the join key of the database | The server. It is never in a response about somebody else — `test/sessions.test.ts` checks the routes that could leak one |
| **Cryptographic identity** | Your devices' Ed25519/X25519 public keys, and the safety number derived from them | Anyone you talk to, for verification |

None of them is a counter. A sequential id would publish how many accounts exist, in what
order they were created, and — for a listing or an order — how much business happens here
and when, to anyone who can read a URL. Every id in this system is random, so an id reveals
nothing except itself, and guessing one is not a way in (`docs/THREAT_MODEL.md`, IDOR).

The three are related only inside the database. A username can be deleted and taken by
someone else; the internal id never leaves the server; the cryptographic identity is the
only one that actually proves anything, which is why verification is built on it and not
on the name.

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
  `ENVELOPE_TTL_MS` (30 days by default) — or sooner, in whole hours, when the sender asked
  for disappearing messages (`docs/DELETION.md`). The requested hour is the one thing that
  choice tells the operator, which is why it is hours rather than minutes and why every
  envelope in the conversation carries the same one.
- The server can still see: which device an envelope is for, how large it is, and when it
  arrived and was collected. That is metadata we do not currently hide (see
  THREAT_MODEL.md).

`attachments`: `id`, `ciphertext`, `created_at`, `expires_at`. A picture, a recording or a
document a conversation carries (point 78) is encrypted in the browser, uploaded as an
opaque blob under an id the *client* generated, and opened with a key that travels inside
the message. There is no sender column, no recipient column, no conversation, no filename,
no media type and no plaintext length — the id is the whole addressing scheme, and it is
192 random bits. The operator learns that a blob exists, its padded size, and when it was
stored and fetched.

An image is also cleaned before it is encrypted: EXIF, GPS coordinates, camera model and
serial, embedded thumbnails, XMP and IPTC blocks are dropped in the browser (ADR-0092,
`docs/STORAGE.md`). That one is not about the operator — the file is ciphertext to them — it
is about the person receiving it, who holds the key. It reduces exposure; it does not make a
photograph anonymous, and the room, the faces and the filename are still in it.

**Typing indicators, read receipts and presence are not columns anywhere.** They are
messages between two clients, off until a person turns them on, and the settings themselves
live in the encrypted vault rather than in a table — a row saying "this account has read
receipts off" would be one more fact about a person on a server that is trying not to hold
any. `docs/METADATA.md` takes each one in turn.

## Marketplace

`sellers`, `listings`, `orders`, `order_events`, `reviews` hold ordinary commercial data:
titles, descriptions, prices, statuses, ratings, and day-granularity dates. Orders store
`buyer_user_id`, `seller_user_id` and an opaque `channel` for the encrypted order chat —
no address, no payment identifier, no invoice, because payments are deliberately not part
of this system.

`deliveries` holds one encrypted file per order: an id, the order id, the ciphertext, and
the times it was created and expires. There is no uploader column (only the order's seller
can write it), no filename, no media type and no hash — a filename is content, and it
travels inside the ciphertext with everything else. The operator learns that an order was
delivered, the padded size of the file (a multiple of 4 KB), and when it was uploaded and
collected.

**Rate-limit buckets are keyed to accounts as well as addresses.** The bucket key is
still an HMAC that rotates daily and still stores no address, but for a request carrying a
session the subject is the account id rather than the address. That is a privacy
improvement as well as a security one: on an onion service the address is meaningless
(everyone is 127.0.0.1), and hashing a meaningless value while letting one user throttle
everybody else is the worst of both.

**The administrative log is bounded on three sides.** `audit_log` records staff actions —
who, what action, which subject, the result, the timestamp — and now also the refusals: an
authenticated account turned away from a privileged route leaves an entry naming the route
*pattern*, never the concrete URL, so the log cannot become a record of which order someone
poked at. It contains no message content, no keys, no tokens and no free text (the `note`
column takes short controlled values like a role name and is truncated at 64 characters).
Entries are deleted after `AUDIT_RETENTION_MS`, one year by default: oversight needs recent
history, and keeping the rest forever would build exactly the pile of personal data this
project exists to avoid.

**Your own security history is a counter, not a timeline.** `security_events` lets an account
see what has happened to it — sign-ins, refused sign-ins, password and key changes,
recoveries, revocations (ADR-0090). It holds an account id, an event kind, a **day** and a
count, and nothing else: no address, no user agent, no session or device id, no time of day,
no free text. Repeats within a day increment the count, so the shape of the table is one row
per kind per day however busy or however attacked the account is. It is readable by its owner
alone — no staff route selects from it, and a test asserts that — and it is deleted after
`SECURITY_EVENT_RETENTION_DAYS`, ninety by default. A refused sign-in against a username
nobody registered records nothing at all, so the table never becomes a list of names strangers
have tried.

**Physical orders carry no address.** A delivery address, a phone number, a door code — none
of them is a column here, and no route accepts one. The buyer's browser encrypts them to
the seller through the order's channel, the seller's browser keeps the plaintext in its
local vault, and the server holds only the same opaque envelope it holds for any other
message, deleted the moment it is delivered. An operator who dumps this database gets the
fact that an order exists, its parties, its price and its status — and no way to ship
anything to anyone.

`order_events` keeps millisecond timestamps: a dispute needs an ordered record of who did
what, and both parties already know it.

Opening a dispute stores one thing in the clear that the order otherwise never does: the
buyer's **reason**, as a row in `reports`. It is written by the buyer knowingly, for the
moderator, and is the only order text a moderator can read — the order's channel stays
encrypted and there is no route that opens it. Evidence, if either side wants to show it, is
exchanged in that channel and described to the moderator in words.

Ratings are published as an average over distinct buyers with the number of buyers beside
it, so a profile discloses "3 buyers" rather than a review timeline; the per-author
calculation happens in SQL over rows that already exist and adds no column.

**A review is published without its author** (point 81). `reviews.author_user_id` exists —
it is what enforces one review per order and one rating per buyer — and no response returns
it. Naming the reviewer would publish what a person bought to everyone who can read the
listing, which is the single fact a marketplace buyer most reasonably expects to stay
between the two parties. What a seller learns about a buyer stays at the minimum the
transaction needs: a username, because the encrypted order chat is opened by name; what a
buyer learns about a seller is what a seller published.

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

Five columns, because "kept for 30 days" answers only half the question: what the data is
*for* is what decides whether it should exist at all, and who can read it is what decides how
bad it is that it does. Live values are in `docs/ENVIRONMENT.md`; the deletion machinery is in
`docs/DELETION.md`.

| Data | Purpose | Retention | Delete condition | Access |
| --- | --- | --- | --- | --- |
| Undelivered envelope | Deliver a message to a device that is offline | `ENVELOPE_TTL_MS` (30 days), less if the sender set a shorter lifetime | The recipient acknowledges it, or it expires | The addressed devices; the operator sees ciphertext |
| Delivered envelope | — | None | Deleted at acknowledgement | Nobody |
| Delivered file (`deliveries`) | Hand one encrypted file to one buyer | `DELIVERY_TTL_MS` (30 days) | The buyer saves it, the order ends, or it expires | The buyer, by order id; the operator sees ciphertext |
| Message attachment (`attachments`) | Hand one encrypted file to a conversation | `DELIVERY_TTL_MS` (30 days) | Anyone holding the id deletes it, or it expires | Whoever holds the id; the key is in the conversation |
| Session | Keep someone signed in | `SESSION_TTL_MS` (30 days), or `SESSION_IDLE_DAYS` (14) unused | Sign-out, expiry, password change, recovery | Its owner; staff have no route to it |
| Rate-limit bucket | Refuse a flood | 24 hours | The sweep | Nobody: it holds a hash and a count |
| One-time prekey | Start a session with forward secrecy | Until claimed | The claim, which deletes it | Public half only, one caller |
| Security event | Show an account its own sign-in history | `SECURITY_EVENT_RETENTION_DAYS` | The sweep | Its owner only, as counts per day |
| Notification | An inbox that describes nothing | `NOTIFICATION_RETENTION_MS` (90 days) | Read, or the sweep | Its owner |
| Account, listings, orders, reviews | Be a marketplace | Until deleted | The owner deletes the account, or moderation removes the listing | The parties; moderation sees the public facts |
| Audit entry | Make a staff action reviewable afterwards | `AUDIT_RETENTION_MS` (1 year) | The sweep | Administrators |
| Search index (`listing_terms`) | Find a listing without scanning the table | Life of the listing | The listing is removed | Public, through search |
| Search *queries* | — | Not stored | — | Nobody |

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
