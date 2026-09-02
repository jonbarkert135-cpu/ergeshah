# Threat model

This document is the contract. Any security claim elsewhere in this repository is only
valid in the terms defined here, and anything not listed as mitigated should be assumed
to be a residual risk.

## What we do *not* claim

- Not anonymous. The platform reduces what the *server* learns; it cannot hide you from
  your ISP, your device, or someone standing behind you.
- Not unbreakable. It is an implementation of well-studied constructions; implementations
  have bugs, and this one has not been externally audited.
- Not free of metadata. Connection timing, message timing and message size *buckets* remain
  observable to the operator and to a network observer.
- Not resistant to a compromised endpoint. Malware on your device reads your messages
  before any encryption happens.
- Not resistant to a malicious *client build*. If the operator serves modified
  JavaScript, that JavaScript can exfiltrate keys. See "Residual risks".

## Assets

| Asset | Where it lives | Consequence if lost |
| --- | --- | --- |
| Message plaintext | Client devices only | Full loss of confidentiality for those messages |
| Identity / prekey private keys | Client vault (encrypted) | Impersonation, decryption of future messages |
| Vault key (from password) | Client memory, never sent | Attacker can decrypt vault backups |
| Session tokens | Client cookie, hash in DB | Account takeover until revoked |
| Social graph (who talks to whom) | Partly inferable server-side | Deanonymisation pressure |
| Marketplace records | Server database | Commercial exposure, correlation |
| Audit log | Server database | Reveals moderator behaviour |

## Attackers and what the design does about them

### Network attacker (passive observer, active MITM, hostile Wi-Fi, ISP)

| Attack | Mitigation | Residual |
| --- | --- | --- |
| Passive interception | TLS 1.3 at the proxy; content is *additionally* end-to-end encrypted | Traffic timing and volume are visible |
| Active MITM on TLS | HSTS (2 years, includeSubDomains), automatic certificate management | A malicious CA plus HSTS bypass on first visit; onion service avoids CAs entirely |
| Downgrade | `upgrade-insecure-requests`, HSTS, no HTTP-only fallback in the app | First-visit downgrade before HSTS is pinned |
| Replay of a captured request | Session cookie + CSRF token + per-message ratchet counters | — |
| Injection into the page | `default-src 'self'` CSP; no inline script; no third-party origin | A compromised server can still change the CSP it sends |

### Server attacker (compromised VPS, malicious operator, stolen backup, leaked database)

| Attack | Mitigation | Residual |
| --- | --- | --- |
| Read stored messages | Server stores ciphertext only; keys never reach it | Server sees the size bucket and the arrival time |
| Crack passwords from a dump | Client-side Argon2id (the work factor that matters), then server-side scrypt over the derived 256-bit half | A weak password is still a weak password |
| Steal sessions from a dump | Only SHA-256 hashes of tokens are stored | A live attacker can steal cookies in transit on a compromised server |
| Reconstruct a user's activity | Coarse (day) timestamps on long-lived rows; no access log; no read receipts | `envelopes.created_at` is millisecond-precise while undelivered |
| Learn who talks to whom | No sender column; sender identity is inside the ciphertext | Timing correlation of send/fetch, and the recipient device is necessarily known |
| Silently substitute keys | Signed prekeys verified by the client; safety numbers for out-of-band comparison | Users who never compare safety numbers will not notice |
| Serve backdoored client code | Same-origin CSP, reproducible build from this repository | **Unmitigated by design.** A web client cannot defend against its own server. This is the single largest residual risk. |

### Application attacker

| Class | Mitigation |
| --- | --- |
| SQL injection | Every query parameterised; no string interpolation of values anywhere |
| XSS | No `innerHTML` in the client; DOM built from text nodes; strict CSP with no inline script |
| CSRF | SameSite=Strict cookies + Origin/Host check + double-submit token |
| SSRF | The server makes no outbound HTTP requests at all; the container is on an internal network with no egress |
| Path traversal | Static assets are read from an explicit allowlist at boot; no path is derived from a request |
| IDOR | Every object lookup is scoped by owner; covered by tests for devices, envelopes, listings, orders and vaults |
| Authentication bypass | Single code path (`authenticate`), opaque tokens, suspended accounts rejected on every request |
| Privilege escalation | Roles checked per route; moderators cannot touch admins; nobody can promote themselves |
| Race conditions | One-time prekey claiming and order transitions run inside transactions |
| Brute force | Token-bucket limits on login, registration, sending and writes |
| User enumeration | Login is constant-work and returns one message for both cases; registration necessarily reveals a taken username (accepted, documented) |
| Request smuggling | Single proxy hop, no request rewriting, Node's own HTTP parser in strict mode |
| Deserialization | JSON only, size-limited, schema-validated field by field |
| Prototype pollution | No recursive merge of user input; validators return primitives |

### Cryptographic attacker

| Attack | Mitigation | Residual |
| --- | --- | --- |
| Stolen device key | Double Ratchet gives post-compromise security: the next DH ratchet step re-keys the session | Messages already on the device are readable |
| Compromise of one message key | Per-message keys derived from a one-way chain | The chain's future keys are safe; that single message is not |
| Nonce reuse | Nonce derived from the unique per-message key, never a counter | — |
| Weak randomness | `randombytes_buf` from libsodium (OS CSPRNG) | Broken OS entropy breaks everything, as always |
| Malicious public keys | Signed prekeys verified before any session opens; sessions refuse to start on a bad signature | Identity keys are trust-on-first-use unless verified out of band |
| Session desynchronisation attack | Decryption ratchets a copy and commits only after authentication | — |
| Harvest now, decrypt later | Documented explicitly: the current handshake is classical X25519 | **Real.** A hybrid PQ handshake is roadmap item PQ-1, not a shipped feature |

### Privacy attacker

| Vector | Status |
| --- | --- |
| IP addresses | Never stored. Used in memory for rate limiting, immediately HMACed with a daily-rotating pepper |
| Access logs | Disabled in the app and in the proxy configuration |
| Analytics, pixels, session replay | None. The CSP forbids any third-party origin, so a future mistake fails loudly |
| Cookies | Two: an opaque session token and a CSRF token. No tracking identifiers |
| Local storage | One entry: the encrypted vault |
| Fonts / CDN | System fonts only; every asset self-hosted |
| Referrers | `Referrer-Policy: no-referrer` plus a meta tag; the proxy strips `Referer` upstream |
| Error logs | Method, route and error message only — no bodies, no identifiers |
| Backups | Contain no plaintext messages by construction; still encrypt them (see DEPLOYMENT.md) |
| Message timing/size | Sizes are padded to buckets (64/256/1024/4096·n) and headers are encrypted, so ratchet keys, counters and exact lengths are hidden. **Timing, count and bucket remain visible to the operator** — no cover traffic or delayed delivery (roadmap MD-2) |
| Delivery addresses (physical orders) | Never sent to the server: encrypted to the seller in the order channel, kept in the seller's vault. The operator sees an order, not where it is going |
| Delivered files | Stored as ciphertext only, padded to 4 KB, with no filename or type; the key never reaches the server. **The operator learns that an order was delivered, the padded size, and the upload and pickup times**, and can delete or withhold a blob (denial of service, not disclosure) |
| Client network location | Hidden from the operator only for users who arrive over the onion service (`docs/DEPLOYMENT.md`). On the clearnet the reverse proxy sees an address, uses it as rate-limit input, and does not store it |
| Browser fingerprinting | Not performed by us; not preventable by us |

## Hostile uploads (point 49)

Every byte a user uploads is treated as hostile. What makes that tractable here is that there
is exactly one upload path — an order delivery — and what it carries is ciphertext the server
cannot open: there is no image to transcode, no archive to expand, no document to render, and
no declared type or filename to believe.

| Vector | What stops it |
| --- | --- |
| MIME spoofing | The API accepts no content type. `Content-Type` on the request is `application/json`, and the payload is a base64url string; a body carrying `mimeType`/`contentType` is refused with `unexpected_field` rather than ignored |
| Extension spoofing | The server stores no filename. The name a buyer sees travels inside the encrypted channel and is sanitised by `safeFileName()` before it is used — including the `U+202E` bidi trick that makes `annex‮exe.pdf` read as a PDF |
| Oversized files | `MAX_DELIVERY_BYTES` is checked in **decoded bytes** (`asBase64Url`), Fastify's `bodyLimit` refuses the request before the handler runs, and the client caps the plaintext at `MAX_FILE_BYTES` |
| Malicious SVG | Stored bytes are never served as a document: the delivery endpoint answers JSON with `X-Content-Type-Options: nosniff`, no `Content-Disposition` and no filename. The client saves the decrypted bytes as `application/octet-stream`, never navigates to the blob URL, and never builds markup from a string (lint rule `html-from-string`) |
| Path traversal | No filesystem path in this server is derived from a request. Static assets are read from an explicit directory listing at boot and registered as literal routes; blobs live in the database, keyed by a random id |
| Archive bombs | Nothing is decompressed server-side, ever — the server cannot even tell an archive from noise. A buyer who unpacks what they bought is doing so in their own tools, which is the same trust decision as buying the file |
| Executable uploads | Storage is a database column; there is no directory an interpreter or web server could reach, and nothing is marked executable. A seller *may* legitimately sell software, so the file is not rejected for looking like a binary — it is delivered as an octet stream the buyer chose to receive |
| Content sniffing | `nosniff` on every response, `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, and no route that echoes stored bytes with a caller-influenced type |

Residual, stated plainly: the operator still learns that a delivery happened, its padded size
and its timing, and the *buyer* still receives bytes chosen by the seller. Nothing here can
tell them the file is safe to open; end-to-end encryption and malware scanning are mutually
exclusive, and this project chose the encryption. `test/uploads.test.ts` covers the table.

## Residual risks, stated plainly

1. **Server-served client code, and a closed source.** The operator can ship a malicious
   bundle to a specific user, and — since the source is proprietary — nobody outside the
   project can build the client to compare against. What remains: the build is reproducible
   and the operator can check a deployment against the source
   (`npm run audit:deployment`); `index.html` pins the bundle with subresource integrity;
   the served digest is published at `/build.txt`, so users can compare it with each other
   and detect a bundle served to one person only. None of that is a substitute for reading
   the source, and this document will not pretend otherwise. **Every security property
   described here is a claim about code you cannot read.**
2. **Metadata.** Who is online, when, how often, and roughly how large their messages
   are (the bucket, not the byte count).
3. **Classical-only handshake.** Recorded traffic today may be decryptable by a future
   quantum adversary.
4. **Unverified identities.** A first contact is still trust-on-first-use: the key comes
   from the server's directory. Comparing the safety number (text or scannable code, per
   device) turns a substituted key into a *detectable* attack, and a later substitution
   raises a warning in the conversation — but nothing forces anyone to look, and an
   unverified conversation gives the operator the same opportunity it always did.
5. **No external audit, and no open source to substitute for one.** The cryptography
   follows published specifications and is property-tested, but it has been reviewed by
   nobody outside this project — and with the source closed, the usual fallback (anyone
   curious can read it) is gone. A paid review under NDA is the only remaining path.
6. **Availability.** A single VPS is a single point of failure, deliberately.
7. **Reputation can be bought at the price of accounts.** A review needs a completed order,
   one account counts once per seller however often it buys, and the number of distinct
   buyers is shown next to every average — so the cheap manipulation (one puppet buying on
   repeat) is worth nothing. Ten puppets still work. Stopping them needs identity or
   payment history, and this project collects neither; the counter-signal a reader has is
   the buyer count, the completed-order count and the seller's dispute count, all public.

If any of these is unacceptable for your use case, the honest answer is that this
platform is not yet suitable for it.

## What an attacker gets, per starting point

Scenarios rather than assurances, so each line can be checked against the code.

| They hold | They can | They cannot |
| --- | --- | --- |
| A username | Learn that the name is taken — registration says so; login and recovery do not | Anything else |
| Username + password | Sign in, read that device's history, send as the user | Open the recovery-wrapped copy of the master key, produce a recovery signature, or decrypt messages delivered only to another device |
| A database dump | See usernames, coarse days, public keys, wrapped blobs, ciphertext | Open a vault, read a message, derive a phrase, or replay a session — tokens are stored hashed |
| A stolen session cookie | Act as the user until the session expires or is revoked, including reading envelopes the server still holds | Open the vault (the master key is not on the server), change the password (needs the current one), or complete a recovery |
| A PGP public key | Nothing; it is public | Impersonate the user — only the private half signs |
| Username + password, on an account with PGP | Ask for a challenge, and stop there | Sign it, so no session is ever created |
| A PGP private key alone | Sign challenges | Get in without the password as well |
| A recovery phrase | Take the account (and clear the PGP factor): rotate the password, sign in, open the backup, read history | Nothing more. This is the strongest secret in the system, which is why the interface says so and why the recovery copy of the master key is a choice |
| A compromised VPS | Everything the server can do: serve modified client code, watch traffic timing and sizes, read the database | Read past messages (forward secrecy, no plaintext at rest), derive keys, or recover a phrase |
| A compromised browser | Everything that device can do while it is unlocked | Read another device's history, or produce a recovery signature without the phrase |

The last two rows are the ones to reread. A hostile server serving modified JavaScript is
the residual risk this architecture cannot close on its own; the answer is reproducible
builds with published hashes (roadmap CRY-2), not a promise.
