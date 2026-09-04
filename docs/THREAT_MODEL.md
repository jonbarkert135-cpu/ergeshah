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
| CSRF | SameSite=Strict cookies + Origin/Host check + double-submit token; on HTTPS both cookies carry the `__Host-` prefix so a sibling host cannot plant or fix them (SEC-2026-014) |
| SSRF | The server makes no outbound HTTP requests at all, and the application container is on an internal Docker network with no gateway, so there is nowhere for one to go. This was stated here before it was true — the container used to sit on the public-facing network as well; `test/deployment.test.ts` now fails if it does again (docs/NETWORK.md) |
| Path traversal | Static assets are read from an explicit allowlist at boot; no path is derived from a request |
| IDOR | Every object lookup is scoped by owner; covered by tests for devices, envelopes, listings, orders and vaults |
| Authentication bypass | Single code path (`authenticate`), opaque tokens, suspended accounts rejected on every request |
| Privilege escalation | Roles checked per route; moderators cannot touch admins; nobody can promote themselves |
| Race conditions | One-time prekey claiming and order transitions run inside transactions |
| Brute force | Token-bucket limits on login, registration, sending and writes |
| One-time prekey exhaustion | Claiming a bundle has its own tight bucket (`key_bundle`, ADR-0035), so an account cannot drain someone's prekeys the way an ordinary read allowance would let it. Residual: an attacker with many accounts can still exhaust them, and sessions then open against the signed prekey alone — authenticated, but without the extra forward secrecy of a one-time key |
| Un-revoking a stolen device | Revocation is final: an identity key that was revoked is refused on re-publication (`409 device_revoked`), so whoever holds the device's private key cannot put it back in the directory. Residual: revoking a device does **not** end sessions signed in on it — the user must also sign out everywhere, which the account view and `INCIDENT_RESPONSE.md` §2 both say |
| User enumeration | Login is constant-work and returns one message for both cases. A recovery challenge is issued for every username and *writes a row either way* — a decoy with a null `user_id` — so neither the answer, the timing nor the table growth distinguishes an account that exists. Every failure of `recovery/complete` returns one message. A private object a caller is not party to answers 404, exactly as a made-up id does. Registration necessarily reveals a taken username (accepted, documented: a username is how you are addressed here) |
| Mass automation: bulk registration, credential stuffing, scraping | A proof of work on the three unauthenticated account endpoints (ADR-0039), plus per-operation buckets, plus a bucket counted against the *targeted username* rather than the caller's address. Residual: proof of work is a cost, not a wall — a determined attacker with CPU still gets through it, more slowly and more expensively. It is deliberately not a CAPTCHA or a phone number, because those defend the service by identifying the user |
| Account lockout as a denial of service | The per-username bucket is sized to stop bulk guessing, not to lock a name: 50 attempts of burst and 10 a minute sustained. Residual: an attacker who spends exactly that allowance can slow a specific user's sign-in attempts. Accepted — the alternative is a tight bucket that hands anyone who knows a username the ability to lock its owner out |
| Session theft (a stolen cookie) | Tokens are opaque, hashed at rest, `HttpOnly` + `SameSite=Strict`, bounded by an absolute expiry *and* an idle expiry, and rotated daily (ADR-0038) so a captured cookie stops working on its own. The account can list and revoke sessions, and "sign out everywhere" ends all of them. Residual: within a day, a stolen cookie is a valid session, and rotation is not theft *detection* — the user is not told that a second device was using it |
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
| Typing, read receipts, presence | No server state exists for any of them: no presence table, no read column, no route that answers "is she online". Typing and read receipts are ordinary encrypted messages between two clients, off by default, and indistinguishable to the server from a sentence. **Residual: an envelope is still an envelope** — turning typing indicators on multiplies how often the operator sees a device send something while its owner composes (`docs/METADATA.md`) |
| Push notifications | None. No device token, no third-party push service, no service worker; the client polls and the inbox says only "something arrived". Adding push would hand a company outside this system a per-device timing feed, which is why the requirements for ever doing so are written down before the feature is wanted |
| Message search | Client-side only, over what the device has already decrypted. There is no server-side index of message content and no route that could build one (point 79). Residual: search sees what *this* device holds, and nothing that has already disappeared |
| Attachments | Encrypted in the browser before upload, stored as a blob with no sender, recipient, filename, type or plaintext length, and opened with a key that never reaches the server. **Residual: the operator sees a blob appear, its padded size, and when it was fetched**, and can withhold or delete it (denial of service, not disclosure). An attachment also outlives the conversation that carried it, by up to `DELIVERY_TTL_MS`, because the table has no owner to cascade from |
| Marketplace purchases | Reviews are published without an author, so reading a listing does not tell you who bought it. The parties still know each other's usernames — the encrypted order chat is opened by name — and the operator still sees that an order exists, between whom, and for how much |
| Delivery addresses (physical orders) | Never sent to the server: encrypted to the seller in the order channel, kept in the seller's vault. The operator sees an order, not where it is going |
| Delivered files | Stored as ciphertext only, padded to 4 KB, with no filename or type; the key never reaches the server. **The operator learns that an order was delivered, the padded size, and the upload and pickup times**, and can delete or withhold a blob (denial of service, not disclosure) |
| Client network location | Hidden from the operator only for users who arrive over the onion service (`docs/DEPLOYMENT.md`). On the clearnet the reverse proxy sees an address, uses it as rate-limit input, and does not store it |
| Browser fingerprinting | Not performed by us; not preventable by us |
| Recovery-challenge timing | `POST /api/auth/recovery/challenge` answers every username identically, but it writes a row only when the account exists *and* has recovery configured. The difference is a few hundred microseconds of database work — a timing oracle an attacker must average many samples to read, and one the rate limit makes slow. Not closed: doing so needs a nullable `user_id` on `auth_challenges`. Recorded as R-10 in `SECURITY_REVIEW.md` |

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

### Malware scanning, and why there is none (point 25)

The brief asks for *optional local* scanning where the deployment allows it, and forbids making
a scanning SaaS mandatory. Here the answer is stronger than "optional": server-side scanning is
impossible by construction, and no version of it is planned.

- **The server holds ciphertext.** A scanner — self-hosted ClamAV included — needs the
  plaintext. Giving it the plaintext means the server can read the file, which is the one thing
  this architecture exists to prevent. An operator who wants scanning has to break end-to-end
  encryption first, and this project will not ship the switch that does it.
- **No external scanning service is used, mandatory or otherwise.** No file, no hash and no
  fragment of a file leaves this deployment (`docs/NETWORK.md` §Every external request). A hash
  lookup would be a privacy leak with a scanner's reputation: it tells a third party which files
  pass through this platform.
- **So no protection is claimed.** Nothing in the product, the documentation or the interface
  says an attachment or a delivery has been checked, because none of them has been. What the
  product does instead is refuse to make the file *easier* to run: the bytes are never served as
  a document, never opened in the page, and always saved as `application/octet-stream`, and the
  screen says the buyer is receiving bytes chosen by the seller.
- **The scan that is actually available is the recipient's own.** A file saved to disk is
  scanned by whatever the recipient's operating system runs, in the place where the plaintext
  legitimately exists. That is local scanning, by the only party entitled to do it.

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
2. **Metadata.** When a device connects, how often, and roughly how large its messages are
   (the bucket, not the byte count). Not *who is online* — there is no presence anywhere in
   this system — but a server that receives requests necessarily knows when it receives
   them, and no feature here hides that.
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
| A stolen session **and** the password, on an account with PGP | Everything that session could already do | Replace the PGP key or turn the factor off: both need a signature from the key on the account (ADR-0088) |
| A PGP private key alone | Sign challenges | Get in without the password as well |
| A recovery phrase | Take the account (and clear the PGP factor), which also ends every session, challenge and device code: rotate the password, sign in, open the backup, read history | Nothing more. This is the strongest secret in the system, which is why the interface says so and why the recovery copy of the master key is a choice |
| A compromised VPS | Everything the server can do: serve modified client code, watch traffic timing and sizes, read the database | Read past messages (forward secrecy, no plaintext at rest), derive keys, or recover a phrase |
| A compromised browser | Everything that device can do while it is unlocked | Read another device's history, or produce a recovery signature without the phrase |

The last two rows are the ones to reread. A hostile server serving modified JavaScript is
the residual risk this architecture cannot close on its own; the answer is reproducible
builds with published hashes (roadmap CRY-2), not a promise.

## If it leaks: seven scenarios, four questions (points 56, 57)

The table above is per credential. This one is per *component*, and it asks the four questions
the brief asks: what is exposed, what remains protected, what can be revoked, what can be
recovered. Read the "remains protected" column as *by design*, not *guaranteed* — every row
depends on the code doing what this repository says it does.

| Leak | Exposed | Remains protected | Revocable | Recoverable |
| --- | --- | --- | --- | --- |
| **Database** | Usernames, coarse days, public keys, wrapped vaults, hashed session tokens, the marketplace record, balances and the ledger, all blob ciphertext | Message and file plaintext (no key on the server), passwords (scrypt over a client-side Argon2id output), recovery phrases, vault contents | Every session and pending challenge (`scripts/incident.mjs`); the rate-limit pepper; the payout worker's token | The data itself, from the last encrypted backup — up to 35 days of history (`docs/BACKUPS.md`) |
| **Storage** | The same blob ciphertext, because blobs *are* database rows here — there is no object store, so a storage leak is a database leak and this project does not pretend the two tiers are separate | Same as above: every blob is client-encrypted under a one-time key that never reached the server | Nothing to revoke: the bytes are unopenable without keys held by the two parties | Blobs expire in 30 days anyway; what is lost is what was in flight |
| **Backup** | One encrypted snapshot per run. Opened only with the backup key, which the running service cannot read | Everything, while the key is elsewhere. With the key: the same exposure as a database leak, offline and at leisure | The backup key (rotate, re-encrypt the current set, destroy the old copies — see `docs/BACKUPS.md` §Key lifecycle) | The service, in full: `npm run backup:restore` and `npm run backup:drill` |
| **Cache** | Nothing. There is no cache tier — no Redis, no memcached, no shared session store. The only cached values are two numbers in this process's memory (free space, blob count) | Everything, trivially | — | — |
| **Session** | That account's history on the server, and the ability to act as them until it expires | The vault (the master key is not on the server), the password (a change needs the current one), recovery, and the PGP factor (ADR-0088) | The session, from any other session, or all of them at once; a password change or recovery ends every session, challenge and device code (ADR-0089) | Nothing is lost |
| **VPS** | Everything the server can do: serve modified client code, watch timing and volume, read the database, read this deployment's secrets | Past message plaintext (forward secrecy, nothing at rest), vaults, phrases, the *payout* spend key (another host), the backup key (off the machine) | All sessions, the pepper, the worker token, TLS keys, the onion key — the order is in `docs/INCIDENT_RESPONSE.md` §Emergency rotation | The service from backup, on a rebuilt host. Not the users' trust in the client bundle: that is CRY-2 |
| **One account** | That account's conversations *from its own device*, its orders, its balance | Every other account; a seller role does not become a moderator role, and a moderator role does not become an administrator (`test/authorization.test.ts`) | The account (suspension), its sessions, its role | The counterparties' own copies; nothing else is affected |

### Blast radius, and where it is honestly wide (point 57)

Two of the three separations the brief asks for hold, and the third does not:

- **Compromised storage does not give database admin** — false here, and stated rather than
  implied: blobs live in the database, so the storage and database blast radius are the same
  one. What limits it is that every blob is ciphertext the server cannot open. Splitting them
  would mean an object store, a second set of credentials and a second thing to back up, for a
  gain of nothing while the bytes are already unopenable.
- **Compromised cache does not give private file access** — trivially true: there is no cache.
- **A compromised marketplace role does not give an admin role** — true, and tested: roles are
  read from the database on every request, a refusal is audited, and no route promotes anyone
  without an administrator (`src/server/app.ts`, `test/authorization.test.ts`).

Credentials are separate per purpose, so one leak is not all of them: the database URL, the
rate-limit pepper, the payout worker's bearer token, the wallet password and the backup key are
five different secrets, from five different places, rotated independently
(`docs/ENVIRONMENT.md`, `docs/INCIDENT_RESPONSE.md`). There is no universal application secret,
and no key that opens more than its own domain (point 71, `docs/CRYPTO.md` §Key separation).

## Declined by request (mechanisms proposed but not built)

This section is a record, not a plan. Each row was proposed to be added to Symvolon and
was **declined** — either because the contract above forbids it, or because it is a
host-level anti-virus/EDR idea that does not fit a server application and would only be
decoration (the rule in `docs/MECHANISMS.md`: a mechanism that cannot name its threat is
ornament). It is written here, at the end of the contract, so the boundary is on the record
and the same requests are not silently reconsidered later.

| Mechanism (as requested) | What it is | Why it was declined | Verdict |
| --- | --- | --- | --- |
| `RansomwareProtection` (VanHelsing RaaS pattern) | Host file-integrity plus process/network monitoring that watches the VPS for ransomware behaviour. | Host AV/EDR. The architecture forbids background process/filesystem monitoring inside the app; ransomware on the operator's VPS is not in this threat model. Names no threat this app defends → ornament. | отвергнуто |
| `StealerProtection` (LummaC2 / QBit pattern) | Guarding browser and wallet paths (`%LOCALAPPDATA%\Chrome`, `fs.watch('/')`) against info-stealers. | Meaningless on a server: user keys live in the user's browser, the server never sees those paths, and the spend key is not on the server. Not applicable to this topology. | отвергнуто |
| Signature blocking (LockBit 3.0 builder pattern) | Signature-based anti-virus that blocks known malware binaries on the host. | Signature AV on the server is decoration; running `lockbit.exe` on the Node host is not a threat this application is positioned to answer. | отвергнуто |
| Cracked-builder detection (RAMP pattern) | Detecting/blocking cracked pentest tooling (e.g. Cobalt Strike) by signature on the host. | Same host-IDS/AV class as above; not the app's threat surface. | отвергнуто |
| Double-blockchain unlinkability (FreeMarketOne pattern) | A second ledger whose purpose is to decouple a participant from their own transactions so trades cannot be attributed to them. | Its stated goal — make marketplace participants untraceable / unlinkable to their deals — contradicts the contract above ("Not anonymous"). This is participant-untraceability infrastructure, not privacy. Architecturally also a cargo-cult: there is no blockchain here (one VPS, SQLite/Postgres). | отвергнуто |
| Proof-of-burn identity (OpenBazaar pattern) | Burn-based pseudonymous identities intended to sever a trader's identity from their trading history. | Same goal and same reason as the row above: participant untraceability, which the contract explicitly disclaims. | отвергнуто |

Escrow, dispute-resolution, seller accountability (KYC), audit trails, and every mechanism
that reduces what the *server* learns (E2EE, data minimisation, encryption at rest, sealed
sender, no access logs, IDOR defence) are **in scope** and are built or on the roadmap; they
are not part of this list.
