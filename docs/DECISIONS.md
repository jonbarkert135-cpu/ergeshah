# Architecture decision records

Each entry: the decision, the alternatives considered, and the trade-off accepted.

## ADR-0001 — Node 22 + TypeScript, executed without a build step on the server

**Decision.** The server runs `.ts` sources directly via Node's native type stripping;
only the client is bundled (esbuild).

**Alternatives.** Go or Rust (better memory safety story, worse code sharing with the
browser); a compiled TypeScript build (an extra artefact that can drift from source).

**Trade-off.** Sharing one implementation of the protocol between client and server
eliminates a whole class of "the two sides disagree" bugs, and the deployed source is
the source you can read. The cost is Node's performance ceiling and an experimental flag.

## ADR-0002 — AGPL-3.0-only

**Decision.** License the project under AGPL-3.0-only.

**Alternatives.** MIT/Apache-2.0 (maximally permissive); GPL-3.0 (does not reach network
use).

**Trade-off.** A privacy platform whose users cannot verify what the operator runs is a
promise, not a guarantee. The AGPL at least obliges a modifying operator to publish their
version. It also keeps the door open to adopting libsignal (AGPL-3.0) later, which a
permissive license would not. The cost: some commercial adopters will not touch AGPL
code.

## ADR-0003 — libsodium for every primitive; the protocol composed from published specs

**Decision.** Use `libsodium-wrappers-sumo` in both client and server. Implement X3DH and
the Double Ratchet as *compositions* of those primitives, following the published
specifications, with RFC test vectors for HKDF and property tests for the ratchet.

**Alternatives.** `@privacyresearch/libsignal-protocol-typescript` (a port of Signal's
older JS library; unmaintained, GPL-3.0); `libsignal-client` (Signal's Rust
implementation, AGPL, Node-only native bindings — cannot run in the browser, so a web
client cannot use it for its half of the protocol); WebCrypto only (no X25519 in older
browsers, no Argon2, no XChaCha20).

**Trade-off.** This is the uncomfortable decision in the project. The rule "never write
your own crypto" is respected at the primitive level, but the protocol composition is
ours, and composition bugs are real. Mitigations: no primitive is hand-written; the
composition follows published specifications closely; every property is tested; the
deviations are documented in `docs/CRYPTO.md`. If a maintained, audited,
browser-compatible Signal Protocol library appears, replacing `src/shared/crypto` with it
is the intended path — the module boundary exists for that.

## ADR-0004 — Version pin: `libsodium-wrappers-sumo` 0.7.15, not 0.7.16

**Decision.** Pin exactly 0.7.15.

**Reason.** 0.7.16 ships a broken ESM entry point (`dist/modules-sumo-esm` imports a file
that is not published), so `import` fails in Node and in bundlers. Pinned, not ranged, so
an install can never silently pick up the broken build.

## ADR-0005 — SQLite by default, PostgreSQL optional, behind a 40-line interface

**Decision.** One `Db` interface, two drivers, portable SQL with `?` placeholders that the
Postgres driver rewrites.

**Alternatives.** An ORM (Prisma/Drizzle: migrations, types, and a large dependency plus
generated SQL you have to audit); PostgreSQL only (an extra service on every small
deployment).

**Trade-off.** We give up ORM conveniences and take on placeholder rewriting; we gain a
deployment that runs on one container with no database service, and SQL we can read.

## ADR-0006 — Password split client-side (Argon2id → auth secret ‖ vault key)

**Decision.** The browser stretches the password once with Argon2id and derives two
independent halves; only one is ever sent, and the server hashes it again.

**Alternatives.** Send the password over TLS and hash server-side (simplest, but a
malicious server can then derive the vault key); OPAQUE-style PAKE (stronger, but no
audited browser implementation we are willing to depend on — noted as roadmap AUTH-1).

**Trade-off.** The salt must be derivable without asking the server, so it is a hash of
the username: a deterministic, non-secret salt. In exchange, a hostile server never sees
password material that would unlock a vault backup.

## ADR-0007 — No framework on the client, no third-party runtime dependency in the browser

**Decision.** Plain TypeScript, DOM built from text nodes, one CSS file, system fonts.

**Trade-off.** More verbose view code. In return the CSP can be `default-src 'self'` with
no exceptions, the bundle contains nothing we did not write except libsodium, and there is
no framework CVE surface.

## ADR-0008 — Rate limiting without storing addresses

**Decision.** Bucket key = `HMAC(pepper ‖ unix-day, address ‖ scope)`; the address exists
only in memory for the duration of the request.

**Trade-off.** Buckets reset daily and NAT'd users share a bucket. Acceptable: the
alternative is an access log with extra steps.

## ADR-0009 — Payments are out of scope for now

**Decision.** Orders track state and price; no payment processor, no wallet, no escrow.

**Reason.** Every payment integration introduces a third party that learns who bought
what, and most demand identity verification — which would undo the point of the project.
When it lands it must be optional and isolated (roadmap PAY-1).

## ADR-0010 — Dependency budget

Production dependencies, and why each one is justified:

| Package | Why | License |
| --- | --- | --- |
| `fastify` | HTTP server with explicit, opt-in behaviour | MIT |
| `libsodium-wrappers-sumo` | Audited primitives, identical in browser and Node | ISC |
| `pg` | Optional PostgreSQL driver | MIT |

Everything else — cookies, CSRF, validation, rate limiting, static file serving, the
migration runner — is a few dozen lines in `src/server/lib`, because each of those as a
dependency would be more attack surface than code.

## ADR-0011 — Encrypt ratchet headers and pad plaintexts; break the wire format to do it

**Status:** accepted (2026-09-02)

**Context.** The first release sent the ratchet header in the clear: ratchet public key,
previous-chain length, message counter. That is enough for the server operator to group
envelopes into sessions, count each conversation's turns, and watch DH ratchet steps —
about as much as a conversation transcript's shape. Ciphertext length also tracked
plaintext length byte for byte, which distinguishes "ok" from a pasted document.

**Decision.** Implement the Double Ratchet specification's header-encryption variant, with
the two initial header keys derived from the X3DH secret under distinct HKDF labels rather
than added as handshake fields, and pad plaintexts to buckets (64, 256, 1024, then
multiples of 4096) with ISO/IEC 7816-4 padding inside the AEAD. The wire format becomes
version 2 — two opaque blobs — and version 1 is **refused**, not supported: the platform
has no deployment yet, and a client that still accepts plaintext headers is a client an
attacker can ask to downgrade. The local vault key changes with it, so stale browser
state is ignored instead of half-read.

**Consequences.** Positive: a server holding every envelope can no longer link them into
sessions or read exact lengths, and the same code path now hides both. Negative: bucketing
costs bandwidth (a one-word message occupies 64 bytes of plaintext), skipped message keys
must store their header key, and out-of-order receipt now needs trial decryption over the
distinct stored header keys — bounded by the skipped-key limits, so still cheap. Timing
and message volume remain visible; padding was never going to fix those.

## ADR-0012 — Hash the auth secret with standard-library scrypt, not a native Argon2 dependency

**Status:** accepted (2026-09-02)

**Context.** The server stored `Argon2id(authSecret)` using `@node-rs/argon2`, a native
dependency whose only job was that one call. The value being hashed is not a password: it
is 32 bytes the client already derived from the password with Argon2id. The work factor
that resists password guessing therefore lives in the browser, and this hash is defence in
depth for a leaked `users` table. Meanwhile every dependency here has to justify itself,
and libsodium's Argon2id — already present — is synchronous WASM, so using it would block
the event loop on every login.

**Decision.** Use `crypto.scrypt` from Node's standard library (RFC 7914, N=2¹⁵, r=8,
p=1): memory-hard, asynchronous, native, audited, and already installed by definition.
Store the parameters in the hash string so they can be raised later. The client-side
Argon2id is untouched.

**Consequences.** One fewer dependency and one fewer native binary in the runtime image.
scrypt is a weaker choice than Argon2id for hashing a low-entropy secret — irrelevant for
a 256-bit input, and stated here so the trade-off is not rediscovered as a finding. If the
client KDF is ever weakened, this decision must be revisited first. Existing hashes are
not portable across the change; there was no deployment, so no migration path exists.

## ADR-0013 — The project is called Symvolon; the protocol labels keep their old strings

**Status:** accepted (2026-09-02)

**Context.** The repository was bootstrapped under a working title. A product needs a name
that means something and that nobody else is using in this space. *Symbolon* (σύμβολον) is
the ancient token broken in two, each half held by one party, matched later as proof that
both belong to the same agreement — which is precisely what X3DH does with key halves, and
precisely what two strangers in a marketplace need. Checked before adopting it: free on
npm and GitHub, no software product using it, no live site on the obvious domains.

**Decision.** Product, documentation, UI and package are named Symvolon. The HKDF and AEAD
context strings (`ergeshah-x3dh-v1`, `ergeshah-root-he-v1`, and the rest) are **not**
renamed. They are opaque domain separators: their only job is to be distinct from each
other and stable over time. Renaming them would invalidate every derived key and every
sealed vault, and would buy exactly nothing — the laziest correct change is no change.

**Consequences.** Anyone reading `src/shared/crypto` will find the old name in the labels;
a comment there and this ADR explain why. If the protocol is ever versioned for real
(v2 labels), that is the moment to switch the prefix, together with a migration.

## ADR-0014 — A random master key, wrapped once per unlocking route

**Status:** accepted (2026-09-02)

**Context.** The vault was encrypted directly with a password-derived key. That made a
password change a full re-encryption, and it made recovery impossible in principle: a
phrase could at best restore *access* to an account whose message keys stayed sealed under
a forgotten password. The security extension asks for cryptographic recovery, strict key
separation, and a server that never holds recovery secrets.

**Decision.** The vault is sealed with a master key: 32 random bytes, never derived from
anything typed. The master key exists only as wrapped blobs, one per route that may unlock
it — the password wrap key, plus an optional recovery wrap key derived from the phrase.
Adding a route wraps 32 bytes; changing a password rewraps 32 bytes; the vault is untouched
by both. Recovery phrases use the BIP-39 *encoding* with a vendored wordlist and about
fifty lines of our own, cross-checked against `@scure/bip39` in the tests (which stays a
dev dependency), but not BIP-39's PBKDF2 seed derivation: the entropy goes into Argon2id at
the same cost as the password path.

**Consequences.** Recovery restores conversations, not just login, and a password change no
longer invalidates a phrase. The costs: one more indirection to reason about, a backup
format carrying two envelopes, and one honest trade-off — the recovery copy makes the
phrase the most valuable secret in the system, so it is offered as a choice with the
consequence spelled out rather than switched on silently. Declining it means a forgotten
password loses the history for good.

## ADR-0015 — `openpgp` for verifying signatures, server-side only

**Status:** accepted (2026-09-02)

**Context.** PGP authentication needs one operation: check a detached signature over a
challenge against a public key. Doing that without a library means parsing the OpenPGP
packet format — armour, key packets, signature packets, hashed subpackets, algorithm
identifiers — a format with decades of edge cases and a long CVE history, in code that
decides whether someone gets in. That is precisely the code this project's rules say not to
write by hand.

**Decision.** Add `openpgp` (6.x) as a production dependency, imported only from
`src/server/lib/pgp.ts`. It has no dependencies of its own, is maintained by ProtonMail,
has been audited by Cure53, and is the reference JavaScript implementation. It is LGPL-3.0+,
which combines cleanly into this AGPL-3.0 project; we use it unmodified, so the copyleft
obligation on the library itself is satisfied by keeping it as an untouched dependency.
Nothing from it reaches the browser: the client only moves armoured text around, and the
production bundle is checked for the string.

**Consequences.** Production dependencies go from three to four, and roughly 17 MB of
`node_modules` on the server. In exchange, the entire OpenPGP surface — including all the
ways a hostile key or signature can be malformed — is handled by an implementation that is
audited and maintained, and our own code stays at about a hundred lines of policy: reject
private keys, require a signing-capable key, verify or return false.

## ADR-0016 — Audits as CI checks, written in the repository, not bought

**Status:** accepted (2026-09-02)

**Context.** Two of this project's promises are invisible to the test suite. "The client
contacts no third party" is a property of a *build artifact*, and "no credentials are
committed" is a property of *history*; both are broken by a single hurried commit, and
neither fails a unit test. The usual answers are a paid scanner or a policy document. A
policy document does nothing, and the project's budget is a VPS.

**Decision.** Two greps with a threat model attached, in `scripts/audit.mjs`: `audit:bundle`
builds the production client and rejects remote URLs, source-map references, `sendBeacon`
and the server-only `openpgp` import; `audit:secrets` scans every tracked file for key
material, tokens and credential literals. Both run in CI, both add no dependency, and both
have tests that fail if the rules stop matching. `docs/AUDIT.md` documents them, adds the
manual checks a reader can perform for free, and lists what none of it proves.

The workflow calls them via `--if-present`, which is why they could be added without the
human step of re-copying `.github/workflows/ci.yml` (see `AGENTS.md`).

**Consequences.** False positives are possible; the escape hatch is an `audit:allow`
comment on the line, which is visible in review, rather than a widened rule. Fixture
passwords under `test/` are exempt from the credential heuristic, key material is not.
The checks stop honest mistakes, not a hostile committer — that is stated in the document
instead of being implied away, and the real mitigation for the served-bundle risk remains
reproducible builds (roadmap OPS-1).

## ADR-0017 — Digital delivery: a blind blob plus a key sent over the ratchet

**Status:** accepted (2026-09-02)

**Context.** A marketplace that sells digital goods has to move a file from seller to
buyer. The default answers all leak: object storage means a third party holds the artefact
and sees who fetches it; an email attachment leaves plaintext on two mail providers; and
"upload the file, we'll keep it safe" is exactly the promise this project refuses to make.
The file also needs a key, and inventing a second key-agreement protocol for it would
double the cryptographic surface to review.

**Decision.** The seller's browser encrypts the file with a fresh random key
(XChaCha20-Poly1305, padded to 4 KB with the message padding scheme, the order id as
associated data), uploads only the ciphertext, and sends the key to the buyer as an
ordinary Double Ratchet message in the order's existing encrypted channel. The server row
(`deliveries`) is id, order id, ciphertext, created, expires — no uploader, no filename, no
media type, no hash: the first is implied by the order, the rest are content.

Uploading *is* the status transition to `delivered`, so `POST /status {delivered}` was
removed; the blob is deleted when the buyer acknowledges it, when the order reaches a
terminal status, or after 30 days.

**Alternatives.** Per-file X3DH handshake (a second protocol for no gain — the channel
already has forward secrecy and authentication). Server-side encryption with a key held by
the operator (defeats the point). Streaming/chunked upload with resumption (more code and
state for a 3 MB cap; when large files matter, that is a separate decision). A SHA-256 of
the plaintext alongside the key (the AEAD tag already authenticates, and the key arrives
over an authenticated channel, so the hash would prove nothing extra).

**Consequences.** A delivery is one buffer in memory on both sides, which is why the cap
is 3 MB of plaintext and the body limit is derived from it. Base64url in a TEXT column
costs a third more storage than bytes would, and keeps the schema identical on SQLite and
PostgreSQL — the choice the whole schema already makes. The operator still learns that an
order was delivered, the padded size and the timings, and can withhold a blob; that is
denial of service, not disclosure, and it is written down in `docs/THREAT_MODEL.md`. A
seller can still upload the wrong file: delivery is not escrow (MKT-1).
