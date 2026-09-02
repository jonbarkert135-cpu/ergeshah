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

## ADR-0002 — AGPL-3.0-only *(superseded by ADR-0022)*

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
which combines with a proprietary project on two conditions — use it unmodified, keep it
replaceable — both of which we meet by leaving it an ordinary runtime dependency and never
distributing a bundled artefact (see `THIRD_PARTY.md` and ADR-0022).
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

## ADR-0018 — Reproducible client build, verified against the deployment

**Status:** accepted (2026-09-02)

**Context.** The largest residual risk in `docs/THREAT_MODEL.md` is that the operator
serves the browser a bundle that does not match this source. Every claim in this
repository about client-side encryption depends on that not happening, and until now the
only answer was "read the source" — which nobody can do against a minified megabyte they
were served ten minutes ago.

**Decision.** Make the build reproducible and make the comparison one command.
`scripts/build-client.mjs` writes `public/BUILD.txt` with the SHA-256 of every artefact and
injects subresource integrity for the script and stylesheet into `index.html`; the server
serves that file at `/build.txt`; `node scripts/audit.mjs deployment <origin>` builds
locally, fetches what the deployment actually sends, and compares digests of the received
bytes. `audit:bundle` builds twice and fails if the two builds differ, so reproducibility
cannot rot unnoticed. `esbuild` is pinned to an exact version, because the bundler *is*
part of the output.

**Alternatives.** Signed release artefacts (a signature proves who built it, not that it
matches the source, and adds a key to protect). A build attestation from CI (moves trust
to GitHub, which the audit document explicitly declines to do). SRI alone (pins the bundle
to the page, but the page is served by the same operator — necessary, not sufficient).

**Consequences.** Verification requires `npm ci`: a different esbuild version produces
different bytes, and a mismatch would look like tampering. `BUILD.txt` served by the
deployment is convenience only — the check hashes what was received, never what the server
claims. And the honest limit stands: this detects a global or accidental substitution, not
a bundle served to one targeted user. That sentence is now in the threat model instead of
an aspiration in the roadmap.

## ADR-0019 — One instance serves both the clearnet and the onion service

**Status:** accepted (2026-09-02)

**Context.** Running an onion service used to require `BEHIND_TLS=false`, and the previous
deployment guide said so — which silently disabled `Secure` on the clearnet cookies of the
same instance. The alternative it suggested, a second instance for Tor, means two
databases or a shared one plus twice the operational surface, for a difference that is
about *transport*, not about the application.

**Decision.** Decide the three transport-dependent behaviours per request, from the Host
header: `Secure` on cookies, `Strict-Transport-Security`, and `upgrade-insecure-requests`
in the CSP are emitted for ordinary hosts and omitted for `.onion` ones — because an onion
service is plain HTTP inside an authenticated, encrypted circuit, where `Secure` cookies
would never be sent, HSTS would pin an address that speaks no HTTPS, and the upgrade
directive would break the page's own requests. Everything else is byte-identical. With
`ONION_HOSTNAME` set (validated as a v3 address at boot) the clearnet site sends
`Onion-Location` so Tor Browser can offer the switch. The `tor` container is built from
Alpine's signed package and maps the hidden service straight at the app, bypassing Caddy.

**Alternatives.** A second instance (two deployments to keep in step, and users' accounts
split or the database shared anyway). A `TRANSPORT=onion` environment switch (a mode flag
whose two values must both be tested forever, and which cannot serve both at once). TLS
inside the onion service (a certificate for an onion address is possible and pointless: the
circuit already authenticates and encrypts).

**Consequences.** The Host header is client-controlled, so a client can talk itself into a
non-`Secure` cookie — on its own request, in its own browser, which is not an attack. The
behaviour is asserted in `test/onion.test.ts` rather than described in a document, because
this is exactly the kind of conditional that rots. And the honest limit is unchanged: both
entrypoints share one database, so Tor hides a user's network location from the operator,
not their activity.

## ADR-0020 — A 180-line QR encoder instead of a dependency, and verification per device

**Status:** accepted (2026-09-02)

**Context.** A safety number that is only text gets compared by nobody: reading forty
characters aloud is exactly the ritual users skip, and skipping it leaves every first
contact trust-on-first-use against a key directory the server controls. A scannable code
fixes the ergonomics. The obvious way to get one is `npm i qrcode`, which is a runtime
dependency in a project that has four and audits every one of them.

**Decision.** Encode the code ourselves: byte mode, version 3, level M — one block, fixed
layout, the eight standard masks, ~180 lines with no dependency, and a hard error above 42
bytes rather than a code that will not scan. The correctness argument is not "we read the
spec": `test/verification.test.ts` decodes the rendered modules with `jsqr`, a reference
decoder kept as a *dev* dependency, exactly as `@scure/bip39` checks our BIP-39 code.

Verification is stored per peer identity key in the local vault. `verificationState()` is a
pure function of the conversation, so the badge, the warning and the tests all read the
same logic: verified when every device in use has been compared, "changed" when one has
not, which is the event worth interrupting someone for.

**Alternatives.** A QR dependency (a fifth production dependency, and a supply-chain risk
for a picture). No code, text only (the status quo nobody used). Scanning as well as
showing (a decoder is an order of magnitude more code, and any phone camera already
decodes — the other side only has to compare what it shows). Blocking messages to an
unverified device (a warning respects the user; a block trains them to click through).

**Consequences.** Payloads over 42 bytes are not supported and never silently truncated;
if a future payload needs more, the encoder needs another version's parameters. Rendering
is an SVG data URL, which the existing `img-src 'self' data:` CSP already allows — no
canvas, no new directive. The record is local: a new device starts unverified, which is
the honest answer rather than a convenient one.

## ADR-0021 — A delivery address is a message, not a column

**Status:** accepted (2026-09-02)

**Context.** Selling physical goods means the seller needs an address, and the reflex is a
`shipping_address` column, perhaps encrypted with a key the server also holds. That reflex
is how every marketplace breach becomes a list of home addresses: the data is in the
database, the key is on the same host, and the operator is one subpoena or one compromised
backup away from handing over both.

**Decision.** There is no address field anywhere in the API or the schema. `physical_good`
is added as a listing kind so the *client* knows to ask; the buyer's browser then sends the
address as an ordinary encrypted message in the order's channel, exactly like the delivery
keys in ADR-0017. The seller's browser stores the plaintext in its own vault; the server
stores the same opaque envelope it stores for any message, and deletes it on delivery.
`test/delivery.test.ts` places a physical order while deliberately posting an address in
the request body, then dumps every table and asserts the string is nowhere — the route
drops unknown fields, and the test proves it rather than trusting it.

**Alternatives.** A column encrypted with a server-held key (the operator can still read
it; a compromise yields both halves). A column encrypted to the seller's public key (better,
but it makes the server the storage and retention point for personal data, with a row that
outlives the order and a schema that invites "just one more field"). A third-party
fulfilment integration (an external processor receiving every buyer's address is the
opposite of this project).

**Consequences.** A seller who loses their vault loses the address and must ask the buyer
again — the same trade this project already makes for message history, and the reason
`docs/PRIVACY.md` says so plainly. Moderating a shipping dispute cannot be done by reading
the address, which is intentional: dispute evidence belongs in the encrypted channel with
only a hash committed server-side (MKT-1). And a physical marketplace still leaks what it
must: the operator knows an order exists, between whom, and for how much.

## ADR-0022 — Proprietary license; supersedes ADR-0002

**Status:** accepted (2026-09-02), superseding ADR-0002 (AGPL-3.0-only)

**Context.** The owner decided the source should be closed. The stated reason is commercial
and precautionary: the platform is heading towards physical goods, sellers' and buyers'
personal data, and a market where the code being readable is seen as a liability.

**Decision.** Symvolon is proprietary — all rights reserved, no licence granted (`LICENSE`).
`package.json` is `private` and `UNLICENSED` so it cannot be published by accident.
Third-party obligations that survive the change are written down in `THIRD_PARTY.md`; the
binding one is `openpgp` (LGPL-3.0+), used unmodified and kept replaceable, which is
satisfied as long as the server is operated rather than distributed as an artefact.

**What this does not change.** Nothing about the architecture. Keys are still generated and
held in the browser, the database still holds ciphertext, there is still no code path from
an operator to a plaintext message, and the delivery address of a physical order is still
not a column (ADR-0021). Closing the source protects business logic; it does not protect
data — that is what "collect nothing that is not strictly required" is for, and a stolen
database is equally readable whether or not the source that wrote it is public.

**What it costs, stated rather than hidden.** The project's own philosophy is "security is
enforced by architecture, not by promises", and verification by outsiders was one of the
architectural pieces. It is now gone:

- Users cannot rebuild the client and compare it with what they are served. `audit:bundle`,
  `audit:secrets` and `audit:deployment` still run, but as *internal* checks whose results
  are a claim.
- Residual risk #1 in `docs/THREAT_MODEL.md` widened accordingly, and `docs/AUDIT.md` now
  opens by saying what its checks are worth to an outsider: diligence, not proof.
- No outside reviewer will find a bug for free; `SECURITY.md` gained a section on
  black-box reporting and offers source access under agreement when a report needs it.
- What survives for a user: the client is delivered to their browser and can be inspected
  there, `/build.txt` publishes the digest of what is served, and identical digests across
  users rule out a bundle targeted at one person.

**Alternatives.** Open client + closed server, the Telegram arrangement (keeps the part
that matters cryptographically verifiable, at the cost of splitting `src/shared`, which is
one implementation used by both sides precisely so the two cannot drift). Source-available
under a non-compete licence (verifiable, not reusable — most of the benefit, most of the
protection). Delaying the decision until launch. The owner considered these and chose full
closure; this ADR records the choice and its price rather than arguing with it further.

## ADR-0023 — One project, one tree: no pre-built open/closed split

**Status:** accepted (2026-09-02). Records a proposal that was built, reviewed by the owner,
and reverted the same day.

**Context.** Anticipating a future Telegram-style arrangement (published client, closed
server), a tool was added that assembled the client half into a separate tree and verified
it built the served bundle byte for byte, running on every push. The owner rejected it: we
are building one project, and a machine that continuously carves it into two halves is a
source of mistakes and, worse, of anonymity leaks — the seam between "publishable" and
"closed" is a new place for a file, a constant or a code path to end up on the wrong side,
and a mistake there is public before anyone notices.

**Decision.** Work on the whole project as one tree. No published subset, no second
licence, no split-maintenance tooling; `scripts/publish-client-source.mjs`, the `audit:oss`
check and the unused AGPL text are removed. The whole repository stays proprietary
(ADR-0022) until the owner decides otherwise.

**Consequences.** Publishing the client later becomes one deliberate piece of work on a
finished codebase, with a human deciding what goes out, instead of a standing invariant
maintained by a script nobody re-reads. The properties that made the split verifiable are
not lost, because they were never part of it: the build is reproducible (ADR-0018), the
served digests are published at `/build.txt` with subresource integrity, and
`npm run audit:deployment` compares a live deployment with a local build. Emulating
Telegram remains a fine ambition; it is a decision to take once, at launch, with the whole
system in view.

## ADR-0024 — Authorization is proved by the route table, not by review

**Status:** accepted (2026-09-02)

**Context.** Points 21–25 of the project brief ask for an administrative audit trail that
does not become a personal-data pile, an authorization check on every endpoint, real
security headers, a hardened frontend and a security review of every route. Most of it was
already true — parameterised queries everywhere, no filesystem path derived from a request,
no outbound requests to be tricked into an SSRF, CSRF in three layers, a `default-src
'self'` policy — so the useful work is not restating that in prose. It is in the two places
where a good state is maintained by memory: a new route that forgets `authenticate`, and a
protection that a refactor removes quietly.

**Decision.** Make both machine-checked, and close the gaps found while looking.

- `app.routeInventory` collects every route as it is registered, and
  `test/authorization.test.ts` walks it: each endpoint not on an explicit public allowlist
  must refuse an anonymous caller, each public entry must really be public, every
  `/api/moderation/*` route must refuse an ordinary session, and a third account with a
  valid session must not touch someone else's order. Adding an unprotected route now fails
  the suite with its own name in the output.
- The audit log gained a `result` column (`ok` / `denied` / `failed`), records refused
  privileged requests by route *pattern*, bounds `note` at 64 characters, and is deleted
  after a retention window (`AUDIT_RETENTION_MS`, one year) by the existing housekeeping
  sweep. An audit trail that keeps everything forever is a surveillance log with a nicer
  name; one that cannot answer "did it work" is not a trail.
- The CSP now carries `require-trusted-types-for 'script'` and `trusted-types 'none'`.
  The client never assigns to an HTML sink, so the strongest DOM-XSS policy a browser
  offers costs nothing and turns a future mistake into a browser-level refusal.
- `el()` — the helper every view builds nodes with — validates URL-bearing attributes
  against a scheme allowlist and throws otherwise. Writing the test found a real hole:
  `//evil.example/path` passed the "starts with `/`" check and would have navigated
  off-site.
- Fastify was left with no timeouts, so a request that never finishes held a connection for
  free; `requestTimeout`, `connectionTimeout` and `keepAliveTimeout` are now set, and
  `maxParamLength` is 128 because every parameter here is an id or a username.

**Consequences.** The public allowlist in the test is now the specification of what is
reachable without a session, and changing it is a deliberate, reviewable act. Trusted Types
constrains future client code: a view that reaches for `innerHTML` will not work in a
modern browser, which is the intended pressure. The audit log answers incident questions
for a year and then forgets, which is a policy choice recorded in `docs/PRIVACY.md` rather
than an accident of nobody writing a delete.

## ADR-0025 — Rate limits per operation, counted against the account

**Status:** accepted (2026-09-02)

**Context.** Points 26–30 of the brief ask for per-operation configurable rate limits, DoS
resilience, untrusted-input handling, non-leaking errors and secrets kept out of Git. The
existing limiter had five generic scopes (`auth`, `register`, `send`, `read`, `write`), was
hardcoded, and keyed every bucket on the client address. Reviewing it produced three
findings worth more than the checklist:

1. **On an onion service, address-keyed limits are one global bucket.** Every request
   arrives from 127.0.0.1, so a single spammer would throttle the whole site while barely
   inconveniencing themselves. The same is true, less absolutely, behind any NAT.
2. **Listing search had no limit at all.** It is also the only query in the system that
   scans — `LIKE '%term%'` cannot use an index — and it is reachable without an account.
3. **The limits could not be changed without a deploy**, which means that during an attack
   the only available response is a code change.

**Decision.**

- Thirteen scopes, one per operation class the brief names: `register`, `login`,
  `recovery`, `sensitive` (password change, key rotation, device linking, deletion),
  `message_send`, `seller_application`, `listing_write`, `order_write`, `review`,
  `moderation`, `search`, plus generic `read` and `write`. Every scope is its own bucket,
  so exhausting one never disables another.
- Buckets are keyed on the **account** when the request carries a session and on the
  address only otherwise. A `preHandler` hook resolves the session once and decides
  nothing; `authenticate` reuses that result, so public routes can still be limited per
  account without an extra query.
- `RATE_LIMITS` overrides any scope as JSON. Unknown scope names and impossible values
  stop the server at boot: a limit you believe you tightened and did not is worse than no
  limit.
- Errors: a 500 now emits one structured JSON line for the operator (reference, route
  pattern, error name and message — no stack, no body, no user, no query) and returns the
  reference to the client with nothing else. Support conversations can start with
  "error 7f3a" instead of a screenshot of internals.
- Validation: every string is normalised to NFC *before* its length is measured, and
  invisible or direction-reversing characters (zero-width spaces, RTL overrides, control
  characters, BOM) are rejected outright — the standard way one marketplace display name
  impersonates another.
- Secrets: any secret may be supplied as `<NAME>_FILE`, the Docker/Kubernetes convention,
  keeping it out of the process environment and out of `docker inspect`. Rotation is
  documented in `docs/DEPLOYMENT.md`, including the part that matters: there is no
  content-protecting key on the server to rotate, because none exists there.

**Consequences.** An operator has one knob per operation and can tighten a single one under
attack. Two accounts sharing an address no longer share an allowance, which is what makes
limits meaningful over Tor. The cost is one session lookup on public API routes for
logged-in visitors, and a slightly larger configuration surface — both cheap next to a
limiter that, on the deployment this project is aimed at, was effectively global.

## ADR-0026 — Project hygiene as executable checks, not as a document

**Status:** accepted (2026-09-02)

**Context.** Points 31–35 of the brief ask for professional repository structure, the full
documentation set, CI gates (lint, types, unit, integration, security, dependency audit,
secret scanning, build verification, migration verification), dependency minimalism,
supply-chain protection, and privacy-by-default. Most of that could be satisfied by writing
documents. Documents rot: the API page that describes an endpoint removed last month is
worse than no page, because it is trusted.

**Decision.** Every requirement that *can* be checked by a machine is checked by one, and
the document is what the check refers to.

- **Documentation drift is a test failure.** `test/docs.test.ts` walks Fastify's route
  table and fails if an endpoint is undocumented (or documented but gone), compares the
  schema against `docs/DATABASE.md`, and compares what `config.ts` reads against
  `docs/ENVIRONMENT.md`. It also fails on any absolute security claim ("unbreakable",
  "100% anonymous") that is not being explicitly rejected — the brief's own rule, enforced
  rather than remembered.
- **No ESLint.** A generic linter is ~100 transitive packages, which point 33 forbids, in
  exchange for style opinions; `tsc --noEmit` already does the type-aware part. Instead
  `scripts/lint.mjs` (≈130 lines, no dependencies) enforces the nine rules that are
  actually load-bearing here. Two of them found real code on first run: `Math.random` in
  the recovery-phrase quiz, now `crypto.getRandomValues`, and three SQL template literals
  that turned out to be safe and now say so in a waiver.
- **`audit:history`.** Scanning the working tree for secrets answers the wrong question; a
  key committed and later deleted is in every clone. The new audit walks every blob in
  every commit. Reviewed fixtures are allowed by blob hash, not by path.
- **Released migrations are immutable**, enforced by `CHECKSUMS.txt`, and
  `test/migrations.test.ts` applies the whole set to an empty database, twice.
- **Dependency policy is executable.** Every production dependency needs a `###` section in
  `docs/DEPENDENCIES.md` answering the brief's seven questions; licences are checked against
  an allowlist that excludes copyleft we cannot ship; the tree has a written budget (68,
  currently 65) that can only rise in a commit that explains why.
- **Supply chain.** `.npmrc` sets `ignore-scripts=true` (install scripts are the most used
  npm compromise path; verified that `npm ci` and the build still work without them),
  `save-exact`, `engine-strict`, and the public registry only. `audit:supply` verifies the
  lockfile's integrity hashes and origins. CI actions are pinned to commit SHAs, the
  checkout keeps no credentials, and `fetch-depth: 0` is required for the history audit.
- **Privacy by default is a test, not a paragraph.** `test/defaults.test.ts` asserts that a
  deployment configuring nothing gets `Secure` cookies, no proxy trust, a loopback bind,
  bounded retention everywhere and every rate-limit scope active; that padding has no
  "off"; that no source file contains a privacy toggle; and that a fresh account has no
  capability it did not earn.

**Conflict worth naming.** The brief says a pull request must pass security gates before
merge; the owner's standing instruction is that everything goes straight to `main` with no
branches. Both cannot hold. The resolution: CI runs on `push` to `main` *and* on
`pull_request`, so the gate exists whichever way a change arrives, and the same commands run
locally before every push (`CONTRIBUTING.md`). Making the gate *blocking* requires a branch
ruleset in the GitHub UI, which only the repository owner can create; until then the gate is
"CI is red for everyone until it is fixed", not "the merge button is disabled".

**Consequences.** Adding an endpoint now costs a documentation line, and adding a dependency
costs a written justification. That friction is the point. The risk is a check that annoys
more than it protects — the waiver mechanism (`audit:allow` with a reason, visible in review)
exists so the answer to a false positive is never to delete the rule.

## ADR-0027 — A design system, and the megabyte that was in front of it

**Status:** accepted (2026-09-02)

**Context.** Points 36–39 asked for a premium, restrained interface with a real design
system, complete dark and light modes on shared semantic tokens, and a fast product. The
existing client was honest but thin: one 150-line stylesheet, dark only, colours as literal
hex values, `window.confirm` for destructive questions, "Loading…" as a loading state, and
a 1 164 kB JavaScript bundle in front of the first paint.

**Decision, and the two bugs it uncovered.**

*The system.* `src/client/styles/app.css` is now tokens plus components: a palette derived
from the two brand colours, semantic tokens on top of it, a 4 px spacing grid, a 1.200 type
scale on system faces, three radii, hairline borders instead of shadows, two motion
durations. Dark is the default set; `[data-theme="light"]` and the
`prefers-color-scheme: light` fallback redefine *the same token names*, which is the whole
of "one system, two themes". `test/design.test.ts` fails if the three blocks disagree, if
component CSS names a colour instead of a token, if view code contains a hex value, or if
anything reaches for the hacker-film register the brief rules out.

*Loading, empty and error states* are three functions in `ui.ts` rather than advice, and
`confirmDialog()` (native `<dialog>`) replaced `window.confirm`.

**Bug one, found by running the real browser instead of trusting the tests: the client did
not work in Chromium at all.** `script-src 'self'` forbids WebAssembly compilation, and the
cryptography *is* WebAssembly, so registration died at the first key derivation with
`CompileError: … 'unsafe-eval' is not an allowed source`. The fix is
`'wasm-unsafe-eval'` — a keyword that permits compiling WASM and nothing else; `eval`,
`new Function` and inline script stay forbidden, and `test/hardening.test.ts` now asserts
exactly that distinction. No test caught this because every test drives the server, and the
CSP is a *browser* behaviour. Screenshot-driven review is now part of front-end work here.

**Bug two, from the same session: inline `style` attributes were being silently dropped.**
`style-src 'self'` has no `'unsafe-inline'`, so two dozen `style: "margin-top:0"` attributes
in the views did nothing at all. They are utility classes now, and a linter rule
(`inline-style`) rejects new ones.

*Performance.* The bundle is split: the entry is 88 kB (25 kB brotli), libsodium is a lazily
imported chunk, and the shell paints before the cryptography arrives. Assets are
content-addressed and served `immutable`, pre-compressed with brotli and gzip at build time,
from memory. Budgets live in `test/audit.test.ts`. Details and the remaining lever are in
`docs/PERFORMANCE.md`.

**Consequences.** The one guarantee that weakened: subresource integrity covers the entry
script and the stylesheet, but a browser cannot enforce SRI on a dynamically imported chunk.
The crypto chunk is instead verified by its content-addressed name, its digest in
`/build.txt`, and `default-src 'self'` — weaker in kind, and said so in `docs/AUDIT.md`
rather than glossed over. The gain is that a first visit is thirteen times lighter, which on
Tor is the difference between usable and not.

## ADR-0028 — Integrity under concurrency lives in the database

**Status:** accepted (2026-09-02)

**Context.** Points 43–44 of the brief ask that the schema be constrained, indexed and
transaction-safe, and that no race let a user buy one thing several times, receive it twice,
move an order illegally, or bypass seller approval. The routes already checked all of that —
with a `SELECT` followed by a write. Under `Promise.all` in the test suite (and under two
browser tabs in production), every handler runs its `SELECT` before any runs its write, and
the checks pass for everyone.

**Decision.**

- *Partial unique indexes* for the two rules that were only application checks: one pending
  seller application per account, one open order per buyer per listing. Same syntax on SQLite
  and PostgreSQL, no cost on rows that do not match.
- *Compare-and-swap transitions.* Every status change — order, delivery, application
  decision, report resolution — is `UPDATE … WHERE id = ? AND status = ? RETURNING id`. No
  row back means someone moved it first, and the caller gets `409 stale_status` instead of
  overwriting their work.
- *Constraint violations are a `409`, not a `500`.* The database refusing a row is the
  designed second line of defence doing its job, so `isConstraintViolation()` (SQLite extended
  code with low byte 19, PostgreSQL SQLSTATE class 23) turns it into a conflict; routes that
  can say something more useful wrap the write in `orConflict()`.
- *Indexes* on `orders.listing_id` (a foreign key that had none), on report targets, and on
  `(seller, author)` for per-author reputation.

**What was tried and rejected: retrofitting `CHECK` constraints.** SQLite has no
`ALTER TABLE … ADD CONSTRAINT`; the documented route is to create the new table, copy, drop
the old one and rename. Inside a transaction with `PRAGMA foreign_keys = ON` (which cannot
be switched off mid-transaction, and the migration runner runs everything in one) the
`DROP TABLE orders` cascades through `order_events`, `reviews` and `deliveries` — verified by
running exactly that against `node:sqlite`, with `legacy_alter_table` on and off. A migration
that can silently empty three tables on a production VPS is a worse risk than the one it
removes. Enum columns therefore stay guarded by `asEnum` at the trust boundary, which is the
only path a request has to them, and any table created from now on carries `CHECK` from the
start.

**Consequences.** A racing client sees `409` where it used to see either success (bad) or
`500` (confusing). Tests for concurrency are cheap to write (`test/integrity.test.ts`) and
run on SQLite, whose single writer serialises the handlers — so the tests also accept the
role check refusing the loser, and the compare-and-swap SQL is asserted directly.

## ADR-0029 — Goods that are not files, and reputation that is hard to buy

**Status:** accepted (2026-09-02)

**Context.** Point 45 asks that delivery not assume a type of good — text, files,
credentials, licence keys, links, manual — while keeping anything sensitive safe. Point 46
asks for ratings, reviews, history, disputes, moderation, verification state, fraud
indicators and abuse reporting, and that ratings not be easy to manipulate. Before this
change a service order could never be completed (the only path to `delivered` was a file
upload), a dispute was a status with no reason and no moderator view, moderators' order
decisions were unaudited, and one account with ten completed orders was ten five-star
reviews.

**Decision.**

- *One blob path for every kind of bytes.* The seller's browser already encrypts a file with
  a one-time key and sends the key through the order's channel. A licence key, a credential
  or a link is the same bytes with a different `kind` in that message; the server learns
  neither the kind nor the content. Sensitive goods are therefore stored the only way this
  project stores anything sensitive: as ciphertext the server cannot open, deleted on
  collection.
- *`manual: true`* for a delivery that happened elsewhere — a service rendered, a parcel
  posted. It stores nothing but the status change; the buyer still confirms or disputes.
- *A dispute is a report.* `disputed` requires a reason (10–2000 characters), which becomes
  a `reports` row with `reason = 'dispute'` — the queue moderators already work. The plain
  report route refuses that reason, so a dispute can be opened only by the buyer of the
  order. The queue enriches order reports with the order's public facts and the seller's
  record; it never touches the channel. A moderator settling the order closes the report in
  the same transaction and writes an `order.settled` audit entry.
- *Per-buyer ratings.* Averages are over each author's latest visible review per seller (and
  per listing), the distinct-buyer count is published, and disputes are counted from
  `order_events`, so settling one does not erase it.

**Rejected:** a separate `disputes` table (a report with a target already is one; a second
queue is a second place to forget), and any reputation heuristic on timing or IP (the data
does not exist here, by design).

**Consequences.** Every listing kind now has a path to `completed`. Reputation is now an
average over people rather than over receipts, which is the metric a reader thinks they are
looking at anyway. The residual — many accounts — is stated as risk #7 in the threat model.

## ADR-0030 — Search is an index, and a page is a cursor

**Status:** accepted (2026-09-02)

**Context.** Point 47 wants search to be fast, safe, indexed, resistant to injection and
paginated, and forbids unrestricted expensive database scans. What existed was
`LOWER(title) LIKE '%term%' OR LOWER(description) LIKE '%term%'` with `LIMIT 50` and no
pagination at all: a leading wildcard cannot use an index, so every anonymous request read
every active listing and its 8 kB description. That is a denial-of-service lever with a
one-request price tag, and browsing past the first fifty listings was impossible.

**Decision.** An inverted index (`listing_terms`, migration 008) instead of a full-text
engine, and keyset pagination instead of `OFFSET`.

- *Portable, no extension.* SQLite FTS5 and PostgreSQL `tsvector` are both better full-text
  engines and neither is portable; this project supports both dialects with the same SQL and
  no ORM. A term table is one `CREATE TABLE` that both accept, and a lookup is an index range
  scan on either.
- *Words, ANDed, prefix-matched.* `tokenize()` normalises to letters and digits, so a term
  can never carry a `%`, a `_`, a quote or a control character even before it is bound as a
  parameter. A query with no usable term is refused (`query_too_vague`) rather than answered
  with the whole catalogue, which would be the scan this point removes. The term drives the
  query (`id IN (SELECT … FROM listing_terms …)`), so the database reads matching listings
  rather than filtering all of them.
- *Cursors, not offsets.* A cursor is the last row's sort key (`<day>.<id>`), validated
  against a regex. `OFFSET 10000` costs ten thousand rows of work and shifts under
  concurrent inserts; a cursor costs one seek and is stable. There is no total count for the
  same reason: `COUNT(*)` over a filtered catalogue is the scan under another name.
- *Bounded by construction.* At most 6 terms per query, at most 50 rows per page, at most 200
  indexed words per listing.

**Rejected:** FTS5 (dialect lock-in), trigram indexes (PostgreSQL-only, and a `pg_trgm`
extension an operator may not be allowed to install), ranking by relevance (a marketplace
this size has no relevance signal worth the code; newest-first is honest), and infinite
scroll in the client (a "Show more" button is one line, works without JavaScript state
machines, and does not hijack the scrollbar).

**Consequences.** Search cost is now proportional to matches, not to the catalogue. The
price is a second write per listing change and the tokeniser's opinions: no substring search
inside a word ("synth" finds "synthesizer", "thesi" does not), and no stemming, so "guitars"
and "guitar" are different terms. If that becomes the complaint, the lazy fix is indexing a
few suffixes per word, not a search engine.

## ADR-0031 — Accessibility and the small screen as properties of the helpers

**Status:** accepted (2026-09-02)

**Context.** Points 40–42: accessibility that is not bolted on at the end, a product that
works from a phone to a large screen with the messenger treated with particular care, and
domain boundaries without microservices. The client had `<label>` elements next to inputs
but not associated with them, six `window.prompt` calls, tables without `<thead>`, an
`aria-live` region around the entire application, a header navigation that hid three of its
six destinations on a phone, and text tokens that failed WCAG AA in both themes. None of
that was visible to the test suite.

**Decision.**

- Put the properties into the three helpers every view uses — `field()`, `table()`,
  `formDialog()` — and add `announce()` for hash navigation. A view cannot then forget them.
- Refuse the alternatives by lint (`browser-prompt`, `raw-table`) and by test: contrast is
  computed from the tokens, the responsive rules are asserted, and the shell is checked for
  the skip link and the absence of a global live region.
- Below 640 px the navigation is a bottom bar; tables stack; the composer is a form under the
  thumb; controls are 44 px on touch.
- Domain boundaries are module boundaries in one process (`docs/ARCHITECTURE.md`), enforced
  by `test/architecture.test.ts` reading every import. Route modules never import each
  other; shared logic lives in `lib/`. The one refactor this forced was moving the report
  constants and reputation queries out of route files.

**Found by the browser pass, not by tests.** Skeleton widths were inline styles, dropped
silently by `style-src 'self'` — the same class of bug as ADR-0027's. The bottom bar was
first pinned to the header, because `backdrop-filter` makes an element the containing block
for `position: fixed` descendants.

**Consequences.** The entry bundle grew from 88 kB to 95 kB (27 kB brotli) for the dialog
and table helpers; the budget is 150 kB. Two palette steps were added to reach 4.5:1
(`--grey-550`, `--grey-800`, `--state-danger-deep`) and two unused ones removed.
