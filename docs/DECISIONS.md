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

## ADR-0032 — Notifications that do not describe messages

**Status:** accepted (2026-09-02)

**Context.** Point 48 asks for internal notifications for new messages, order updates, seller
application decisions, moderation actions, reviews and disputes — and requires that
notification metadata not reveal the content of end-to-end encrypted messages to the server.
The naive table (`user_id, title, body, sender, conversation_id`) would do exactly that: even
without a preview, one row per message per recipient hands the server a per-conversation
message counter and a timing trace, which is the traffic analysis `routes/messages.ts` goes
out of its way not to keep.

**Decision.**

- *No free text anywhere.* The table has `kind` (closed set, `CHECK`), an optional subject
  pointing at a record the server can already see, and `detail`: a status word this codebase
  chose, capped at 32 characters by a constraint. `notify()` has no parameter for a sentence,
  so no future caller can add one without changing the schema and this ADR. The prose a reader
  sees is written in the client.
- *One unread hint for messages, coalesced by the schema.* A partial unique index allows a
  single unread `message` row per account; ten messages refresh its timestamp instead of
  writing ten rows. The row names no sender and no channel. The client already polls for
  envelopes and decrypts them — that is where "who" and "what" come from.
- *No push, no email, no device tokens.* A notification is delivered by the client asking.
  Web Push means a third-party endpoint learning when a pseudonymous account is contacted;
  email means an identity this service deliberately never collects.
- *Written in the transaction that caused it* for order, application and review events, so a
  notification never describes a rolled-back action. Where the notification is a courtesy on
  top of a completed action (a delivered message, a moderator's decision already recorded), it
  is best-effort: `notifyQuietly` swallows the failure rather than turning it into a 500.
- *Retention:* 90 days, read or unread (`NOTIFICATION_RETENTION_MS`), and `ON DELETE CASCADE`
  with the account. An inbox is a notice board, not a history.

**Rejected:** per-message rows (a message counter), an unread count per conversation (the
same thing with extra steps), storing the sender for "message from @alice" (the social graph
this project does not keep), and Web Push.

**Consequences.** A user sees that mail arrived but not from whom until their client decrypts
it, which is the honest consequence of the encryption. Notification volume for messages is one
row per account per read cycle, so the table stays small. The residual risk is unchanged from
messaging: the server still sees *when* an account is written to, which is stated in
`docs/THREAT_MODEL.md`.

## ADR-0033 — Uploads are hostile, and this server refuses to know anything about them

**Status:** accepted (2026-09-02)

**Context.** Point 49 requires defences against MIME spoofing, extension spoofing, oversized
files, malicious SVG, path traversal, archive bombs, executable uploads and content sniffing,
using size limits, type validation, safe storage, randomised object names and non-executable
storage. The usual implementation of "type validation" is magic-byte sniffing plus an
allow-list — and it is impossible here, because the only bytes a client uploads are ciphertext
the server cannot read. Attempting to validate a type would mean asking the client to declare
one, which is the vector rather than the control.

**Decision.** Refuse the metadata instead of trusting it, and keep the bytes somewhere nothing
can interpret them.

- *No type, no name, no path in the API or the schema.* `deliveries` has five columns and none
  of them is a filename. A delivery body accepts `ciphertext` or `manual` and nothing else:
  `onlyKeys()` rejects `filename`, `mimeType`, `path` and friends with `unexpected_field`, so
  no client can come to depend on being believed and no future handler finds the field there.
- *Caps in decoded bytes.* `asBase64Url` measured characters, which made every documented cap
  a third too generous, and accepted lengths of `4n + 1` that are not base64 at all. Both are
  now errors.
- *Names are sanitised on the client, where the only name lives.* `safeFileName()` (in
  `shared/`) strips separators, `..`, control characters and bidi overrides, refuses Windows
  device names, caps the length and never returns an empty string. It runs where a peer's name
  enters the vault and again where a download is named.
- *Storage is a database column with a random id.* No directory, no filesystem path derived
  from a request, nothing executable, and no static route that could serve a stored blob.
  Downloads are `application/octet-stream` from a blob URL that is never navigated to.
- *No scanning, and we say so.* An E2EE marketplace cannot scan what it cannot decrypt.
  Pretending otherwise would be the absolute security claim `test/docs.test.ts` forbids.

**Rejected:** magic-byte validation (nothing to sniff), rejecting executables (a software
seller is a legitimate user; the honest control is that the buyer chose the seller), unpacking
archives to check them (an archive bomb defence that runs the bomb), and storing files on disk
behind a static server (the classic path-traversal and misconfigured-interpreter surface, for
no benefit at 5 MiB).

**Consequences.** The upload surface is one endpoint that accepts two fields and stores one
opaque string. The buyer carries the residual risk that the bytes they bought are malicious,
which is stated in `docs/THREAT_MODEL.md` rather than papered over.

## ADR-0034 — Backups that expire, and logs that are boring on purpose

**Status:** accepted (2026-09-02)

**Context.** Points 50 and 51. Backups must be encrypted, access-controlled, versioned, tested
and documented — *and* must not become a permanent copy of every user's deleted data. Logging
must help security without destroying privacy, and five questions (what, why, how long, who,
when deleted) must be answered before production rather than after an incident. What existed:
a `DEPLOYMENT.md` snippet suggesting `VACUUM INTO` and `age`, with no retention story, no
verification and nothing runnable; and one hand-written `process.stderr.write` in the error
handler that was careful, but was careful by memory rather than by construction.

**Decision.**

- *One script, `scripts/backup.mjs`, with AES-256-GCM from `node:crypto`.* No new dependency
  and no external binary that has to be installed on the host at 3am. The authentication tag
  turns a truncated or edited backup into a loud failure instead of a quiet restore. Every
  `create` decrypts its own output, runs `PRAGMA integrity_check` and counts tables before it
  reports success; `restore` verifies before it writes and refuses to overwrite. That is what
  makes "tested" a property of the tool rather than a quarterly intention.
- *The application cannot decrypt its own backups.* The key is a file read by the script, never
  part of `config.ts` and never a command-line argument (`ps` and shell history are logs too).
- *Retention is the policy, not the implementation detail:* 35 days, minimum 7 files, and **no
  weekly/monthly/yearly archive tier**. An archive tier is a permanent copy of deleted
  accounts, and this product promises deletion. An operator with a legal obligation to keep
  more can, in their jurisdiction, with their own justification — not by default.
- *One logging module, three line shapes, a fixed field list, and a scrubber.* `log()` has no
  `extra` and no `context`; `scrub()` redacts anything shaped like a key or an address and
  drops any message that so much as names a password, token, cookie or ciphertext. The lint
  rule `unstructured-log` fails the build if anything else under `src/server/` writes to a
  stream, so the next debugging session cannot leave a `stderr.write(request.body)` behind.
- *Retention for logs lives with the process manager* (Docker `json-file`, 3 × 10 MB;
  journald a week), because the application owns no log file and should not learn to rotate one.

**Rejected:** `age`/`gpg` as a hard dependency (an operator who has not installed it discovers
that during their first restore), streaming encryption with libsodium (async init in a CLI, for
a 5 MB file), a redaction pipeline over rich structured logs (the cheaper control is not
collecting the fields), a log shipper or error-reporting SaaS (a third party learning when a
pseudonymous service has incidents, and a CSP exception to go with it), and keeping stack
traces (a stack is a filesystem layout and a dependency inventory).

**Consequences.** `npm run backup` is a one-liner in a cron job whose failure is visible, and a
restore drill takes a minute. Data lost more than 35 days ago is genuinely unrecoverable —
deliberate. Debugging is harder than with request logging: an operator gets a route pattern, an
error name and a scrubbed message, and for anything more must reproduce it. That is the trade
this project is here to make.

## ADR-0035 — Revocation is final, and claiming a prekey is not an ordinary read

**Status:** accepted (2026-09-03)

**Context.** PASS 2 of the review loop (`SECURITY_REVIEW.md`, R-02 and R-03) attacked the
key directory as a hostile *account*, the cheapest attacker to be. Two things worked.

Re-publishing a device set `revoked_at = NULL`, so "revoke this device" was undone by the
device itself: a thief holding the identity private key and a session could publish the
same bundle again and reappear in every prekey bundle. And `GET /api/keys/bundle/:username`
consumes one one-time prekey per device per call while sitting in the generic `read` bucket
(240 burst, 240/minute) — one account could empty another account's prekeys in seconds, so
every new session with that person would open against the signed prekey alone.

**Decision.** A revoked identity key is refused for good (`409 device_revoked`); a new
device means a new identity, which is what the client generates anyway. Bundle claiming
gets its own scope, `key_bundle` (30 burst, 10/minute) — the fourteenth, and the first that
exists because a *read* consumes something belonging to somebody else.

**Rejected:** keeping a "re-activate device" path behind the password (the password is what
a stolen unlocked browser already has); refilling one-time prekeys server-side (the server
has no private material and must not invent any); making the bundle route
`sensitive` (that bucket is shared with password changes and linking, and exhausting it
would break account management rather than slow an attacker).

**Consequences.** Revoking a device on the wrong day costs a new device identity and a new
safety-number comparison — deliberate friction on a rare action. A client that opens many
conversations at once (a first sign-in with a large contact list) will now be throttled at
30; it retries, and the alternative was letting anyone drain a stranger's prekeys. Neither
change touches an existing session, a stored key or the wire format.

*Amended by ADR-0060: the claim itself is now one statement, because "inside a transaction"
was not the same as atomic on a database with real concurrency.*

## ADR-0036 — One writer at a time on SQLite, because handlers are not synchronous

**Status:** accepted (2026-09-03)

**Context.** `node:sqlite` is synchronous, but a request handler is not. A transaction body
that awaits anything yields to the event loop, and the next request's `BEGIN IMMEDIATE`
runs *inside* the first transaction: SQLite answers "cannot start a transaction within a
transaction" (a 500 under any real concurrency), and the statements that do get through
share one transaction — a rollback in one request could discard another request's writes.
Found by a test that fetched four prekey bundles at once (R-01); three of the four failed.
PostgreSQL never had the problem, because each transaction checks out its own pooled client.

**Decision.** The SQLite driver queues transactions on the connection: each waits for the
previous one to finish before it opens. Nested calls are unchanged — they reuse the open
transaction, which is what the existing `inTransaction` flag already meant.

**Rejected:** a mutex library (nine lines of promise chaining, no dependency); retrying on
`SQLITE_BUSY` (the failure is not contention between processes, it is one process talking
over itself); `PRAGMA journal_mode`/`busy_timeout` tuning (a timeout does not stop a nested
`BEGIN`); making every handler synchronous (it is the shape of the whole application).

**Consequences.** Writes were already serialised by SQLite's single-writer rule; the queue
makes the waiting explicit instead of an error. Reads outside a transaction are untouched.
A transaction body that never settles would now stall later transactions — acceptable,
because every one of them is a handful of statements with no external I/O.

## ADR-0037 — A break-glass tool that can only take access away

**Status:** accepted (2026-09-03)

**Context.** Point 52 asks for incident procedures. A procedure whose step is "run this SQL
by hand" is a procedure nobody follows correctly at 3am, and the operator genuinely needs
three things the API cannot give them: acting for *other people's* accounts, acting while
the application is stopped, and one line to copy.

**Decision.** `scripts/incident.mjs`, with `status`, `sessions:revoke-all`,
`sessions:revoke`, `devices:revoke`, `suspend`, `reinstate` and `links:purge`. Every
destructive command refuses to run without `--yes` and prints the rows it changed. The tool
runs on the host against the database file, not inside the read-only container: a
break-glass path shipped inside the running service is a backdoor with a nicer name. It has
no command that reads a message, a vault or a password hash, and `test/incident.test.ts`
asserts that no such SQL exists in the file.

**Rejected:** an admin HTTP endpoint (the compromise case is exactly when the application
cannot be trusted); PostgreSQL support in the same script (it would need the driver, a
connection string on a command line and a second code path nobody exercises — the tool
refuses loudly and prints the equivalent SQL instead); a `--dry-run` flag (`status` before
and after is the honest version, and one fewer mode to get wrong).

**Consequences.** The procedures in `INCIDENT_RESPONSE.md` are executable, and their
commands are covered by tests rather than by hope. An operator on PostgreSQL still has to
paste SQL — documented, not pretended away.

## ADR-0038 — A session that ends of neglect, and a token that does not last a month

**Status:** accepted (2026-09-03)

**Context.** Point 68 asks for expiration, rotation and invalidation. Three of those
existed. The session row carried `last_seen_day` and *nothing read it*: an abandoned
session — a browser on a shared machine, a laptop that was sold — stayed valid for the full
thirty-day TTL, and the cookie value never changed in all that time, so a token captured
once was a token that worked for a month.

**Decision.** Two limits and one rotation, all in `resolveSession`:

- **absolute** expiry (`expires_at`) is unchanged and is never extended;
- **idle** expiry deletes a session that has gone unused for `SESSION_IDLE_DAYS` (14);
- the token **rotates on the first request of each day** — the same write that already
  updated `last_seen_day`, so it costs one write per session per day and no new schedule.

Rotation needs a grace window or it becomes a race: two requests can be in flight when the
cookie changes. Migration 010 adds `previous_token_hash` and `rotated_at`, and the previous
hash is accepted for 60 seconds after the rotation and refused afterwards.

**Rejected:** rotating on every request (a browser with two tabs would fight itself, and the
write amplification is real); binding a session to an IP address (it would mean storing
addresses, which is the thing this project spends the most effort *not* doing); a sliding
absolute expiry (a session that renews itself while you use it never ends, which is the
opposite of the requirement); telling the user "your session was used from a new place"
(there is no place — nothing records where a session is used, and inventing that record to
warn about it would be a poor trade).

**Consequences.** A stolen cookie has a shelf life of about a day even if nobody notices
the theft. Day granularity means the idle window is 14 to 15 days, which is fine for a
policy expressed in weeks. `last_seen_day` is now load-bearing rather than decorative, and
`test/sessions.test.ts` covers both expiries, the rotation, the grace window and its end.

## ADR-0039 — Arithmetic instead of a CAPTCHA

**Status:** accepted (2026-09-03)

**Context.** Point 71 asks for defences against registration abuse, credential stuffing,
spam and scraping, and asks in the same breath that verification not become surveillance.
The rate limiter alone could not carry this: for an unauthenticated request it counts
against the client address, and on the onion service every request arrives from one address
— the `tor` container — so `register` and `login` shared a *single global bucket* for the
whole deployment. Roughly one login a minute for everybody, or a limit loose enough to
defend nothing. Its own source comment noticed the problem for authenticated traffic and
stopped there.

**Decision.** A proof of work on `register`, `login` and `recovery/challenge`: find a nonce
whose SHA-256 has `POW_BITS` (default 16) leading zero bits. The refusal is a `428` that
*carries* the challenge, so there is no endpoint to fetch one from and no extra round trip;
the challenge is a MAC over a random token, a timestamp and the difficulty, so issuing one
writes nothing and cannot be downgraded; redeeming one inserts a row whose primary key
makes it single-use. Both the browser client and the test client solve and retry
transparently. Alongside it, a second bucket (`account_attempt`) counts attempts against
the *targeted username*, which is the counter that still works when the attacker has many
addresses or the users share one.

**Rejected:** a CAPTCHA (a third party watching our users, which is the thing this project
exists to avoid); email or SMS verification (it turns "no personal data" into "an identity
document with extra steps", and point 69 asks recovery not to demand personal data either);
a per-address block list (there is no address on the onion service, and blocking Tor exits
punishes exactly the users this is built for); a hashcash *stamp* the client mints itself
(precomputable at leisure — the server must choose the challenge); requiring proof of work
on every endpoint (an authenticated caller can be charged to their account instead, which
is cheaper for them and just as effective).

**Consequences.** Automation now pays per attempt in CPU rather than per address, and
nobody is asked who they are. It is a cost and not a wall: an attacker with real hardware
still gets through, more slowly. The browser pays a fraction of a second on sign-in, and
the search blocks the thread — if the difficulty is ever raised to where that is felt, the
loop moves to a Web Worker. `POW_BITS=0` disables the gate for a closed instance, which is
supported and documented rather than hidden.

## ADR-0040 — The deployment is checked by tests, not described by documents

**Status:** accepted (2026-09-03)

**Context.** Points 63–67 are largely configuration and prose: a compose file, a Caddyfile,
a hardening page. Prose about security controls decays silently — this repository had a
live example. `docs/DEPLOYMENT.md` and `docs/THREAT_MODEL.md` both stated that the
application container had no route to the internet, while `deploy/docker-compose.yml` had
it on the public-facing network alongside the proxy. Nobody was lying; the file changed and
the sentence did not.

**Decision.** `test/deployment.test.ts` reads `deploy/docker-compose.yml`, `deploy/Dockerfile`
and `deploy/Caddyfile` and asserts the properties the documents claim: unprivileged and
read-only containers, all capabilities dropped, memory/CPU/process limits, health checks,
base images pinned by digest, the application off the public network with no published
port, the internal network actually internal, no database port published even in the
commented-out example, TLS 1.2 as the floor with no legacy protocol enabled, and the admin
API off. It also checks that the three documents exist and cover the topics the brief
lists. It runs inside `npm test`, so it needs no change to the CI workflow.

**Rejected:** a YAML parser dependency to inspect forty lines of our own configuration
(the supply chain is the thing being audited; a twenty-line reader that only understands
this file is the cheaper trade); actually starting the containers in CI (it needs a Docker
daemon, a network and minutes — and it would test Docker, not our configuration); trusting
a review checklist (this ADR exists because a checklist is what failed).

**Consequences.** A control cannot be removed while the paragraph describing it stays.
The cost is that the test knows the shape of the compose file: reorganising it means
updating the reader. That is the intended cost — noticing is the feature.

## ADR-0041 — Disappearing messages are an agreement, not a guarantee

**Status:** accepted (2026-09-03)

**Context.** Point 74 asks for message deletion — disappearing messages, client-side
deletion, server-side deletion of ciphertext, key destruction, retention — and adds the
constraint that matters: do not promise cryptographic destruction where every copy cannot
be reached. Most messengers ship "delete for everyone" and a shredder icon, both of which
describe an outcome the software cannot produce.

**Decision.** Four mechanisms, each named for what it actually does.

1. **Disappearing messages** — a per-conversation lifetime in whole hours. The expiry
   travels inside the ciphertext so both clients agree without the server being told; both
   drop the plaintext when it passes; the sender additionally asks for a shorter envelope
   TTL (`ttlHours`, clamped to `ENVELOPE_TTL_MS`) so an undelivered copy is not held for
   thirty days. When the two sides disagree, the sooner expiry wins.
2. **Client-side deletion** — one message, or a whole conversation. Deleting a conversation
   destroys its ratchet state as well as its history: the session keys are the part that
   could still open something.
3. **Server-side deletion** — unchanged and already strong: an envelope is deleted at
   acknowledgement, and by expiry regardless.
4. **Key destruction** — skipped message keys now expire after seven days
   (`MAX_SKIPPED_KEY_AGE_MS`) rather than only when two thousand newer keys push them out. A
   key derived for a message that never arrived used to stay openable for the life of the
   conversation.

**Rejected:** "delete for everyone" (it asks the other client to cooperate and reports
success either way — a lie in the reassuring direction); minute-granularity expiry (the TTL
is visible to the operator, and precision there is a fingerprint); a shorter TTL for control
messages, which would have let the operator tell a typing signal from a sentence by its
expiry.

**Consequences.** `docs/DELETION.md` states the ceiling in the same document as the feature:
JavaScript cannot reliably zero a string, `localStorage` is not a shredder, an operator's
encrypted backup may still hold a deleted envelope, and a recipient can always copy what
they can read. The UI says "delete from this device", because that is what the button does.

## ADR-0042 — Typing, read receipts and presence are messages, and they are off

**Status:** accepted (2026-09-03)

**Context.** Points 75–77. A messenger's metadata features are usually server state:
a presence table, a `read_at` column, a websocket that broadcasts "typing". Each is a
continuous record of when a person is awake and paying attention, held by the party this
architecture trusts least.

**Decision.** No server state for any of them, and nothing on by default.

- **Presence does not exist.** No `last_seen`, no heartbeat, no route that answers "is she
  online". The nearest thing in the schema is `sessions.last_seen_day`, which is a day and
  is read only to expire idle sessions.
- **Typing and read receipts are ordinary encrypted messages** — a payload with a `signal`
  field and no text, carried by the same ratchet, padded the same way, with the same expiry
  as everything else in the conversation. The server cannot tell one from a sentence.
- **Both are off until a person turns them on**, and the settings live in the encrypted
  vault rather than in a table, because "this account has read receipts off" is itself a
  fact about a person.
- Typing is throttled to one signal per six seconds, shown for eight, and never written to
  the vault: a presence *history* is what this feature becomes if nobody stops it.
- Read receipts are "read up to this timestamp", once per batch — not one per message.

**Rejected:** a presence service (the feature this system is least able to make private); a
`read_at` column (it would make the server the authority on when someone read something);
per-message receipts; syncing the settings server-side so they follow a linked device — a
new device starts with everything off, which is the right direction for a default to fail in.

**Consequences.** Turning typing indicators on is a real cost, and `docs/METADATA.md` says
so: the operator sees envelopes while you compose. The inverse cost is small and accepted —
the unread badge lights up for a signal, because the server coalesces one "something
arrived" hint per account and must not be able to tell what the something was.

## ADR-0043 — Attachments are blind blobs with a client-chosen id

**Status:** accepted (2026-09-03)

**Context.** Point 78: if images, files, audio or video are supported, encrypt them
client-side, and do not treat HTTPS as a substitute for end-to-end encryption. The order
delivery path already stores blobs the server cannot open, but it is bound to an order.

**Decision.** One new table (`attachments`) and three routes, sharing `crypto/file.ts` with
deliveries. The browser generates a 192-bit id, encrypts the bytes under a fresh key with
that id as associated data, uploads `{ id, ciphertext }` and nothing else, and sends the
key inside the encrypted message. There is no sender column, no recipient column, no
conversation, no filename, no media type and no plaintext length. Fetching needs the id and
opening needs the key; the server has neither to give away. Its own bucket
(`attachment`: 12 burst, 3/minute) is the quota, because a per-account quota needs an owner
column.

**Rejected:** embedding media in the envelope (a 64 kB cap and megabytes of base64 in
`localStorage`); a recipient column so the server can authorise fetches (it is the social
graph, written down); a server-assigned id (the client must know the id *before* it
encrypts, since the id is the associated data); inline image previews, which would need
`blob:` in the CSP and would point the browser's image decoder at bytes a stranger chose —
attachments are saved, never rendered.

**Consequences.** An attachment outlives its conversation by up to `DELIVERY_TTL_MS` and is
not reached by account deletion, because there is no owner to cascade from. Deleting the
conversation destroys the only copy of the key, so what remains is unopenable bytes on a
clock. Anyone holding the id may delete the blob early — a recipient deleting bytes they
already have is a smaller risk than the column that would prevent it.

## ADR-0044 — Search happens in the browser, and push does not happen at all

**Status:** accepted (2026-09-03)

**Context.** Points 79 and 80 are two conveniences with one shape: both are easy if the
server knows more, and both are the reason products quietly end up reading messages.

**Decision.** **Search** over private messages runs on the client, against what that device
has already decrypted. There is no route that searches envelopes and no index of message
content anywhere on the server; the marketplace's inverted index (ADR-0030) covers listings,
which are public by nature. **Push notifications** are not implemented: the client polls,
and the internal inbox says "something arrived" and nothing else (ADR-0032).

**Rejected:** encrypted-search schemes (searchable encryption leaks access patterns, and
the honest version of it here is a client that already holds the plaintext); a third-party
push service, which would give a company outside this system a per-device timing feed of
one person's conversations keyed to a token that survives reinstalls — for a notification
tone.

**Consequences.** Search sees what this device holds: not another device's history, and not
what has already disappeared. No push means no notification when the tab is closed, which
is a real product cost and the reason the requirements for ever adding it are written down
now (`docs/METADATA.md`): opaque payload, no plaintext, self-hosted first, opt-in per
device, deletable token, and the residual disclosed.

## ADR-0045 — A review does not name its buyer

**Status:** accepted (2026-09-03)

**Context.** Point 81 asks the marketplace to minimise data in both directions: do not
require what a feature does not need, do not tell a seller more about a buyer than the
transaction needs, and do not tell a buyer more about a seller either. Auditing what the
API actually returned turned up a leak nobody had noticed: `GET /api/market/listings/:id`
published each review's author username, and no client rendered it.

**Decision.** Reviews are returned with a rating, a body and a day, and no author.
`reviews.author_user_id` stays in the table — it enforces one review per order and one
rating per buyer, and it is read by nothing that answers a request.

**Rejected:** a per-listing pseudonym (it still links repeat purchases, and it invites the
belief that the reviewer is anonymous when a seller can identify them from their own order
list anyway); dropping the author column (it is what makes reputation hard to buy).

Two request bodies were tightened in the same pass, for the same reason uploads were
(ADR-0033): `POST /api/market/orders` and `POST /api/market/seller-applications` now refuse
an unexpected field instead of ignoring it. Silently dropping a `shippingAddress` leaves a
buyer believing their parcel has somewhere to go; silently dropping a `legalName` invites
the next version of that client to depend on a field this server will never store.

**Consequences.** A reader sees the average, the number of distinct buyers, and the reviews
themselves — which is the signal — without learning who bought what. The seller still knows
who ordered from them, because the encrypted order chat is opened by username; that is the
minimum the transaction needs, and it is stated in `docs/PRIVACY.md` rather than dressed up.

## ADR-0046 — Payment state is designed before it is built, and stays outside the messenger

**Status:** accepted (2026-09-03)

**Context.** Point 82. Payments are not implemented, and the temptation when they are is to
put a payment reference on the order, a card field behind it, and a webhook handler that
logs everything it receives — at which point the system holds identity.

**Decision.** Write the architecture now and enforce what can be enforced before the feature
exists. `docs/PAYMENTS.md` fixes the rules: payment state in its own module and tables,
joined to an order by id and to nothing else; never a card number, expiry, CVV, bank
account, billing address or raw webhook body; no import between the payment domain and
messaging; card data never touching this origin. `test/payments.test.ts` dumps the schema
and fails on a card-shaped column, and checks that no route accepts one.

**Rejected:** building a payment adapter speculatively (YAGNI, and the wrong feature to
guess at); a hosted processor as the default choice — the preference order is no processor,
then a self-hosted cryptocurrency gateway (roadmap PAY-1), then a conventional processor
with its disclosure written into the threat model.

**Consequences.** Today an order records what was bought and how it ended, and the money is
arranged between the parties in their encrypted channel. Escrow stays blocked on payments,
and if it arrives a moderator's power stays what it is now: settle the order, never move the
money.

## ADR-0047 — Blocking is the recipient's decision, and the server is not told

**Status:** accepted (2026-09-03)

**Context.** Points 83 and 84. Abuse protection has to exist, and the obvious block list is
a server-side table of who refuses whom — which is the social graph, written down, for the
component that is not supposed to have it. The messaging design has no sender column
precisely to avoid holding that.

**Decision.** A block is client-side and lives in the encrypted vault. A blocked peer's
envelopes are decrypted (the ratchet must advance or the session desynchronises), then
discarded without being stored or shown, and sending to a blocked peer is refused locally.
Moderation stays in its four separate lanes (`docs/MODERATION.md`): marketplace, public
content, reports and disputes — and private messages, which have no lane, no route and no
key. A report about private abuse carries only the words the reporter chose to write.

**Rejected:** server-enforced blocking (it would need the pair, and the pair is the graph);
shadow-banning; content scanning of messages or attachments, which is impossible here and
would not be added if it were possible.

**Consequences.** A blocked sender can still consume rate-limit allowance and briefly occupy
storage, and a block applies per device rather than per account. `test/abuse.test.ts` asserts
the structural half: no moderation route reads `envelopes`, `vaults`, `deliveries` or
`attachments`, and the moderation queue never returns an order's channel.

## ADR-0048 — Health is two endpoints, and monitoring counts nothing but numbers

**Status:** accepted (2026-09-03)

**Context.** Point 85. A production service needs uptime, CPU, memory, disk, database health,
error rate and latency. The default way to get them is an agent, an exporter and a time
series keyed by route and by user — which is an access log with a graph on top, in a project
whose whole argument is that it does not keep one.

**Decision.** Two endpoints with different audiences. `GET /healthz` stays what it is:
unauthenticated, two words, so a liveness probe reveals nothing about load or headroom.
`GET /api/admin/health` is administrator-only and answers everything else, assembled from
`process`, `node:os` and one `SELECT 1`. The counters behind it (`lib/metrics.ts`) take a
status code and a duration — two numbers, no route, no account, no address, no body — and
live in memory, so a restart resets them. `test/observability.test.ts` walks the response and
fails on any leaf that is not a number, a boolean or one of four fixed words.

**Rejected:** Prometheus with per-route labels (the labels are the leak, and a scrape endpoint
is a second thing to authenticate); an APM or error-reporting SaaS (a third party learning
about users); persisting the counters (a time series of endpoint volume is an access log
written slowly); exposing the numbers on `/healthz` (load and headroom tell an attacker when
to push).

**Consequences.** "Which endpoint is slow" is not answerable from production; it needs a
reproduction and a profiler, which is the trade this project keeps making. An operator who
wants history has to poll the endpoint and store it themselves, and is told in
`docs/OBSERVABILITY.md` that this is the moment they start keeping one.

## ADR-0049 — Ceilings the rate limiter cannot enforce

**Status:** accepted (2026-09-03)

**Context.** Point 86. Token buckets count requests that arrive. The cheapest ways to exhaust
a small VPS do not arrive as requests: sockets that are opened and never used, a body that is
streamed forever, a transaction left idle holding a connection, a query that runs for a
minute after its client has gone.

**Decision.** Cap each one where it is cheapest. `MAX_CONNECTIONS` (default 512) is applied to
the HTTP server, so beyond it the kernel queues instead of the process running out of memory;
the request, connection and keep-alive timeouts stay as they are; the body limit stays derived
from the largest legitimate payload. PostgreSQL gets `statement_timeout` and
`idle_in_transaction_session_timeout` from `DB_STATEMENT_TIMEOUT_MS` (default 5s) and a bounded
`connectionTimeoutMillis`, so a burst fails fast rather than piling up. SQLite has no
server-side statement timeout; there the protection stays the indexes and the `LIMIT` on every
list query, and that is stated rather than papered over.

**Rejected:** a per-account disk quota for attachments (it needs an owner column, and that
column is the social graph — the `attachment` bucket is the quota instead); a global concurrency
semaphore in front of the handlers (a second queue in user space, in front of the kernel's).

**Consequences.** A deployment that legitimately needs more than 512 concurrent sockets has to
raise a number, which is a smaller surprise than an out-of-memory kill. A long-running
PostgreSQL query now fails at five seconds with a driver error rather than blocking a
connection; if a legitimate query ever needs longer, the fix is the query.

## ADR-0050 — One version in the path, one envelope for every error

**Status:** accepted (2026-09-03)

**Context.** Points 88 and 89. The API had no version anywhere, so the only way to make a
breaking change was to break clients silently. Its errors were already consistent in shape,
but nothing enforced it, the code list existed only in the source, and a `429` did not carry
the `Retry-After` that `docs/API.md` promised — a documented header that was never sent.

**Decision.** `/api/v1/...` is stripped before routing (Fastify's `rewriteUrl`), so the
versioned and unversioned paths are the same endpoint and there is only one route table; every
`/api/` response carries `X-API-Version`. A breaking change ships as `/api/v2` next to v1,
never as an edit to v1. Errors keep the `{ error, message }` envelope; every code the source can
produce is listed in the error table in `docs/API.md`, and `test/api.test.ts` extracts the codes
from the source and fails on one that is missing there or documented and gone. A `429` now
carries both `Retry-After` and `retryAfterSeconds`, and the client puts the number in the
message instead of inventing a backoff.

**Rejected:** duplicating the route table under a `/api/v1` prefix (two spellings that can
drift); a version negotiated by header alone (invisible in a log, a `curl` and a bug report);
error codes maintained as a hand-written enum (a second list to forget).

**Consequences.** Older clients keep working through the unversioned path for as long as v1 is
current, which is a compatibility promise this project has now made in writing. Adding an error
code means editing `docs/API.md` in the same commit, which is the point.

## ADR-0051 — No WebSocket, and the nine things one would have to do

**Status:** accepted (2026-09-03)

**Context.** Point 87 asks how the WebSocket layer is secured. There is no WebSocket layer:
messaging is store-and-forward over HTTP with a polling client, which is what makes "no
presence, no last-seen, no heartbeat" (ADR-0042) enforceable rather than promised.

**Decision.** Keep it that way, and make it checkable. `test/api.test.ts` fails if `new
WebSocket`, a `ws:`/`wss:` URL, a `ws`/`socket.io`/`@fastify/websocket` dependency or a socket
scheme in `connect-src` ever appears. `docs/NETWORK.md` carries the checklist a socket would
have to satisfy before it could ship — handshake authentication, per-frame authorisation,
`Origin` validation, shared rate-limit buckets, per-account connection limits, heartbeat, idle
and handshake timeouts, a frame cap no larger than `MAX_ENVELOPE_BYTES`, and reconnect backoff.

**Rejected:** adding a socket now for a live order chat (polling already delivers it, and the
socket would add presence the server currently cannot observe); answering point 87 with "not
applicable" and no test, which is how a "we do not do that" becomes untrue in a later commit.

**Consequences.** A message can be up to one polling interval late, and Tor pays a round trip
for each poll. In exchange the server holds no open connection per user, and there is no
second authentication path to secure.

## ADR-0052 — Rolling back a migration is a restore, not a down script

**Status:** accepted (2026-09-03)

**Context.** Point 90 asks for migrations that are versioned, reversible where practical, and
tested. Two of the three were already true: `NNN_name.sql` applied in order inside a
transaction, checksummed once released, and `test/migrations.test.ts` applies the whole set to
an empty database and proves the runner is idempotent. Reversibility was neither implemented
nor decided, which meant the plan for a bad deployment was improvisation.

**Decision.** Every new migration declares its own answer in a header comment —
`-- reversible: yes — <the statements that undo it>` or `-- reversible: no — <why>` — and
`npm run audit:migrations` refuses a new file that does not. The rule applies only to files
absent from `CHECKSUMS.txt`, because a released migration is never edited; the eleven that
predate the rule are classified by kind in the rollback table in `docs/DATABASE.md`. There are
no `down` scripts. For anything that deletes or rewrites data, the rollback is a restore from
an encrypted backup, which is a path that is actually exercised (`docs/BACKUPS.md`).

**Rejected:** a `down` section per migration (code that runs once, under pressure, having
never been tested against production data — and it invites editing a released migration to fix
its reverse); a migration tool with an opinion about all this, which is a dependency for a
directory of eleven SQL files.

**Consequences.** Recovering from a destructive migration takes as long as a restore takes,
which is the number to know before deploying one rather than after. Adding a migration now
costs one line of thought about how it would be undone — which is the point, since the author
is the only person who will ever have that answer cheaply.

## ADR-0053 — Three environments, and a placeholder that says what it is

**Status:** accepted (2026-09-03)

**Context.** Point 91. The three configurations already differed in the right ways, but
`NODE_ENV` was cast, not parsed: `NODE_ENV=prod` read as "not production" and silently turned
off the strict checks the production path adds. And the development fallback secret — long
enough to pass the length check — would have been accepted in production had anyone copied a
`.env` between machines, which is exactly how that mistake is made.

**Decision.** `NODE_ENV` is parsed into `development | test | production` and anything else
stops the boot. The development fallback keeps the prefix `development-only-`, and production
refuses any secret that starts with it, by name, with a message that says how to generate a
real one. `test/environments.test.ts` asserts all of it, and `docs/ENVIRONMENT.md` states how
the three differ in one table.

**Rejected:** a fourth `staging` environment (it is a production deployment with its own
secrets, and pretending otherwise is how staging ends up with production data); detecting a
"weak" secret by entropy (a guess with false positives, where a prefix is a fact).

**Consequences.** A deployment that used a non-standard `NODE_ENV` value now fails at boot
rather than running in a weaker mode nobody chose. The placeholder is recognisable in a
process listing and in a `.env`, which is the property that makes the check possible.

## ADR-0054 — The records stay in one file, and `docs/adr/` is the way in

**Status:** accepted (2026-09-03)

**Context.** Point 94 asks for ADRs in `docs/adr/`. Fifty-one of them already existed, in
`docs/DECISIONS.md`, in numeric order, each citing the ones it narrows or supersedes.

**Decision.** Keep the records in one file and add `docs/adr/README.md` as the index: every
record, grouped by area — architecture, cryptographic protocol, authentication, database,
deployment, privacy, security, marketplace, client, process. `test/adr.test.ts` fails if a
record is missing from the index, if the index links to an anchor that does not resolve, if a
record appears twice, or if a record since ADR-0011 is missing its template sections.

**Rejected:** splitting into fifty-one files (fifty-one places to grep, a link-rot surface,
and a set of cross-references to keep in step, in exchange for nothing a reader gains);
generating the index from the source (a build step for a table that changes once a week, and
one more thing that can be stale in a checkout).

**Consequences.** Adding a record means two edits in one commit — the record and its row —
and the test says so immediately if the second is forgotten. A record long enough to deserve
its own document gets one and is linked from the index.

## ADR-0055 — Two questions before a commit, and one order when requirements disagree

**Status:** accepted (2026-09-03)

**Context.** Points 92, 93 and 95. "Did this change reduce security?" and "did this change
create a performance regression?" are the two questions that catch what a test suite cannot
see — a check moved to the client, a claim that outran the code, a page that got heavier for
a nicer animation. And when requirements genuinely conflict, an unstated priority order gets
resolved by whoever argues longest.

**Decision.** `docs/CHANGE_REVIEW.md` holds both questions with the mechanical answer for each
(which suites, which budgets, which audit), what to do when the answer is yes — redesign, or
optimise without weakening security — and the ten-item priority order from point 95:
cryptographic correctness, security, privacy, data integrity, authorization, reliability,
performance, maintainability, user experience, visual effects. `AGENTS.md` and
`CONTRIBUTING.md` point at it, and `test/adr.test.ts` fails if either question disappears or
if the ladder is reordered.

**Rejected:** a pull-request template (there are no pull requests here — ADR-0026); a
checklist that duplicates what the audit already enforces, which trains people to tick boxes;
leaving the priority order implicit "because it is obvious", which it is right up until a
deadline.

**Consequences.** Two rows of the ladder are now settled rather than negotiable: a security
measure is not removed to make an interface smoother, and a rate limit is not widened to make
a demo feel faster. An exception needs an ADR, which is the cost that keeps exceptions rare.

## ADR-0056 — A mechanism carries its threat, and a file has a ceiling

**Status:** accepted (2026-09-03)

**Context.** Points 96, 97 and 98. The system had accumulated a lot of security machinery, and
nothing tied any of it to a threat: a reader could not tell which parts were load-bearing and
which were habit. That is the condition in which "let us add another algorithm" sounds like
progress. Separately, `routes/auth.ts` had grown to 783 lines — the file where a missing check
would be least visible.

**Decision.** Every mechanism gets a row in `docs/MECHANISMS.md` with six columns: purpose,
threat, security property, implementation, test, failure mode. A mechanism that cannot fill the
row is not added, and `test/mechanisms.test.ts` fails if a row is incomplete or names a file or
a suite that does not exist. `docs/CHANGE_REVIEW.md` states the choice rule that goes with it —
prefer the safer design while its complexity stays reasonable for one VPS, but never prefer
homemade cryptography to an audited standard — and the eleven-line quality bar, each line
mapped to the command that enforces it. A `giant-file` lint rule caps `src/` and `test/` files
at 700 lines, with one exemption for the BIP-39 word list; `routes/auth.ts` was split along the
seam that already existed, into account lifecycle and `routes/recovery.ts` (the paths that
bypass the password), sharing `lib/auth_flow.ts`.

**Rejected:** a security section in the README (prose nobody diffs); more primitives "for depth"
— five ciphers are five attack surfaces and one of them is the weakest; a line limit low enough
to force artificial splits, which produces files that are small and incoherent.

**Consequences.** Adding a mechanism now costs a row and a test, which is the intended friction.
The register is a second place to update when a mechanism changes — the test makes forgetting
loud rather than silent.

## ADR-0057 — Uploads stop before the disk does, and `TRUST_PROXY` names the proxy

**Status:** accepted (2026-09-03)

**Context.** Two findings from the self-review (`docs/SELF_CRITIQUE.md`, 1 and 3). Blob uploads
inside the rate limit can still fill a small VPS — roughly 900 MB per account per hour — and a
full filesystem stops every SQLite write, which is an outage for the whole service, not just for
uploads. And `TRUST_PROXY=true` made Fastify believe `X-Forwarded-For` from whoever connected,
which is a rate-limit bypass for anything that can reach the port.

**Decision.** A free-space floor in front of blob writes (`lib/storage.ts`): below
`STORAGE_FLOOR_BYTES` (512 MB by default) an upload is refused with `503 storage_full` and
everything else keeps working. The check reads `statfs`, caches it for five seconds, and — this
is the important part — does *not* refuse writes when the filesystem cannot be read, because a
safety margin that fails closed is an outage of its own. `TRUST_PROXY` now also accepts the
proxy addresses, and the documentation recommends that form.

**Rejected:** a per-account storage quota (it needs an owner column on `attachments`, and that
column is the social graph — ADR-0043); refusing uploads by counting bytes in the database (a
sum per upload, and it would not see the WAL, the backups or anything else on the disk).

**Consequences.** An operator now has a number to alert on (`disk.availableBytes`) and a
degraded mode instead of a hard stop. The asymmetry underneath is unchanged and stays on the
roadmap: blobs live for 30 days, and a determined attacker still consumes the allowance up to
the floor.

## ADR-0058 — The criticism of this project lives in this project

**Status:** accepted (2026-09-03)

**Context.** Points 99 and 100. Weaknesses were being found and then scattered — a sentence in
an ADR, a line in the threat model, a roadmap entry, a comment. Nobody could answer "what is
currently wrong with this system" from the repository, which is the question a reviewer, a user
and a future maintainer all ask first.

**Decision.** `docs/SELF_CRITIQUE.md` collects them, each with the seven headings from the
brief — problem, why it matters, severity, attack scenario, proposed fix, implementation,
verification — and fixed findings stay on the page with their fix. `test/mechanisms.test.ts`
enforces the headings and a fixed severity vocabulary. `docs/CHANGE_REVIEW.md` closes with the
development cycle every block of requirements goes through, ending in *reassess* and *improve*,
so a finding has somewhere to land by construction.

**Rejected:** an issue tracker (this repository has no public one, and a private list is exactly
the thing this decision is against); folding the findings into `THREAT_MODEL.md`, which states
what the design accepts, not what the implementation currently gets wrong.

**Consequences.** The project ships a page that argues against itself, which is the intended
effect and is unusual enough to be worth stating: a reader can grade the honesty of everything
else by it. It also has to be maintained — a stale critique is worse than none, so a fixed
finding is edited, never deleted.

## ADR-0059 — Both drivers run the whole suite, and a migration may name a dialect

**Status:** accepted (2026-09-03)

**Context.** Two drivers have shipped since ADR-0004, and only one was ever executed. The
first run of the suite against a real PostgreSQL did not reach the second test: `INTEGER` is
32-bit there and every timestamp in this schema is a millisecond epoch, so the server could
not finish its own migrations (`docs/SELF_CRITIQUE.md`, finding 9). Fixing that ran into the
strongest rule in the repository — a released migration is never edited — and into a second
difference: `pg` returns `BIGINT` and `COUNT(*)` as strings, which would have made
`expires_at < now` and `count === 0` silently wrong.

**Decision.** A second CI job runs the whole suite against PostgreSQL 17
(`TEST_DATABASE_URL`, one schema per test server, `test/database.ts`). Migrations may be
named `NNN_name.postgres.sql` or `NNN_name.sqlite.sql` and then run on that driver only;
`012_widen_timestamps.postgres.sql` widens every millisecond column to `BIGINT` after the
released migrations, without touching one of them. The Postgres driver parses int8 into a
number and throws on a value that cannot be represented exactly, so both drivers return the
same types to the application. Schema introspection in tests goes through helpers rather than
`sqlite_master` and `PRAGMA`.

**Rejected:** editing 001–011 to say `BIGINT` (it is the rule that keeps deployments and
development in step, and "no PostgreSQL deployment can exist yet" is an argument that stops
being true the moment somebody deploys); a `DO $$ … $$` block to widen columns generically
(procedures in migrations, and the statement splitter would cut it in half); keeping the
strings and coercing at every call site (dozens of places, each one a chance to forget).

**Consequences.** CI is two jobs and about a minute longer. Dialect-scoped migrations are a
door that can be misused — the rule is that they exist for type differences, and a scoped
migration that is not about one is a bug. The int8 parser is global to the process, which is
correct here and would need revisiting if this schema ever stored a genuine 64-bit
identifier.

## ADR-0060 — A one-time prekey is claimed by one statement

**Status:** accepted (2026-09-03)

**Context.** `claimOneTimePreKey` read the oldest unclaimed key and then deleted it, inside a
transaction. That is atomic only if the database serialises the two statements, which SQLite
does (one write handle) and PostgreSQL at READ COMMITTED does not. Four concurrent bundle
requests on PostgreSQL received two distinct keys instead of four
(`docs/SELF_CRITIQUE.md`, finding 8).

**Decision.** One statement: `DELETE FROM one_time_prekeys WHERE id = (SELECT id … ORDER BY
key_id LIMIT 1) RETURNING key_id, public_key`. The delete chooses the row and takes it, and
`RETURNING` tells the caller whether it was the one that took it. A caller that loses retries
three times; then the device is treated as out of keys and the bundle is served with the
signed prekey only.

**Rejected:** `SELECT … FOR UPDATE SKIP LOCKED` (correct on PostgreSQL, unsupported on
SQLite, and this codebase writes one SQL for both); `SERIALIZABLE` for the transaction (a
retry loop on serialisation failures, for one row); trusting SQLite's write queue and
documenting the PostgreSQL path as unsafe (that is the cargo-cult inverse — knowing about a
correctness bug and writing it down instead of fixing it).

**Consequences.** Claiming is now one round trip rather than three, and correct on both
drivers. Under heavy contention a caller can still be served without a one-time key, which is
the documented weaker path rather than a broken one.

## ADR-0061 — Recoverability is a command, not a claim

**Status:** accepted (2026-09-03)

**Context.** `docs/BACKUPS.md` promised "tested" backups, and what was tested was that a
snapshot decrypts and passes `PRAGMA integrity_check`. That is a property of the file, not of
the service: a backup can decrypt perfectly and still be one the application refuses to start
on — a schema the current code no longer understands, a migration that fails on the restored
copy, a file the process cannot open. The operator finds out at the worst possible moment,
and `docs/HARDENING.md` asked for a quarterly exercise that nobody had ever run.

**Decision.** `npm run backup:drill`: restore the newest backup to a temporary copy, start a
real server against it in production mode on a random loopback port with a throwaway pepper,
wait for `/healthz`, fetch the page, then delete the copy. It never touches the live database
and never binds the production port. `test/backup.test.ts` runs it on every commit, so the
procedure cannot rot between quarters.

**Rejected:** a document describing the drill (that is what existed, and it was never
executed); restoring over the live database in a maintenance window (the drill should be
cheap enough to run often, and anything that can destroy production will not be); a
staging environment (a second VPS to pay for and patch, to answer a question a temporary
file answers).

**Consequences.** The suite is about a second slower and starts a child process, which is
worth it: this is the only test that proves the whole path — snapshot, encrypt, decrypt,
migrate, boot — works end to end. The drill is SQLite-only, like the backup script;
PostgreSQL deployments use `pg_dump` and the same rules, and their drill is not automated
yet.

## ADR-0062 — A bibliography, and beliefs that carry a label

**Status:** accepted (2026-09-03)

**Context.** Points 103 and 104 ask that critical decisions come from primary sources and that
what is known stay distinguishable from what is assumed. The specifications were being followed
— `docs/CRYPTO.md` names X3DH, the Double Ratchet, RFC 5869 — but the citations were scattered
through prose, there was no single place a reviewer could see *which document we read for
what*, and nothing separated "this reproduces published test vectors" from "we believe this
composition is faithful". Those two sentences deserve very different amounts of trust, and in
a document that mixes them the reader has to guess.

**Decision.** `docs/SOURCES.md`: one table mapping every construction to its primary source and
to the check that proves the code agrees, and a second table stating the project's load-bearing
beliefs under five labels — FACT, ASSUMPTION, DESIGN CHOICE, RISK, UNKNOWN. `test/features.test.ts`
fails if a specification cited anywhere in `docs/` is missing from the page, if a label
disappears, or if a second hand-written cryptographic construction appears beside HKDF.

**Rejected:** citations left inline only (they drift, and nobody can audit a bibliography that
does not exist as a list); a `references.bib`-style file with no link to the tests (a
bibliography whose entries nothing verifies is decoration); labelling every sentence in every
document (the labels are worth something precisely because they are reserved for the beliefs
the system rests on).

**Consequences.** A new primitive or specification now has a place it must appear, and a change
that invalidates one of the labelled beliefs is not finished until the label is corrected. The
UNKNOWN rows are deliberately uncomfortable to read: two of the three say that nobody outside
this project has checked the thing that matters most.

## ADR-0063 — A feature is finished when nine parts exist, and a test counts them

**Status:** accepted (2026-09-03)

**Context.** Point 106 asks for production-grade features rather than demonstrations: frontend,
backend, database, authorization, validation, error handling, security, tests, documentation.
The repository satisfied that in practice — `test/authorization.test.ts` walks the route table,
`test/docs.test.ts` refuses an undocumented endpoint — but there was no place to *see* it, so
the question "is the marketplace actually finished, or is it a screen?" could only be answered
by reading the tree. That is also the question a new block of requirements (point 101) has to
answer before adding anything.

**Decision.** `docs/FEATURES.md`: one row per feature, with its client, server, tables,
authorisation rule, tests and documentation, plus a closing section listing what is *not*
finished. Validation and error handling are noted as cross-cutting rather than per-row, because
in this codebase they are one module each and a per-feature variant would itself be the defect.
`test/features.test.ts` fails if a route file, a screen or a table in the schema has no row, if
the page names a test file that does not exist, or if the "what is missing" section is deleted.

**Rejected:** a checkbox grid with nine columns (unreadable, and it would have invited ticking
boxes rather than naming files); generating the page from the code (the interesting content is
the judgement — which rule applies, what is missing — and a generator cannot write it).

**Consequences.** Adding a route or a table now forces an edit to the matrix, which is the
point: the cheapest moment to notice that a feature has no authorisation rule is while writing
the row that has to name one.

## ADR-0064 — One currency, and it is Monero, stored as an integer

**Status:** accepted (2026-09-03)

**Context.** The marketplace priced listings as `price_minor` (an integer of minor units) plus a
`currency` column from a list of four: USD, EUR, XMR, BTC. Three of those four need somebody to
tell the server an exchange rate before a price can even be displayed next to another price, and
a rate means an outbound HTTP call — to CoinGecko, Binance, Kraken, anyone. The application
container has no route to the internet, deliberately and now provably (`docs/NETWORK.md`,
`test/deployment.test.ts`). So the schema quietly contained a network dependency that the
deployment forbids, and the first person to implement a "price in USD" label would have
discovered it as a bug rather than as a decision.

The requirement that prompted this asked for the opposite arrangement — prices in XMR with USD
shown "via the CoinGecko API, updated every five minutes, averaged across three exchanges" —
and for amounts stored as floating point with twelve decimals.

**Decision.** One currency: XMR. `price_pico` (`BIGINT`, piconero, 10⁻¹² XMR) replaces
`price_minor`; the `currency` column is dropped from `listings` and `orders`; `USD`, `EUR` and
`BTC` are removed from the validator. The wire format is a decimal *string* (`"0.045"`), parsed
into piconero by string arithmetic in `src/shared/money.ts`, because a JSON number is a double
and a double cannot hold every piconero — `0.045 * 1e12` is `45000000000.00001`, and a price one
piconero out is a payment that never matches. A price is 0 (free) or at least 0.001 XMR, which
is ten to a hundred times the network fee it would cost to move or refund; the ceiling is
1,000 XMR, an order of magnitude inside `Number.MAX_SAFE_INTEGER` in piconero. Existing rows are
zeroed and every live listing is paused: converting a historical fiat price needs a rate for a
past day, from a source this deployment cannot reach, applied to somebody else's price without
asking them.

**Rejected:** floating-point amounts (the requirement's own suggestion, and the classic money
bug: a rounding error here is an unpayable invoice); keeping `currency` "for later" (a column
whose only legal value is `'XMR'` is a decision postponed, not preserved, and it invites the
rate oracle back); a fiat display fetched by the browser instead of the server (it moves the
egress to the buyer, tells CoinGecko that this person is looking at this shop, and needs
`connect-src` opened for a decoration); an operator-set reference rate (a number a human updates
by hand is stale by definition, and a wrong rate shown next to a real price is worse than no
rate — it can be added later as an explicit, timestamped, obviously-manual field if anyone
actually wants it); Bitcoin as a second currency (see ADR-0065).

**Consequences.** There is nothing in this codebase that asks anybody for an exchange rate, and
a test says so by grepping for the exchanges by name. Sellers price in the currency they are
paid in — the honest arrangement for a marketplace whose settlement asset is XMR — and a price
displayed anywhere is exact to the piconero. The cost, stated: a buyer who thinks in dollars has
to convert in their head or in their wallet, and the pause-and-re-price migration is visible
work for any seller who had listings before it.

## ADR-0065 — Monero settlement: subaddresses, a view key, polling, and no automatic refund

**Status:** accepted (2026-09-03) — design only; the code is roadmap PAY-1

**Context.** A requirements block asked for a full Monero payment system: a wallet built from
`monero-js` with the private spend key in an environment variable, a WebSocket subscription to a
node that reads each block and matches `tx.address` against pending orders, automatic refunds
"to the address the payment came from", a 30-minute timeout that makes an address invalid, and
BTC as a secondary currency through a swap API. Four of those five cannot be built as written,
and the fifth should not be.

**Decision.** `docs/PAYMENTS.md` now carries the design; the parts that are decisions rather
than description:

- **`monero-wallet-rpc` over JSON-RPC, no wallet library.** `monero-js` does not exist on npm;
  the real libraries are `monero-ts` (formerly `monero-javascript`), which ship a WebAssembly
  build of the wallet. Against a four-dependency budget and an audited bundle, an HTTP client
  for a documented JSON-RPC interface is the smaller and more reviewable thing.
- **The server holds the private view key and nothing else.** It must recognise payments; it
  must not be able to move them. A spend key on an internet-facing host is the failure mode that
  ends projects like this one.
- **Subaddress per order** (`create_address`), not "stealth addresses" — those are the
  protocol's automatic one-time output keys, not an integration's to create — and not integrated
  addresses, which serialise payments per address.
- **Polling, not sockets.** `monerod` exposes JSON-RPC, ZMQ pub/sub and `--block-notify`; it has
  no WebSocket interface, this project has no WebSockets by decision (ADR-0042), and a payment
  cannot be recognised from a block in the first place, because a Monero transaction names no
  recipient. Only a view-key scan can. A 30–60 s poll against a 2-minute block time is not a
  compromise, it is the mechanism.
- **A quote expires, an address does not.** A subaddress cannot be revoked; a late payment to an
  expired quote is still credited to its order, because the money arrived.
- **Refunds are recorded, not executed.** There is no sender address in a Monero transaction, so
  a refund needs a destination the buyer supplies and a key the server does not have.
- **No Bitcoin, and no swap service.** A swap API learns the order, the amounts and both legs,
  can freeze funds mid-order, and can be compelled; and BTC publishes the purchase on a
  transparent ledger. The one property this marketplace is for is the one BTC does not have.
- **Custody is a separate decision, not a technical detail.** Buyer-pays-seller directly
  (out-of-band, today's answer) is non-custodial and needs no node at all. An operator wallet
  that receives buyers' money and forwards it is custody: a hot wallet worth robbing, a
  jurisdiction-dependent legal position, and exactly the compelled-disclosure surface this
  design otherwise removes. The platform's revenue model therefore has to be chosen *before*
  the gateway is built, because the two options produce different code.

**Rejected:** implementing the requirements as given (the code in them does not run: a
non-existent package, a socket that does not exist, a block scan that cannot work, and a refund
target the chain does not contain); building the gateway now against a stub node (the custody
question decides the schema, so it would be written twice); MyMonero or another remote node (it
sees every one of this shop's payment queries, which is the metadata the design exists to
withhold).

**Consequences.** PAY-1 becomes a shippable piece of work with its unknowns named, and the
answer to "why is there no payment code yet" is a document rather than a shrug. Until it ships,
settlement is what it has been: an address in the encrypted order channel, and two parties who
can each verify the payment in their own wallet — including with Monero's own payment proof
(transaction key), which needs nothing from this server.

## ADR-0066 — The marketplace holds the money, and the ledger is what makes that defensible

**Status:** accepted (2026-09-03)

**Context.** ADR-0065 left one question open on purpose, because it decides the schema: does the
platform hold funds, or do buyer and seller settle directly? The owner answered it — a
FunPay-shaped marketplace, where a buyer tops up a balance, the platform holds the price while
the order runs, and the commission is taken from the completed sale. The reason given is the
one that decides it: with direct settlement the two parties can agree beside the platform and
there is nothing to charge a commission on, and no protection to offer a buyer.

That answer buys a business model and imports the largest risk in this repository. Somebody
else's money is now on a server that is reachable from the internet.

**Decision.** Custodial balances, with the risk pushed into the places it can be bounded.

- **Double-entry, not a counter.** `balances` is a running total; `ledger_entries` is an
  append-only history of signed movements in two columns (`available`, `held`). Nothing writes
  one without the other in the same transaction; every operation either sums to zero or names
  the outside world (a confirmed deposit, a sent payout). `test/wallet.test.ts` re-adds every
  entry and compares it to the balance, so a solvency bug fails a test instead of an argument.
- **Escrow is the order state machine.** The price moves to `held` when the order is placed —
  an unfunded order is refused with **402**, before the seller is told anything — and settles
  on `completed` or returns on `cancelled`. A moderator settling a dispute moves the *order*;
  the money follows. Nothing in the system can move money without an order, a deposit or a
  payout row.
- **The platform is an account.** Fee revenue lands on `account_id = 'platform'` rather than
  being computed by summing orders, so revenue reconciles like everything else and a
  double-charged fee cannot hide. `GET /api/admin/treasury` publishes liabilities as one
  number.
- **The fee is 5% of a completed order, charged to the seller** (`ORDER_FEE_BPS`, rounded down
  in the seller's favour). Nothing on top-ups, nothing on payouts, nothing on a cancelled
  order. Boot refuses a fee above 20%.
- **Three wallets, and the application has none of them.** The app tier gets a private view key
  at most; a separate payout process holds a spend key and a working float; everything above
  the float is swept to a cold wallet whose seed never touches this repository, this database
  or a chat. `test/payments.test.ts` greps `src` for a spend key and for the RPC calls that
  spend.
- **Payout limits bound automation, never the money.** Each account has an optional ceiling —
  set by hand when a seller is approved, changed later, both audited — and the deployment
  default (2 XMR ≈ ordinary buyer) applies otherwise. Above it a payout is *queued for an
  administrator*, so a seller withdrawing a large balance needs one approval, and an attacker
  who owns the web process cannot drain anything by asking nicely.
- **Minimums: enforced on the way out, advertised on the way in.** A payout below
  `MIN_WITHDRAWAL_XMR` is refused; a top-up below `MIN_DEPOSIT_XMR` is credited anyway.
  Keeping money because it was smaller than a suggestion is theft, and Monero offers no address
  to return it to. *(Superseded by ADR-0067: the deposit minimum is enforced too, and a smaller
  transfer is recorded uncredited and refunded by hand rather than credited or kept.)*

**Rejected:** a `users.balance_pico` column with `UPDATE … SET balance = balance + ?` (the
common shape, and the reason such platforms cannot prove what they owe); an internal
account-to-account transfer (a payment rail with no order attached is a money transmitter's
product and an abuser's first tool); an endpoint that credits a balance (nothing a compromised
session can call should be able to create money); automatic payouts with no ceiling (it makes a
web process compromise worth the whole wallet); one Monero key per deposit address to limit a
breach (every subaddress of a wallet derives from one spend key — a thousand keys means a
thousand wallets and backups; hot/cold buys the same protection with one moving part);
non-custodial 2-of-3 multisig now (right long-term answer for large orders, young tooling, and
it does not solve the commission problem the owner actually raised).

**Consequences.** The platform is a custodian, with everything that follows: regulated activity
in many jurisdictions (`docs/PAYMENTS.md` §Custody states this plainly and notes that this
repository holds no legal opinion), an operational duty to keep the hot float small, and a
solvency number somebody has to look at. In exchange the marketplace can charge for what it
does, a buyer has a hold to point at when a seller vanishes, and the fee no longer depends on
two strangers choosing to be honest about a sale.

## ADR-0067 — The deposit minimum is enforced, and a smaller transfer is recorded rather than kept

**Status:** accepted (2026-09-03)

**Context.** ADR-0066 shipped `MIN_DEPOSIT_XMR` as advice: a top-up below it was credited
anyway, because refusing a payment nobody can refund reads as theft. The owner's instruction
is that the minimum applies on the way in as well as on the way out — top up from about ten
dollars, or not at all.

The instruction and the earlier reasoning both have a point behind them. Dust top-ups cost
more than they are worth: each one is a row, a support question, and a payout fee larger than
the amount. And a payment silently kept is exactly the accusation a custodial platform cannot
survive.

**Decision.** Enforce it, and make the uncredited money visible instead of absent.

- A transfer below `MIN_DEPOSIT_XMR` is written to `deposits` with status `below_minimum` and
  **no ledger entry**: not credited, not counted as platform revenue, not part of the treasury
  liability, and not silently discarded either.
- `GET /api/wallet` returns `belowMinimumXmr`, the total that arrived under the floor, and the
  wallet screen says the amount, why it is not on the balance, and that support returns it.
- The deposit screen states the minimum as a rule, not a suggestion, *before* anyone sends
  anything.
- Refunding one is a manual payout by an operator (`docs/PAYMENTS.md` §Refunds). There is no
  automatic refund, for the reason in ADR-0065: a Monero transfer names no sender, so the
  platform cannot return money to an address it does not have.

**Rejected:** crediting anyway (the owner's instruction, and it is a real cost with no ceiling
— dust is free to send and not free to hold); refusing and keeping (theft with a changelog
entry); an automatic refund (no sender address exists to refund to); accumulating dust until it
crosses the floor (a balance that appears days later, and an incentive to send dust).

**Consequences.** Somebody who sends 0.005 XMR sees their money named on their own screen and
has to ask for it back — worse than an automatic credit for them, better than a silent loss,
and honest about the rule. `test/wallet.test.ts` covers both sides of the boundary.

## ADR-0068 — Standing is earned on settled orders, and it is what the catalogue sorts by

**Status:** accepted (2026-09-03)

**Context.** Escrow protects an order placed here. The failure mode is the deal that starts
here and finishes elsewhere: a buyer pays a seller directly, receives nothing, and has no hold
to point at. The chat is end-to-end encrypted and will stay that way, so nothing in this
system can *detect* that conversation. What is left is incentive.

**Decision.** A seller's level is computed only from money this escrow moved.

- `sellers.settled_pico` is incremented inside the same transaction that settles a completed
  order, with the seller's actual earnings. It is a sum of ledger movements, so it cannot be
  raised without moving real money through an escrow that charges a fee to do it.
- `level` is 0–3, derived from settled volume *and* completed orders together (0.5 XMR and 3
  orders, 5 XMR and 20, 50 XMR and 100 — `src/server/lib/reputation.ts`). Both conditions,
  because volume alone is one large sale and orders alone are free listings.
- `listings.rank_key` is `level * 100000 + created_day`, and the catalogue orders by it
  descending. Keyset pagination still seeks one index (ADR-0030); the cursor is the rank key.
- The level is published; the volume behind it is not. A buyer needs to know how much trade a
  seller has settled here, not how much money they made.

**Rejected:** ranking by review score (buyable, and ADR-0029 already limits what reviews can
say); ranking by revenue with the number published (a seller's income is not the catalogue's
business); reading the chat for off-platform offers (the one thing this project will not do);
a penalty for a *suspected* off-platform sale (unfalsifiable, and it makes moderation a target).

**Consequences.** A seller who takes a deal off the platform keeps the whole price and loses
level progress, catalogue position and the buyer's protection — the incentive is the mechanism,
and it is honest about being an incentive rather than a rule. A new seller starts at the bottom
of the catalogue, which is the cost, and a search still finds them.

## ADR-0069 — A listing may not advertise a way around the escrow; the chat stays unread

**Status:** accepted (2026-09-03)

**Context.** The same problem as ADR-0068, from the other side: a listing that says "pay me
directly, it is cheaper" reaches every reader of the catalogue, and the buyers who take it up
are the ones who then have no dispute. Moderating that is not moderating a conversation — a
listing is a public advertisement this server stores in the clear and republishes.

**Decision.** Listing text (title, description) and a seller application's statement are
refused when they carry a payment destination or an off-platform contact route: a Monero or
Bitcoin address, an email address, a named third-party messenger, or a "pay me directly"
phrase in either of the catalogue's languages (`src/server/lib/listing_policy.ts`, 400
`off_platform_offer`). The error names the rule, never the pattern that matched.

Nothing is applied to messages. The chat is end-to-end encrypted, the server holds ciphertext,
and no rule that requires reading it will be written here.

**Rejected:** scanning the encrypted channel (impossible without breaking the product's central
promise, and it would be a promise broken quietly); a classifier (a dependency, a model, and a
false positive that no seller can argue with); silently hiding a listing that matches
(shadow-banning teaches nothing and looks like a bug); a wide phrase list (a seller who cannot
publish "email me the receipt after delivery" is a support ticket, so the list stays short).

**Consequences.** The filter is trivially evadable — "you know where to find me" passes — and
that is stated rather than hidden: it raises the cost of advertising the bypass to strangers,
and ADR-0068 is what makes taking it unattractive. Buyers also get the rule in words on the
listing itself: ordering here holds the price; paying directly has no escrow, no dispute and no
refund.

## ADR-0070 — The Monero tier: a watcher that cannot spend, a worker that cannot be called

**Status:** accepted (2026-09-03)

**Context.** ADR-0066 built the books and left the chain out: balances, escrow, the fee, the
payout queue and the treasury total all worked against a `deposits` table nothing ever wrote.
Roadmap PAY-2 is the missing half, and it is where a marketplace like this one usually gets
robbed — not through the cryptography, through a spend key in the same process as an HTTP
router.

Four constraints already in this repository decide most of it (`docs/PAYMENTS.md` §How the
Monero tier must work): the application container has no route to the internet, there are no
WebSockets, the server keeps no key that moves anything, and the dependency list is closed.

**Decision.** Split the wallet in two along the line of what each half can do, and let the
network topology enforce it.

- **The watcher lives in the application process** and speaks to `monero-wallet-rpc` over the
  internal network with three calls and no others: `create_address`, `get_transfers`,
  `get_balance` (`src/server/lib/monero.ts`; `test/monero.test.ts` asserts the vocabulary is
  exactly those three). The wallet it talks to is opened with a **private view key**, so the
  worst an attacker who owns the web process can do is read what arrived.
- **A subaddress per account, created on demand and kept forever.** The index is the whole of
  the attribution — a Monero transfer names no sender — so a second address for one account
  would make a payment unattributable and a reused address would credit the wrong person.
- **Crediting is idempotent three times over**: the scan skips rows already recorded, the
  unique key on `deposits` refuses a duplicate, and `creditDeposit` treats that refusal as
  success. A deposit credited twice is money the platform does not have.
- **Confirmations before credit, never the pool.** `DEPOSIT_CONFIRMATIONS`, default 3 (~6
  minutes). An unconfirmed transfer is not money.
- **The payout worker is a separate process on a separate host** with the spend key and a
  working float (`scripts/payout-worker.mjs`). It *pulls*: `POST /api/payouts/claim` hands it
  one payout and marks the row `sending` in the same statement; it sends; it reports `sent` or
  `failed`. Nothing calls the worker, so a compromised web tier has nothing to ask.
- **`sending` is a one-way door.** No timeout re-queues a payout, because only the process
  holding the key knows whether a transaction was signed, and an automatic retry on an
  uncertain outcome pays somebody twice. A stuck row is an operator with a wallet history.
- **Solvency is compared on the same clock as the scan** and published on
  `GET /api/admin/treasury`: liabilities against what the wallet holds, with the shortfall as
  its own number and a loud log line. The worker refuses anything above its float, which
  returns the money to the owner's balance rather than parking it invisibly.

**Rejected:** a wallet library (a dependency for what is `fetch` and JSON-RPC); one wallet per
account (every subaddress derives from one spend key — a thousand keys is a thousand backups);
ZMQ or `--tx-notify` as the mechanism rather than as an optimisation (a push that is missed is
a top-up that never appears; polling is dull and self-healing); crediting from the transaction
pool (fast, and it pays for transactions that never land); a push API where the marketplace
tells the worker to send (it makes the web tier's compromise worth a wallet); automatic
re-queueing of a `sending` payout (double payment); mutual TLS between worker and marketplace
(right answer at scale, a certificate authority to run today — the bearer token is compared in
constant time and the endpoint is closed when it is unset).

**Consequences.** A deployment can now take money, and everything that follows is real: an
operator has a node to run, a float to keep topped up, a cold reserve to sweep to, and a
shortfall number somebody has to look at. What this decision does *not* buy is confidence in
the RPC vocabulary — every test here runs against a fake wallet, so the first stagenet run is a
roadmap item (PAY-6) and not a formality.

## ADR-0071 — Uncredited dust goes back to its payer, and the refund pays its own way

**Status:** accepted (2026-09-03)

**Context.** ADR-0067 made the deposit minimum real: a transfer under `MIN_DEPOSIT_XMR` is
written to `deposits` with status `below_minimum` and no ledger entry. That was the right call
— crediting a 0.0001 XMR top-up costs more in payout fees than it is worth — but it left the
platform holding money with somebody's name on it and no way to return it except a support
conversation. "You have my coins and there is no button" is the complaint a custodial
marketplace deserves to be judged by, and roadmap PAY-4 is it.

Two facts shape the answer. First, this server does not know where the money came from: a
Monero transfer carries no sender, so only the payer can name a destination. Second, a payout
costs a network fee **that the platform pays** — `scripts/payout-worker.mjs` sends the full
requested amount out of the float — so a refund of dust is a small, real cost to the operator,
and an unbounded one if a stranger sends a hundred one-piconero transfers and asks for a
hundred refunds. (This ADR also corrects `docs/PAYMENTS.md`, which claimed the fee was
deducted from the amount withdrawn. The code never did that; the sentence was wrong.)

**Decision.** `POST /api/wallet/refunds` takes an address and returns everything below the
minimum to it, as one payout in the ordinary queue.

- **It is not a new kind of money movement.** A refund is the moment those deposits are
  *finally credited* — one `deposit` ledger entry per row, each naming its deposit — and
  immediately held for a payout. Both halves are one transaction, so there is no instant in
  which the money is spendable and no crash that credits without queueing (`lib/refunds.ts`).
- **Claim first, credit second.** `UPDATE deposits SET status = 'credited' … WHERE status =
  'below_minimum' RETURNING` takes the rows before anything is written, so two requests racing
  produce one refund and one `nothing_to_refund` rather than the same dust sent twice.
- **All of it, or none.** The fee is per transfer, so refunding in instalments is worse for
  both sides. Under `MIN_REFUND_XMR` (default 0.001 — about twenty network fees) the whole
  transaction rolls back and the screen says what it is waiting for: an honest "not yet" beats
  a refund that costs the float more than it returns.
- **It is a payout, so every payout rule applies**: one pending payout per account, the
  account's automatic ceiling (a payer of a hundred small transfers can exceed it, and then a
  human approves it), the destination stored only until the transfer is sent, and the sending
  done by a process this server cannot reach (ADR-0070).
- **Uncredited dust is a liability and now says so.** `solvency()` and
  `GET /api/admin/treasury` count it (`uncreditedTopUpsXmr`): it sits in the wallet, it is owed
  to whoever sent it, and leaving it out reported a surplus exactly the size of that debt.

**Rejected:** crediting below-minimum top-ups to the spendable balance on request (it makes the
minimum a suggestion — a payer could fund an account entirely in dust and buy with it);
deducting the network fee from the refunded amount via `subtract_fee_from_outputs` (correct in
principle, but it puts an RPC parameter this repository has never run on the path where money
leaves, and `MIN_REFUND_XMR` buys the same protection with arithmetic already tested); a
per-account refund cooldown (the floor already makes dust-spam uneconomic for the spammer:
they lose the dust and the platform loses one fee); refunding automatically to nowhere (there
is no address to refund *to* — that is the whole problem).

**Consequences.** Dust stops being a support queue, and the treasury number gets slightly
worse and considerably more honest. What is still manual is the case below the floor: a payer
who sent 0.0002 XMR once and never returns has money on this platform that only an operator
can move, and the wallet screen says so in those words rather than implying it will be
returned.
