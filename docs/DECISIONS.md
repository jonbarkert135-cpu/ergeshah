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

