# Security policy

This page is the map: what this software assumes, what it protects, what it does not, and
how to report a hole in it. Each section is a summary with a link to the document that
carries the detail — the detail is machine-checked against the code, and this page is not.

## Threat model

Who we defend against, and how far: `docs/THREAT_MODEL.md`. It is the contract. Every
security statement in this repository is only valid in the terms defined there, and
anything not listed as mitigated is a residual risk.

The short version. A **network attacker** sees TLS (or an onion circuit) and, inside it,
content that is already end-to-end encrypted; they still see timing and volume. A
**compromised server or stolen database** yields ciphertext, password hashes and
marketplace records — not message plaintext, because the keys that would decrypt it never
exist on the server. A **hostile server serving modified client JavaScript** is not
defended against, and that is the single largest residual risk. A **compromised device**
reads its owner's messages, as it always does.

## Security assumptions

- The user's device and browser are trusted. If they are not, nothing below matters.
- The network is hostile: passive observation, active MITM and injection are assumed.
- The operator's proxy is the only component that sees client addresses, and the operator
  is the same person who runs the application.
- The database is not trusted with anything that could decrypt a message.
- Users who care about impersonation compare safety numbers out of band. Identity is
  trust-on-first-use until they do.

## Cryptographic architecture

`docs/CRYPTO.md`, with the composition reviewed in `docs/SECURITY_REVIEW.md`.

X3DH (X25519, HKDF-SHA256) establishes a session; a Double Ratchet with **encrypted
headers** carries it, so the ratchet key and the counters are not visible to the server.
Messages are XChaCha20-Poly1305, one key per message from a one-way chain, nonces derived
from the message key rather than counted, plaintext padded into size buckets. The client
vault is sealed with a random master key, which is wrapped once under a key derived from
the password (Argon2id) and once under a key derived from the recovery phrase — the server
holds both wrapped copies and can open neither. Known-answer, negative, malformed-input,
replay, corrupted-ciphertext, wrong-key, wrong-identity, nonce and session-reset tests live
in `test/cryptography.test.ts` and `test/protocol.test.ts`.

## Authentication model

The server never sees a password. The client stretches it with Argon2id and splits the
result: one half is the `authSecret` sent to the server (hashed again with scrypt before
storage), the other never leaves the device. Sessions are opaque random tokens stored only
as SHA-256 hashes, in `HttpOnly; SameSite=Strict` cookies, with a CSRF double-submit token
and an Origin/Host check on every unsafe request. Optional second factor: a PGP key,
proved by signature. Optional recovery: a BIP-39 phrase that restores the vault's contents,
not merely access. Roles are read from the database on every request, so a demotion or a
suspension takes effect immediately. Details: `docs/API.md`, `docs/ARCHITECTURE.md`.

## Privacy model

`docs/PRIVACY.md` justifies every stored field. No access log, no addresses (rate limits
are daily-rotating HMACs), no sender column on an envelope, no read receipts, no typing
indicators, no "who is online", day-granular timestamps wherever a day is enough, and a
notification that says something arrived without saying what, from whom, or how much.
Retention is a configuration value for every table that grows.

## Known limitations

- Not anonymous, not unbreakable, not free of metadata: connection timing, message timing
  and message size buckets remain observable.
- The handshake is classical X25519 — harvest-now-decrypt-later is a real risk, and a
  hybrid post-quantum handshake is a roadmap item, not a shipped feature.
- A web client cannot defend against its own server serving modified code.
- No external audit has been performed. `docs/SECURITY_REVIEW.md` is a self-review, and it
  says what it did not cover: no fuzzing, no PostgreSQL job in CI, no browser end-to-end
  run, no load test.

## Deployment hardening

`docs/DEPLOYMENT.md`. One VPS, Docker, Caddy for TLS, optional Tor onion service. The
application container has no route to the internet, runs read-only with capabilities
dropped, binds to localhost by default and refuses to start in production without its
secret. Backups are encrypted with a key the running service does not hold, and they
expire (`docs/BACKUPS.md`). The client build is reproducible and its digests are published
at `/build.txt`, so an operator can check that the deployment serves what the source
builds (`npm run audit:deployment`).

## Incident response

`docs/INCIDENT_RESPONSE.md` — procedures for credential rotation, session revocation, a
compromised server, a database breach, a dependency vulnerability and a key compromise,
with the commands they need (`scripts/incident.mjs`, exercised by `test/incident.test.ts`).

## Reporting a vulnerability

Report privately, not in a public issue. Open a GitHub *security advisory* on this
repository (Security → Advisories → Report a vulnerability). Include:

- affected component and version/commit,
- reproduction steps or a proof of concept,
- the impact you believe it has,
- whether the issue is already public.

Please do not run automated scanners, load tests, or account-enumeration attempts
against a deployment you do not own.

**In scope:** authentication, session handling, authorization/IDOR, the cryptographic
protocol and its implementation, metadata leaks beyond what `docs/THREAT_MODEL.md` already
documents, injection, SSRF, supply-chain issues in our dependency set.

**Out of scope:** findings that only restate a *documented* residual risk in
`docs/THREAT_MODEL.md`, missing hardening that has no attack path, self-XSS, and issues in
third-party infrastructure of a specific deployment.

### Working without the source

This software is proprietary, so a researcher has the deployed client, the network, and the
API — not the code. Black-box findings are welcome on exactly the same terms as any other,
and if a report needs source access to be conclusive, say so in the report and we will
arrange it under an agreement rather than leave the issue unexamined.

### What we will not claim

We do not claim anonymity, unbreakability, or complete metadata protection. Security
statements in this repository are tied to a written threat model, and a report that
narrows the gap between that model and reality is always welcome.
