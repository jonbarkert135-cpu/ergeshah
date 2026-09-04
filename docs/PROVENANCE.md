# Provenance: where code here came from

Points 143–148. Nothing in this repository was pasted from a search result. That is a claim
worth making concrete, because "we adapted a pattern from an open-source project" is where
licence obligations and unreviewed code enter a codebase, and neither arrives with a label.

Three pages divide the work: `THIRD_PARTY.md` lists the dependencies and their obligations,
`docs/SOURCES.md` lists the specifications the cryptography implements, and this page is the
register point 146 asks for — every borrowed or substantially adapted implementation, with its
source, licence, version, purpose, modifications and security review.

## The register

| Component | Source | Licence | Version | Purpose | Modifications | Security review |
| --- | --- | --- | --- | --- | --- | --- |
| HKDF-SHA256 (`src/shared/crypto/hkdf.ts`) | RFC 5869, written from the specification (libsodium's JS wrapper exports no HKDF) | the RFC is a specification, not code — no licence attaches | RFC 5869 (2010) | key separation for every protocol step | none: extract-and-expand as written, over libsodium's HMAC-SHA256 | `test/hkdf.test.ts` runs appendix A.1–A.3 vectors; the only hand-written primitive here, and it is reviewed line by line against the RFC (`docs/SOURCES.md`) |
| BIP-39 word list (`src/shared/crypto/bip39-wordlist.ts`) | bitcoin/bips, `bip-0039/english.txt` | public domain per BIP-39 (BIP text is CC0/2-clause; the list is data fixed by the standard) | BIP-39 English, 2048 words | recovery phrases | none — the file is the list, unsorted and unedited, so it can be diffed against the standard | cross-checked against `@scure/bip39` (MIT, dev dependency) in `test/recovery.test.ts`; the encoder is ours |
| QR encoder (`src/shared/qr.ts`) | ISO/IEC 18004 (QR Code specification), byte mode, written here | specification | ISO/IEC 18004:2015, version 1–10, level M | device linking and safety numbers without a runtime dependency (ADR-0020) | encoder only — no decoder, one mode, no Kanji, no micro-QR | decoded in tests by `jsqr` (Apache-2.0, dev dependency) to prove the output is a real QR code |
| ISO 7816-4 padding (`src/shared/crypto/padding.ts`) | ISO/IEC 7816-4 padding scheme | specification | — | length hiding for plaintexts (ADR-0011) | fixed bucket sizes chosen here; the padding scheme itself is unmodified | `test/padding.test.ts`, plus the fuzz corpus in `test/fuzz.test.ts` |
| X3DH and the Double Ratchet (`src/shared/crypto/x3dh.ts`, `ratchet.ts`) | Signal's published X3DH and Double Ratchet specifications | specifications, freely published; no Signal code is used | X3DH r2, Double Ratchet r2 (with header encryption) | session establishment and message encryption | deviations are listed in `docs/CRYPTO.md`; header encryption is the specification's own variant | `test/protocol.test.ts` (out-of-order, replay, skipped keys, break-in recovery). Composition, not primitives — the part `docs/EXTERNAL_REVIEW.md` asks a reviewer to read first |
| Every primitive (X25519, Ed25519, XChaCha20-Poly1305, BLAKE2b, Argon2id, HMAC) | libsodium, via `libsodium-wrappers-sumo` | ISC | 0.7.15, pinned (ADR-0004) | all cryptography | none — used as published, never patched | upstream audits plus RFC vectors in `test/cryptography.test.ts` |
| `fastify`, `pg`, `openpgp` | npm registry, unmodified | MIT, MIT, LGPL-3.0+ | as pinned in `package-lock.json` with integrity hashes | HTTP server, PostgreSQL driver, PGP signature verification | none — patching `openpgp` would make the patch LGPL source we must publish (`THIRD_PARTY.md`) | `npm run audit:dependencies` (budget, licences), `audit:supply` (pinning, install scripts), `audit:inventory` (the freeze) |

## The rules this register enforces

**Never copy blindly (point 144).** The sequence is search → understand → compare → verify →
adapt → test → security review → commit. A snippet that cannot be explained line by line is not
adapted, it is imported, and imports go through the dependency gate below.

**Prefer the mature thing (points 145, 180).** In order: a standardised construction, an
audited library, an official implementation, a well-maintained project, and only then code
written here. This project's own rule is stricter for cryptography — primitives always come
from libsodium or the Node standard library, and what is written here is composition
(`docs/CHANGE_REVIEW.md` §4). "The most powerful code" is never the criterion; the criterion
is which solution fits *this* threat with the least new surface.

**Licence gate (point 147).** Before any code is used: the licence, its compatibility with a
proprietary product (ADR-0022), redistribution conditions, copyleft reach, attribution. An
unknown licence means the code is not imported — there is no "probably fine". Anything
AGPL/GPL is out of the question for this tree; LGPL is acceptable only as an unmodified,
replaceable dependency, which is exactly the `openpgp` arrangement and why it is documented.

**Dependency gate (point 148).** Security history, maintenance, licence, privacy (does it phone
home), size, network behaviour, and necessity — in that order, and the last question is the one
that usually ends it. Four runtime dependencies is a budget, not an accident
(`docs/DEPENDENCIES.md`, ADR-0010): if a task can be done safely without a new package, it is.
Every dev dependency added for verification — `@scure/bip39`, `jsqr` — exists to check our own
code and stays a dev dependency, which `npm run audit:dependencies` enforces.

**Research sources, in the order they carry weight (points 142, 143).** Primary source
(specification, RFC) → official repository → official documentation → reputable security
research (OWASP, NIST, a vendor advisory, an academic paper) → community source. A blog post is
never the sole basis for a security decision; if it is the only reference, the decision waits.
When a candidate implementation is evaluated, the comparison is written down: maturity,
maintenance, licence, known vulnerabilities, dependency tree, and architectural fit
(`docs/DECISIONS.md` is where the conclusion lands — ADR-0075 and ADR-0098 are two examples of
patterns from other projects being taken, reshaped or refused).
