# Primary sources, and how much weight each one carries

Point 103. Nothing load-bearing in this project rests on recollection, a blog post or a
vendor's description of its own product. Every cryptographic construction here comes from a
published specification, and this page is the bibliography: what the source is, what depends
on it, and how we know the code agrees with it.

It exists for two reasons. An external reviewer (`docs/EXTERNAL_REVIEW.md`) should not have to
reverse-engineer which document we were reading. And a later change that quietly departs from
a specification should be visible as a change to this page, not as a subtle difference nobody
notices.

## What the code implements, and from where

| Construction | Primary source | Where it is used | How the agreement is checked |
| --- | --- | --- | --- |
| X25519 key agreement | RFC 7748 | Every handshake and ratchet step (`src/shared/crypto/`) | libsodium's implementation; `test/cryptography.test.ts` runs RFC 7748 §6.1 |
| Ed25519 signatures | RFC 8032 | Identity keys, prekey signatures, recovery signatures | libsodium; property tests over sign/verify, forgery and tampering |
| ChaCha20-Poly1305 | RFC 8439 | The AEAD, in its XChaCha20 extended-nonce form | libsodium; `test/cryptography.test.ts` runs RFC 8439 §2.8.2 |
| XChaCha20 extended nonce | draft-irtf-cfrg-xchacha (CFRG draft, stable and widely deployed) | 24-byte nonces, so random nonces are safe without a counter | libsodium `crypto_aead_xchacha20poly1305_ietf_*`; nonce uniqueness is property-tested |
| BLAKE2b | RFC 7693 | Fingerprints, safety numbers, key derivation inputs | libsodium `crypto_generichash` |
| HMAC-SHA256 | RFC 2104, FIPS 198-1 | The HKDF core | libsodium `crypto_auth_hmacsha256` |
| HKDF-SHA256 | RFC 5869 | Every key separation in the protocol | Written here (libsodium's JS wrapper does not export it) and checked against RFC 5869 appendix A.1–A.3 in `test/hkdf.test.ts` |
| Argon2id | RFC 9106 | Password → auth secret ‖ vault key, in the browser | libsodium `crypto_pwhash` with the moderate parameter set |
| scrypt | RFC 7914 | The server-side hash of the auth secret | Node standard library, N=2¹⁵ r=8 p=1 |
| BIP-39 mnemonics | BIP-39 (bitcoin/bips) | Recovery phrases | Our encoder against the specification's own wordlist and checksum rule; cross-checked in tests against `@scure/bip39` (a dev dependency only) |
| X3DH | Signal's X3DH specification | Session establishment | Composed here; deviations are listed in `docs/CRYPTO.md` §"Session establishment" and are the first thing an external review is asked to look at |
| Double Ratchet, with header encryption | Signal's Double Ratchet specification, §"Header encryption" | Message encryption | Composed here; `test/protocol.test.ts` covers out-of-order, replay, skipped keys and a break-in recovery |
| OpenPGP signatures | RFC 4880 | Optional second factor | OpenPGP.js, server-side only, never in the client bundle |
| Onion service v3 addresses | Tor rend-spec-v3 | Validating `ONION_HOSTNAME` and advertising the service to Tor Browser | The v3 format is required at boot; `test/onion.test.ts` refuses a malformed address rather than emitting a broken header |
| Cookie attributes (`Secure`, `HttpOnly`, `SameSite=Strict`) | RFC 6265bis | Session and CSRF cookies | `test/sessions.test.ts`, `test/defaults.test.ts`, and `test/onion.test.ts` for the one host where `Secure` cannot apply |
| Content Security Policy Level 3 | W3C CSP3 | The response headers | `test/hardening.test.ts` asserts the exact policy |
| Monero amounts, subaddresses and integrated addresses | Monero documentation (`docs.getmonero.org`: public addresses, integrated addresses, technical specifications) | Piconero as the stored unit, and the per-order subaddress design in `docs/PAYMENTS.md` | `test/payments.test.ts` checks the unit arithmetic and the schema; the address design is not yet code |
| Monero wallet and daemon RPC | Monero developer guides (`wallet-rpc`), `monerod` reference and `docs/ZMQ.md` in monero-project/monero | Which calls a gateway may use — `create_address`, `get_transfers` — and the absence of any WebSocket interface (ADR-0065) | Design only; no code depends on it yet |
| JPEG segment structure (SOI, APPn, COM, SOS) | ITU-T T.81 / JFIF (ECMA TR/98) | Which segments the metadata stripper may drop (`src/shared/media.ts`, ADR-0092) | `test/uploads.test.ts` builds a file per rule and asserts what survives |
| PNG chunk structure and the ancillary chunks a decoder needs | W3C/ISO PNG (Third Edition), including `eXIf` | The keep-list in the stripper: critical chunks, display chunks, animation chunks | Same suite |
| RIFF container and the WebP `EXIF`/`XMP ` chunks | Google WebP container specification | The two chunks removed, and the RIFF length rewritten after removal | Same suite |
| ISO base media box structure, `udta`, `mvhd`/`tkhd`/`mdhd` timestamps | ISO/IEC 14496-12 | The box walk and the video metadata cleared in place (`src/shared/isobmff.ts`, ADR-0109) | `test/isobmff.test.ts` builds a HEIC and an MP4 byte by byte and asserts what is zeroed and what survives |
| HEIF item structure (`meta`, `iinf`/`infe`, `iloc`, `idat`) and the `Exif`/`mime` item types | ISO/IEC 23008-12 | How a still image's Exif and XMP items are located and zeroed without moving the coded image | Same suite |
| File upload handling | OWASP File Upload Cheat Sheet | The upload checks that are possible on ciphertext: authorisation, size in decoded bytes, no client-controlled path or name, storage outside any webroot (`docs/STORAGE.md`) | `test/uploads.test.ts`, `test/limits.test.ts` |
| Monero spendable age (10 blocks) and ~2-minute block target | Monero technical specifications, `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE` | The confirmation policy in `docs/PAYMENTS.md`: "paid" and "spendable" are different moments | Design only |

Two rules follow from this table and are not negotiable (point 104): **primitives are never
written here** — every one of them comes from libsodium or the Node standard library
(ADR-0003, ADR-0012) — and **compositions follow a published specification** or they do not
ship. HKDF is the single exception to the first rule, for the reason in the table, and it is
the only file in the project checked line by line against an RFC's own vectors.

One specification appears in this repository without being used: **RFC 7519** (JSON Web
Tokens), whose example token is one of the audit fixtures in `docs/AUDIT.md`. There are no
JWTs here — sessions are opaque random tokens, stored as a SHA-256 hash (`src/server/lib/sessions.ts`, ADR-0038) — and the mention is
listed so that a search for it does not suggest otherwise.

## What we believe, labelled

Point 103 asks for the difference between what is known and what is assumed to be kept
visible. Applied to the load-bearing beliefs of this system:

| | Statement |
| --- | --- |
| **FACT** | libsodium is the audited reference implementation of these primitives, and the WASM here is built from that C source. |
| **FACT** | HKDF, X25519 and ChaCha20-Poly1305 in this repository reproduce their specifications' published test vectors — the test names the section. |
| **FACT** | The server never receives a password, a master key or a message body in the clear; `test/security.test.ts` dumps every table and fails if known plaintext appears. |
| **ASSUMPTION** | The operating system's CSPRNG is sound. Everything random here comes from it via `randombytes_buf`; nothing in this project can detect a compromised one. |
| **ASSUMPTION** | The browser executes the bundle it was served, and the device is not already compromised. Both are outside what any server-delivered client can verify. |
| **ASSUMPTION** | The X3DH and Double Ratchet compositions written here are faithful to their specifications. The tests support this; only an external review can establish it (`docs/EXTERNAL_REVIEW.md`). |
| **DESIGN CHOICE** | Ed25519 identity keys converted to X25519 for agreement, rather than two key pairs — standard, supported by libsodium, and it halves what a user must verify. |
| **DESIGN CHOICE** | Argon2id in the browser rather than on the server: the server never sees material it could crack offline, at the cost of a second of the user's CPU. |
| **DESIGN CHOICE** | One VPS, SQLite by default, PostgreSQL behind a small interface. Availability is traded for a surface one person can audit (ADR-0005). |
| **RISK** | The handshake is classical-only; traffic recorded today may be readable by a future quantum adversary (roadmap PQ-1). |
| **RISK** | The operator serves the client code, so a targeted bundle is possible; reproducible builds and a published digest make it detectable, not impossible. |
| **UNKNOWN** | Whether the composed protocol has a flaw a specialist would see in an afternoon. Nobody outside this project has read it. |
| **UNKNOWN** | How the system behaves under real load on real hardware: the numbers in `docs/PERFORMANCE.md` come from a development machine and a synthetic run. |

If a future change makes one of these lines false, the change is not finished until the line
is corrected. That is the entire point of writing them down.
