# Brief for an external cryptographic review

This page exists to be sent to a reviewer. It says what to look at, in what order, what has
already been checked by machine, and which questions this project cannot answer about
itself. It is the standing answer to roadmap item **CRY-1** and to finding 7 in
`docs/SELF_CRITIQUE.md` — the highest-severity open item here, and the one thing on the list
that effort inside the project cannot close.

Nothing about the codebase needs to change before a review starts. It is small on purpose:
the cryptography is about **1,400 lines** of TypeScript, no framework, four runtime
dependencies, and every primitive comes from libsodium or the Node standard library.

## What we are asking

**Not** "is this secure?" — that question has no answer worth paying for. Five specific ones:

1. **Does the handshake bind what it claims to bind?** X3DH here derives from a published
   specification, but the transcript, the identity keys and the prekey signature are
   composed by us. Is there an identity-misbinding or unknown-key-share path?
2. **Is the ratchet correct at its edges?** Out-of-order delivery, skipped-key storage and
   its bound, a header key that rotates on a DH ratchet step, and what happens when the same
   header key decrypts two different headers.
3. **Is any nonce reused, ever?** Across a rekey, across a restart, across the vault's
   re-wrap, across attachment and delivery encryption.
4. **Is the vault's key hierarchy sound?** A random master key wrapped three ways — password,
   recovery phrase, second device — with Argon2id parameters chosen for a browser. Does any
   wrapping route weaken another, and does revoking one revoke what it should?
5. **Where is a downgrade possible?** Between protocol versions, between the encrypted-header
   and legacy formats, in the PGP and recovery-phrase login paths that bypass the password.

An answer of "we found nothing in area 3" is a useful answer. An answer of "this is fine" is
not, and we would rather have the four findings than the sentence.

## Where to look, in order

| Order | Files | Lines | Why it is first |
| --- | --- | --- | --- |
| 1 | `src/shared/crypto/ratchet.ts` | 585 | The largest piece of composition, and the one with state |
| 2 | `src/shared/crypto/x3dh.ts`, `session.ts` | 180 | The handshake and the session it produces |
| 3 | `src/shared/crypto/vault.ts`, `identity.ts` | 375 | Key hierarchy, wrapping, device identity |
| 4 | `src/shared/crypto/hkdf.ts`, `aead.ts`, `padding.ts` | 145 | Thin wrappers; wrong parameters would be invisible elsewhere |
| 5 | `src/shared/crypto/mnemonic.ts` | 105 | BIP-39, our own implementation of a published standard |
| 6 | `src/server/routes/keys.ts`, `auth.ts`, `recovery.ts` | ~900 | The server's side: what it will hand out, and to whom |

Read alongside: `docs/CRYPTO.md` (the assumptions, stated), `docs/THREAT_MODEL.md` (what is
in and out of scope by design), `docs/PRIVACY.md` (what the server stores), and
`docs/DECISIONS.md` (60 records; ADR-0003, 0011, 0012, 0014, 0035 and 0060 are the
cryptographic ones).

## What is already checked by machine, so you need not

Every push runs 468 tests and seven audits (`docs/AUDIT.md`, `docs/TESTING.md`), including:

- published test vectors for HKDF, BIP-39 and the AEAD, plus an independent BIP-39
  implementation cross-check;
- ratchet properties: forward secrecy, out-of-order delivery, replay refusal, corrupted
  ciphertext, wrong key, wrong identity, session reset (`test/cryptography.test.ts`, nine
  failure kinds);
- a sweep asserting no plaintext appears in any database column;
- the whole suite against both database drivers.

These are necessary and not sufficient, which is the sentence this brief exists to fix: they
were written by the same people who wrote the code, so they cannot catch a mistake in the
reasoning, only in the execution.

## Known weaknesses — you do not need to find these

Stated up front so that review time is not spent rediscovering them:

- No post-quantum handshake yet (roadmap PQ-1), blocked on an audited browser-capable
  ML-KEM. "Harvest now, decrypt later" applies.
- An attachment can be fetched by any authenticated account that knows its 192-bit id
  (`docs/SELF_CRITIQUE.md`, finding 4) — a deliberate trade against keeping a recipient
  column.
- The server can see who talks to whom at the transport level; the schema does not record it
  (`docs/METADATA.md`).
- Metrics are in memory and lost on restart (finding 6).

## Out of scope

Front-end design, marketplace business logic, dependency CVEs (checked on every push),
infrastructure and the hosting provider, and legal or compliance questions.

## How to run it

Node 22, `npm ci`, then `npm run check && npm test && npm run audit`. The full suite takes
about twenty seconds; PostgreSQL variant in `docs/TESTING.md`. No account, no service and no
network access is needed — the tests start real servers on in-memory databases.

## What we will provide

Read access to the repository (the source is closed — `LICENSE`), this brief, the documents
listed above, and answers in writing. We will publish the summary of any review, including
findings we do not fix and why, in `docs/SELF_CRITIQUE.md`.

## What we would like back

A written report per finding: what, where, severity, exploit path, and the recommendation.
Reproduction that fits in a test we can add to the suite is worth more to us than a longer
prose description — the fix and the regression test go into the same commit here.
