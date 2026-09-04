# Security review loop

Point 55 asks for ten review passes before every large milestone. This file is the record
of them: what each pass looked at, what it found, and where the regression test lives. A
finding with no test is not closed — it is a memory, and memories are how the same bug
ships twice.

Findings are numbered per review round. Severity is about *this* system: **high** = message
plaintext, vaults or accounts at risk; **medium** = access control, availability of the
service, or a control that does not do what it claims; **low** = defence in depth, honesty
of an interface, or a documentation control.

## Round 1 — milestone "points 52–62" (2026-09-03)

Reviewed: everything under `src/`, `scripts/`, `deploy/` and `docs/` at commit `ec63857`.

| # | Pass | Finding | Severity | Status |
| --- | --- | --- | --- | --- |
| R-01 | 4 Code | Two concurrent requests could nest their SQLite transactions: the second `BEGIN` failed (500) and, worse, statements from both requests shared one transaction — a rollback in one could discard the other's writes | medium | **fixed** — transactions are queued per connection (`src/server/db/sqlite.ts`, ADR-0036); `test/security.test.ts` "never hands the same one-time prekey to two callers at once" now asserts four concurrent bundle fetches all answer 200 |
| R-02 | 2 Threat model | Device revocation was reversible: re-publishing the same identity key cleared `revoked_at`, so a stolen device that still held its identity key could put itself back into every prekey bundle | medium | **fixed** — a revoked identity key is refused for good (`routes/keys.ts`, ADR-0035); `test/security.test.ts` "never resurrects a revoked device" |
| R-03 | 2 Threat model | `GET /api/keys/bundle/:username` consumes one one-time prekey per device per call and was limited by the generous `read` bucket (240 burst): any account could drain another account's prekeys in seconds, forcing new sessions onto the signed prekey alone | medium | **fixed** — its own `key_bundle` bucket, 30 burst / 10 per minute (ADR-0035); `test/security.test.ts` "stops one account draining another account's one-time prekeys" |
| R-04 | 7 UX | `POST /api/auth/logout-everywhere` existed with no way to reach it in the client, and the revoke-device dialog implied that revoking ended the device's sessions. The stolen-device story was therefore *possible* and *undiscoverable* | medium | **fixed** — "Sign out everywhere" in the account view, corrected dialog copy, and the pairing written down in `INCIDENT_RESPONSE.md` §2 |
| R-05 | 4 Code | Single-line fields (device label, seller display name, listing title, category) accepted CR and LF: a display name could span lines, push text out of a card and read differently to a moderator than to a buyer | low | **fixed** — `asString` is single-line, prose fields opt in via `asText` (`lib/validate.ts`); `test/security.test.ts` "refuses a line break in a single-line field" |
| R-06 | 4 Code | `POST /api/messages/ack` reported the number of ids *submitted*, not the number of envelopes deleted — an interface that overstates what happened | low | **fixed** — `DELETE … RETURNING id` (`routes/messages.ts`) |
| R-07 | 4 Code / docs | `docs/API.md` described CSRF as a required `X-Requested-With: symvolon` header. The server actually checks Origin against Host and a double-submit `X-CSRF-Token`. Drifted documentation of a security control is a control nobody can review | low | **fixed** — API.md now describes what `security.ts` does; `test/security.test.ts` sweeps every unsafe route with no token |
| R-08 | 3 Cryptography | `ratchet.ts` cited `test/ratchet.test.ts`, which does not exist (the tests are in `protocol.test.ts` and now `cryptography.test.ts`) | low | **fixed** |
| R-09 | 6 Performance | The notification inbox orders by `created_at DESC, id DESC`; two notifications written in the same millisecond therefore have no stable order. Product behaviour is acceptable (a millisecond is not a meaningful ordering to a reader), but a test depended on it and failed under load | low | **accepted**, test made deterministic (`test/notifications.test.ts`) |
| R-10 | 5 Privacy | `POST /api/auth/recovery/challenge` returns a challenge for every username, but only writes a row when the account exists *and* has a recovery key. The difference is measurable as latency: a timing oracle for "does this account have recovery configured" | low | **fixed (2026-09-03, point 70)** — it turned out no schema change was needed: `auth_challenges.user_id` was already nullable, so the endpoint now writes a decoy row with a null `user_id` for names nobody registered, and does the same work either way. `POST /api/auth/recovery/complete` verifies the signature against a fixed unusable key for a decoy, so that path is constant-work too, and every way of failing returns one message. `test/antiautomation.test.ts` and `test/recovery.test.ts` cover both. The earlier assessment ("needs a schema change") was wrong about the schema, which is a lesson about checking the column before pricing the fix |

### What each pass actually did

**PASS 1 — Architecture.** Re-read `ARCHITECTURE.md` against `src/`. The module boundaries
hold (`test/architecture.test.ts` proves it mechanically). One conceptual gap: *revocation*
lived in two domains — IDENTITY revokes devices, AUTH revokes sessions — with nothing
saying that an operator needs both. That is R-02/R-04, and it is why the incident procedure
now names both commands in one block.

**PASS 2 — Threat model.** Attacked the system as a hostile *account*, which is the cheapest
attacker to be: drain someone's prekeys (R-03), un-revoke a device (R-02), claim another
account's identity key (already refused), acknowledge someone else's envelopes (refused,
now tested), mark someone else's notifications read (refused), move someone else's order
(refused). Two of six worked; both are fixed.

**PASS 3 — Cryptography.** Reviewed the composition, not the primitives: X3DH derives the
root key and, with two distinct labels, the two initial header keys; the Double Ratchet
seals the header under those keys and uses the sealed header as the AEAD's associated
data, so a ciphertext cannot be lifted into another envelope; message keys come from a
one-way chain and each is used once; nonces are derived from the message key, never
counted. Low-order public keys are refused by libsodium rather than silently producing a
zero shared secret — now pinned by a test instead of assumed. No change was needed; the
new coverage is `test/cryptography.test.ts` (published vectors, wrong keys, wrong
identities, corrupted ciphertext, replay, session reset).

**PASS 4 — Code.** Read every route and library file. Findings R-01, R-05, R-06, R-07,
R-08. R-01 is the one that mattered: it was invisible in single-request tests and appeared
the moment four requests arrived together.

**PASS 5 — Privacy.** Walked every column a request can write. No new metadata leaks: the
new `key_bundle` bucket stores an HMAC like every other bucket, and the incident tooling
writes nothing at all. R-10 is the one measurable side channel found, and it is documented
rather than hidden.

**PASS 6 — Performance.** The serialisation in R-01 makes writes strictly sequential on
SQLite — which they already were, since SQLite has one writer; the queue only makes the
waiting explicit instead of an error. Reads are unaffected. The `key_bundle` limit adds one
bucket row per caller per day. R-09 is the only ordering artefact found.

**PASS 7 — UX.** R-04. Also checked that no security control is a setting a user can turn
off (`test/defaults.test.ts`), and that the account view now explains the difference
between revoking a device and ending its sessions in the words a person would use.

**PASS 8 — Deployment.** `deploy/docker-compose.yml` unchanged: no egress, read-only
container, dropped capabilities, database in a named volume. One operational note that was
missing: `scripts/incident.mjs` runs **on the host**, against the database file, and is not
part of the read-only container image — that is deliberate (a break-glass tool inside the
service would be a backdoor with a nice name) and is now written in `DEPLOYMENT.md`.

**PASS 9 — Supply chain.** Four runtime dependencies, all pinned by the lockfile;
`npm run audit:deps`, `audit:supply` and `audit:dependencies` are clean. Nothing was added
in this milestone: the incident tool uses `node:sqlite`, and the new tests use what is
already installed.

**PASS 10 — Adversarial.** Given the source and an account, the sharpest remaining attacks
are the ones the threat model already names and this round did not change: a malicious
*server* serving modified client JavaScript (unmitigated by design), traffic analysis
against message timing and size buckets, and a compromised endpoint. Everything else found
in this round is in the table above.

## What this review is not

It is not an external audit, and nothing here was fuzzed. There is no PostgreSQL job in CI
(so R-01's PostgreSQL path is reasoned about, not exercised), no browser-level end-to-end
run, and no load test — so the availability claims are arguments, not measurements. Those
gaps are listed in `TESTING.md` and `ROADMAP.md`, and they are the honest boundary of what
"reviewed" means here.

## Round 2 — milestone "privacy-first account, recovery and PGP authentication" (2026-09-04)

Reviewed: the whole authentication surface — `routes/auth.ts`, `routes/recovery.ts`,
`lib/auth_flow.ts`, `lib/sessions.ts`, `lib/pgp.ts`, `lib/password.ts`, the client's account
and security screens, and the schema behind all of it — against a brief that asked for a
minimum-identity account, cryptographic recovery, and PGP as a real authentication factor.

Most of the brief was already the design: no email or phone column exists, identifiers are
random UUIDs, the phrase is generated in the browser from the OS CSPRNG and never sent, the
server holds only public halves, and no administrator override exists anywhere. What follows
is what this pass found that was *not* right.

| # | Pass | Finding | Severity | Status |
| --- | --- | --- | --- | --- |
| R-11 | 2 Threat model | The second factor could be removed, or replaced with an attacker's key, on a session plus the password alone. Against the exact attacker PGP exists to stop — someone who has the password — the factor was one request from being switched off | **high** | **fixed** — ADR-0088: replacing a key needs a signature from the key being replaced, removing one needs a signature from the key being removed; `test/pgp.test.ts` "needs a signature from the key being replaced" and "takes the factor off only for someone who can sign with the key being removed" |
| R-12 | 3 Cryptography | Challenges were bare random nonces. Nothing in the signed bytes said which service asked, what the signature authorised, or when it expired — so the separation between "sign in", "add a key" and "remove a key" was the server's bookkeeping rather than the signature's meaning, and a user pasting bytes into `gpg` could not see what they were agreeing to | medium | **fixed** — ADR-0087: a one-line statement with protocol version, `SERVICE_ID`, purpose, challenge id, expiry and nonce, stored whole and verified as stored; pinned by `test/pgp.test.ts` "names the protocol, the service, the purpose, the challenge and its expiry" |
| R-13 | 4 Code | A recovery and a password change ended every session and left the *other* two session-minting credentials alive: a pending authentication challenge, and a parked device-link code. After a recovery those are precisely what an attacker who caused it would still hold | medium | **fixed** — ADR-0089: `revokeAllCredentials()` deletes sessions, challenges and device links in one transaction; `test/security_center.test.ts` "takes the sessions, the pending challenges and the parked device codes with it" |
| R-14 | 7 UX | An account had no way to notice anything: a stranger could sign in with a stolen password (on an account without PGP) and the owner would never see a trace, because the only log in the system records staff actions | medium | **fixed** — ADR-0090: `security_events`, a count per kind per day, owner-only, ninety-day retention, surfaced in the new security centre |
| R-15 | 6 Performance / tests | `test/evidence.test.ts` compared a commitment against a dispute that could land in the same millisecond, and the rule counts a tie as "before". A flaky assertion about a real property | low | **fixed** — both rows are aged explicitly, so the ordering under test is the one the test describes |
| R-16 | 5 Privacy | The new history is itself data at rest: a database dump now shows, per account, that a sign-in happened on a given day. Considered and accepted — day granularity, no address, no time of day, no session or device id, a counter instead of a timeline, ninety-day expiry, and it exists so the *account* can see an intrusion the operator would otherwise be the only one to notice | low | **accepted**, recorded in `docs/PRIVACY.md` and ADR-0090 |
| R-17 | 4 Code | Unspent send tokens survive a recovery, because the table deliberately has no owner column (ADR-0084) | low | **accepted** — stated in ADR-0089 rather than quietly left: a stolen token can post an envelope until it expires, cannot read anything, and cannot become a session |

### The adversarial pass, by starting point

The brief asked for eight scenarios. `docs/THREAT_MODEL.md` §"What an attacker gets, per
starting point" is the maintained version of this table; the delta this milestone made:

* **Username + password, PGP enrolled.** Unchanged at the front door (challenge, no session);
  now also unchanged *behind* it — the factor can no longer be removed or swapped without the
  key (R-11).
* **A stolen session.** Same as before, plus one new read: the account's own coarse security
  history. It cannot change the password, cannot rotate the key, and after a password change
  or recovery it is gone along with every pending challenge and device code (R-13).
* **A database dump.** Unchanged for secrets — scrypt over a client-side Argon2id output,
  wrapped vault blobs, hashed session tokens, public keys only. One new coarse fact per
  account per day (R-16).
* **A recovery phrase.** Unchanged, and still the strongest secret in the system: it takes
  the account, clears the PGP factor, and now also invalidates everything the old credentials
  had issued.
* **A compromised VPS or browser.** Unchanged, and unchangeable by anything in this
  milestone: a hostile server can serve modified client code, and malware on the endpoint
  reads what the user reads. Both are stated in the threat model rather than mitigated by a
  claim.

### What this round did not do

No fuzzing, no external review, and no test of the PGP paths against a real `gpg` binary —
the signatures in `test/pgp.test.ts` are made by OpenPGP.js, which is also what verifies them
on the server. A round-trip through actual `gpg --detach-sign` is a manual step for the first
deployment, and it is on `docs/ROADMAP.md` as AUTH-8.
