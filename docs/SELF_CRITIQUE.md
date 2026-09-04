# What is wrong with this system

Point 99. Everything below was found by reviewing this repository against its own claims, and
none of it is hypothetical — each finding names the file it lives in. A project that only
publishes its strengths is a marketing document; `docs/THREAT_MODEL.md` states residual risk in
the abstract, and this page states the specific things that are currently worse than they look.

Severity is `low | medium | high | critical`, judged on this deployment: one VPS, a small
number of users, an operator who is also the developer.

Fixed findings stay on the page with their fix, because a list that only grows is one nobody
believes, and a list that deletes its history teaches nothing.

## 1. Uploads can fill the disk while staying inside every limit

**Why it matters.** The `attachment` bucket allows 12 uploads in a burst and 3 a minute
sustained, capped at 5 MB each (`MAX_DELIVERY_BYTES`). That is roughly 900 MB an hour, per
account, entirely within the rules — and accounts cost one proof of work. There is no per-account
storage quota, deliberately: a quota needs an owner column on `attachments`, and that column is
the social graph this table exists without (ADR-0043).

**Severity:** medium — availability only, no confidentiality impact, and it needs sustained
effort rather than one request.

**Attack scenario.** Ten accounts upload continuously for a day: ~200 GB of blobs. Long before
that, the filesystem holding the SQLite file is full; SQLite then fails *every* write, so
nobody can send a message, log in or place an order. Recovery is manual and needs the operator
awake.

**Proposed fix.** Refuse blob writes before the disk is gone, rather than after, and alert on
the number that predicts it.

**Implementation.** `src/server/lib/storage.ts`: an upload asks how much space is left
(`statfs`, cached for five seconds) and is refused with `503 storage_full` when the write
would leave less than `STORAGE_FLOOR_BYTES` free (default 512 MB). Reads, deletions, messages
and logins are unaffected — the service keeps working while somebody frees space.
`disk.availableBytes` in `GET /api/admin/health` is the number to alert on.

**Verification.** `test/mechanisms.test.ts` covers the floor: refused when the margin is gone,
allowed when it is not, and — importantly — *not* refused when the filesystem cannot be read,
because a safety margin that fails closed would take the service down on its own.

**Still open:** the underlying asymmetry. A determined attacker with many accounts still
consumes the whole allowance up to the floor, and blobs live for `DELIVERY_TTL_MS` (30 days).
Shortening that TTL, or charging storage to an account without naming one, is roadmap work.

## 2. The authorisation sweep was passing by luck for four routes

**Why it matters.** `test/authorization.test.ts` walks the route table and asserts that every
route refuses an anonymous caller. Four routes — `link/claim`, `recovery/challenge`,
`recovery/complete`, `pgp/complete` — are public *by design*, since each one is the
authentication step itself. They passed the sweep only because they were registered before any
route that mints a CSRF cookie, so the anonymous client happened to be refused at the CSRF layer
instead. Splitting `routes/auth.ts` reordered the table and the sweep went red.

**Severity:** low — no route lost a check; the test was weaker than it appeared, which is the
worse kind of weakness because it is invisible while it is green.

**Attack scenario.** None directly. The real risk was the next route: a genuinely private
endpoint registered early enough would have been "protected" by the same accident, and the
sweep would have said it was fine.

**Proposed fix.** Make the public set explicit rather than incidental.

**Implementation.** The four routes are now in the `PUBLIC` allowlist in
`test/authorization.test.ts`, each with the reason it cannot require a session, and the comment
records why they used to pass.

**Verification.** `npm test` — the sweep now fails if any of the four stops being public *or*
if a new route is added that nobody allowlisted.

## 3. `TRUST_PROXY=true` believed any client that connected

**Why it matters.** With `TRUST_PROXY=true`, Fastify read `X-Forwarded-For` from whoever
connected. Behind Caddy on a private network that is correct; if the application port is
reachable any other way, it lets a caller choose the address their anonymous rate-limit bucket
is keyed on.

**Severity:** low — authenticated limits are keyed on the account and unaffected, the port is
not published in the shipped compose file, and on an onion service every address is 127.0.0.1
anyway.

**Attack scenario.** An attacker who can reach the app container directly (a second service on
the host, a misconfigured firewall) rotates `X-Forwarded-For` per request and never exhausts an
anonymous bucket: registration and login floods regain the address dimension the limiter was
designed to remove.

**Proposed fix.** Let the setting name the proxy instead of trusting a header from anywhere.

**Implementation.** `TRUST_PROXY` now takes `true`, `false`, or the proxy addresses to believe
(`10.0.0.2`, `127.0.0.1/8, ::1`), passed to Fastify's `trustProxy`. The documentation
recommends the address form.

**Verification.** `test/environments.test.ts` and `docs/ENVIRONMENT.md`; the shipped default is
still `false`, which `test/defaults.test.ts` asserts.

## 4. Any authenticated account can fetch any attachment whose id it knows

**Why it matters.** `GET /api/attachments/:id` is authenticated but not scoped to a party.
This is deliberate — scoping needs a recipient column, and that column is the social graph
(ADR-0043) — and the id is a 192-bit random capability, so guessing is not the concern. But it
means the store is a shared namespace: an id that leaks (a screenshot, a copied link, a
compromised device) is enough to fetch the ciphertext, from any account.

**Severity:** low — the bytes are still encrypted, and the key travels only inside the
conversation. This is a defence-in-depth gap, not a disclosure.

**Attack scenario.** A device is compromised and its ids are exfiltrated without its keys. The
attacker collects the ciphertexts now and waits for a key compromise later; without the id they
would have needed the server.

**Proposed fix.** None that is worth the column. The honest mitigations are shorter blob
lifetimes and client-side deletion after download, both of which already exist.

**Implementation.** Documented rather than changed: `docs/API.md` and `docs/PRIVACY.md` say the
id is the capability. A future option is a per-blob deletion token, which adds no graph.

**Verification.** `test/attachments.test.ts` asserts the store holds no owner, recipient, name
or type — i.e. that the trade is the one described, not a wider one.

## 5. SQLite serialises every write behind one queue

**Why it matters.** `node:sqlite` is synchronous, and handlers are not, so transactions are
queued on a single handle (ADR-0036). One slow transaction delays every write in the process:
sending a message, placing an order, logging in. The PostgreSQL driver has no such queue —
and, as findings 8 and 9 below show, the absence of that queue is not only a performance
difference.

**Severity:** medium — a scalability limit rather than a vulnerability, but it is also a
denial-of-service amplifier: anything that makes one transaction slow makes all of them slow.

**Attack scenario.** A large delivery upload commits while a dozen ordinary requests wait; a
handful of accounts uploading concurrently turns a fast service into a queue. No rule is broken.

**Proposed fix.** Treat SQLite as the single-small-instance option it is, and make the
PostgreSQL path a tested one rather than a claimed one.

**Implementation.** Done (OPS-2): the whole suite runs against a real PostgreSQL in CI as
well as SQLite, one schema per test server (`test/database.ts`, `docs/TESTING.md`).
Operationally, `DB_DIALECT=postgres` for anything beyond a small instance.

**Verification.** The `postgres` job in `deploy/github-ci.yml`, on every push. The queue
itself remains — this finding is about a property of SQLite, not a bug — but the alternative
is now known to work rather than assumed to.

## 6. Monitoring is in-memory, so an incident with a restart loses its evidence

**Why it matters.** `GET /api/admin/health` reports counters since boot (`lib/metrics.ts`).
A crash, an out-of-memory kill or a deployment resets them, which is exactly when an operator
wants the previous hour. The decision was deliberate (ADR-0048: a persisted per-route time
series is an access log written slowly), but the cost is real.

**Severity:** low — an operability gap, not a security one.

**Attack scenario.** An attacker who can cause restarts (see finding 1) also erases the error
rate and latency that would have shown what they were doing.

**Proposed fix.** Keep the counters as they are, and let the operator own the history:
`docs/OBSERVABILITY.md` states that polling and storing the endpoint is their decision, with
short retention and no new fields.

**Implementation.** Documented. A ring of the last N hourly snapshots in memory would survive
nothing; a file would be a new artefact to protect.

**Verification.** `test/observability.test.ts` keeps the response numeric, so whatever an
operator stores stays free of subjects.

## 7. The cryptography has never been reviewed by anyone outside this project

**Why it matters.** The primitives are libsodium, but the composition — X3DH, the double
ratchet, header encryption, the vault, the recovery key — is written here and reviewed here.
Property tests and published vectors catch mistakes of implementation; they do not catch a
protocol that composes two correct primitives into a wrong whole.

**Severity:** high, on the item that matters most in a messenger, and the one thing on this
page money would fix faster than effort.

**Attack scenario.** A flaw in the composition — a nonce reused across a rekey, a transcript
that is not bound to identities, a downgrade in the handshake — is invisible to every test
written by the same person who wrote the bug.

**Proposed fix.** An external cryptographic review (roadmap CRY-1), and a hybrid
post-quantum handshake once an audited browser-capable ML-KEM exists (PQ-1) — noting that
"harvest now, decrypt later" is a real threat model for a messenger, not a marketing line.

**Implementation.** Not implemented, and not implementable from inside the project. What has
been done is to make the review cheap to buy: `docs/EXTERNAL_REVIEW.md` is a brief a reviewer
can work from on day one — the five questions we want answered, the reading order with line
counts, what CI already proves, and the weaknesses we already know about so that nobody
spends billable hours rediscovering them. The mitigation until then is unchanged: everything
is composed from published specifications with test vectors, and `docs/CRYPTO.md` states the
assumptions rather than hiding them.

**Verification.** `test/cryptography.test.ts` covers the nine kinds of failure the brief asks
for. That is necessary and, as `docs/ROADMAP.md` says in the same words, not sufficient.

## 8. Two callers could be handed the same one-time prekey

**Why it matters.** A one-time prekey is the part of X3DH that gives forward secrecy to the
very first message. Claiming it was `SELECT`, then `DELETE`, inside a transaction — which is
not the same thing as atomic. On SQLite it was correct by accident: that driver serialises
every write behind one handle, so the two statements could not interleave. On PostgreSQL at
READ COMMITTED, two transactions read the same row and both returned it.

**Severity:** high on the property it breaks, and it was live in every configuration that
used the PostgreSQL driver — which, per finding 9, is none, because that driver could not
start. That is luck, not design.

**Attack scenario.** Two parties open a session with the same device at the same moment and
receive the same one-time key. The key's whole purpose is to be used once: reuse collapses
the initial secret into one both sessions share, so an attacker who later compromises one
session's initial state learns something about the other's, and the "one-time" in the name
is untrue.

**Proposed fix.** Make the claim one statement, and let the database decide who won.

**Implementation.** `src/server/routes/keys.ts`: `DELETE … WHERE id = (SELECT … LIMIT 1)
RETURNING key_id, public_key`. The row is chosen and taken by the same statement, and
`RETURNING` reports whether this caller is the one that took it. A caller that loses retries
three times; after that the device is out of keys rather than busy, and the bundle is served
without a one-time key, which the protocol already documents as the weaker-but-sound path.

**Verification.** `test/security.test.ts` fires four concurrent bundle requests and requires
four distinct keys. Before the fix it saw two on PostgreSQL, and passed on SQLite — the same
test, the same code, one driver hiding the bug.

## 9. The PostgreSQL driver had never worked

**Why it matters.** The README, `docs/DATABASE.md` and the deployment guide all offer
PostgreSQL for "anything larger", and ADR-0004 chose the two-driver design. None of it had
ever been run: the first time the suite pointed at a real PostgreSQL, the server could not
finish its own migrations. `INTEGER` is 64-bit in SQLite and exactly 32-bit in PostgreSQL,
and every timestamp in this schema is a millisecond epoch — a number that outgrew int4 in
1970. On top of that, `pg` returns `BIGINT` and `COUNT(*)` as strings, so comparisons like
`expires_at < now` and `count === 0` would have been quietly wrong even after the columns
were widened.

**Severity:** medium — nobody could deploy the broken path, because it failed at boot rather
than in production. What it says about the project is worse than what it does: a documented,
tested-looking capability that had never been executed once.

**Attack scenario.** None. The honest version is the failure mode this represents: a claim
in the documentation that no command checked.

**Proposed fix.** Run the suite against both drivers in CI, and fix whatever that finds.

**Implementation.** Migration `012_widen_timestamps.postgres.sql` (dialect-scoped, ADR-0059),
`BIGINT` for `schema_migrations.applied_at` in the runner, and an int8 parser in
`src/server/db/postgres.ts` that returns numbers and throws rather than rounding above 2^53.
Test-side schema introspection that used `sqlite_master` and `PRAGMA` now goes through
`test/database.ts`, so the same assertions run on both.

**Verification.** The `postgres` job in CI: 467 passing, 1 skipped (the query-plan assertion,
which is about SQLite's planner). Locally: `TEST_DATABASE_URL=… npm run test:postgres`.

## 10. A test that passed here and failed on a clean clone

**Why it matters.** The free-space floor (finding 1's fix) is asserted by a test that used a
floor of `Number.MAX_SAFE_INTEGER - 1`, on the reasoning that no disk is that large. tmpfs is:
running the suite from a fresh clone under `/tmp`, `statfs` reported `bavail * bsize` of about
9.2 × 10¹⁸, the floor was never crossed, and the test failed. The same value is what
`availableBytes` invents when `statfs` throws — so on a machine where the filesystem could not
be read at all, the assertion would have *passed* while proving nothing. A test whose result
depends on the filesystem it runs on is not evidence about the code, in either direction.

**Severity:** low for the product — the mechanism itself works, and CI would have caught the
failing direction. Medium for the process: it means the suite was never run from a clean clone
outside this working copy, which is the exact rehearsal point 107 asks for.

**Attack scenario.** None directly. The realistic damage is a green suite that stops meaning
anything on the machine an operator actually uses.

**Proposed fix.** Make the assertion independent of the host, and make the clean-clone run a
habit rather than an accident.

**Implementation.** The floor in `test/mechanisms.test.ts` is now `Number.MAX_VALUE`, which no
filesystem can report and which the `statfs`-failed fallback cannot reach either. The
clean-clone rehearsal is written up in `docs/TESTING.md` with the command.

**Verification.** The suite passes both in this working copy and in a fresh clone under
`/tmp`; the previously failing test now fails only if the mechanism itself stops refusing.

## 11. A change to the second factor left the other sessions signed in

**Why it matters.** ADR-0089 made a password change and a recovery revoke every session,
challenge and device-link code. A change to the *second* factor did not: enrolling a PGP key,
rotating it, removing it, or replacing the recovery key updated the row and left every other
session alive. The comment on `POST /api/auth/pgp/remove` even said so — "sessions are left
alone" — a sentence about the vault that had become a decision about sessions.

It was found by writing the point-131 matrix from the other browser's side
(`test/revocation.test.ts`): open a second session, rotate, and ask whether it still works. It
did. Two of the five tests in that file fail against the previous commit, which is the
evidence that the hole was real and not a documentation gap.

**Severity:** medium. It needed an attacker who already held a session — the case a key
rotation is performed to end. Nothing about the vault, the messages or the money was exposed
by it; the rotation simply did not evict who it was supposed to evict.

**Attack scenario.** An attacker with a stolen session cookie. The user notices something
wrong, rotates the PGP key (or removes it and re-enrols), and reasonably believes the account
has been taken back. Before this fix, the stolen session kept working until it expired, and
the visible security history said the key had been rotated.

**Proposed fix.** Treat a factor change as the credential rotation it is.

**Implementation.** `revokeOtherCredentials()` in `src/server/lib/sessions.ts` — the ADR-0089
revocation, keeping only the session that performed it — now runs on `POST /api/auth/pgp/key`,
`POST /api/auth/pgp/remove` and `POST /api/auth/recovery/key` (ADR-0102). The caller survives
because it has just proved the password *and* a signature from the key being replaced.

**Verification.** `test/revocation.test.ts`: the point-131 matrix, one case per trigger, each
asserting a *second* session is 401 afterwards — plus the one thing a rotation cannot revoke,
unspent sealed-sender tokens, asserted rather than claimed.

