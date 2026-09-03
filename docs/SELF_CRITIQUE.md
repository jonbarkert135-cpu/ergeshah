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
sending a message, placing an order, logging in. The PostgreSQL driver has no such queue.

**Severity:** medium — a scalability limit rather than a vulnerability, but it is also a
denial-of-service amplifier: anything that makes one transaction slow makes all of them slow.

**Attack scenario.** A large delivery upload commits while a dozen ordinary requests wait; a
handful of accounts uploading concurrently turns a fast service into a queue. No rule is broken.

**Proposed fix.** Treat SQLite as the single-small-instance option it is, and make the
PostgreSQL path a tested default rather than an alternative.

**Implementation.** Roadmap OPS-2: run the suite against both drivers in CI. Operationally:
`DB_DIALECT=postgres` for anything beyond a small instance, which the deployment guide already
recommends.

**Verification.** Until OPS-2 lands, this is unverified for PostgreSQL — the suite runs on
SQLite. That is stated here rather than implied by "supports both".

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

**Implementation.** Not implemented. The mitigation until then is that everything is composed
from published specifications with test vectors, and that `docs/CRYPTO.md` states the
assumptions rather than hiding them.

**Verification.** `test/cryptography.test.ts` covers the nine kinds of failure the brief asks
for. That is necessary and, as `docs/ROADMAP.md` says in the same words, not sufficient.
