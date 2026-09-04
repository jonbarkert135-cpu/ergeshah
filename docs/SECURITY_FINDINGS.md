# Findings register

Point 151: every finding carries the same eleven fields, whatever found it — a scanner, a
fuzz run, a failing test, a dependency advisory or a person reading the diff. The register is
one table so that "what is open, and how bad is it" is one question with one answer.

`node scripts/security.mjs scan` reads this file and fails the build if a row is incomplete,
if a severity or status is not one of the values below, if a `fixed` row names a regression
test that does not exist (point 158), if a `fixed` row is missing from
`docs/SECURITY_CHANGELOG.md` (point 178), or if a **CRITICAL or HIGH row is still open**
(point 152). That last rule is the release block, and the only way past it is a status of
`accepted` whose *Fix* column says where the decision is written down.

**Severity** (point 152): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
**Status**: `open`, `fixed`, `accepted`, `not-applicable`.

Severity here is about this deployment, not about a CVSS vector: what an attacker gets, how
much they need first, and what it costs the people using the service. A defect that needs a
stolen administrator session to matter is not the same finding as one a stranger can trigger
with a header.

| ID | Severity | Component | Source | Description | Attack path | Impact | Likelihood | Fix | Regression test | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-2026-001 | MEDIUM | `src/server/lib/cookies.ts`, `src/client/api.ts` | header fuzzing, `test/fuzz.test.ts` (block 141–180) | `decodeURIComponent` on a cookie value throws on a malformed escape (`csrf=%zz`, a truncated UTF-8 sequence, a lone `%`), and cookies are parsed before authentication on every request | set or inject one malformed cookie for the origin — a related host can, and so can anything else running on it — then every request from that browser is answered by the error handler | every route answers 500 `internal_error` instead of the 401/403 it was going to; one error line per request in the operator's log, which is how a bad header becomes an incident; the browser is unusable until the cookie is cleared | high: one header, no account, no timing | guarded decode in both places — a value that will not decode is kept verbatim and refused by the check that was going to refuse it | `test/fuzz.test.ts` | fixed |
| SEC-2026-002 | MEDIUM | `src/server/routes/auth.ts` | reading the register path while writing the authorization matrix (block 141–180) | the first account of a deployment becomes `admin` after a `SELECT` that is not in the transaction that inserts, so two registrations racing on an empty database both saw an empty `users` table | register twice in the same instant against a brand-new deployment, before or with the operator | a second, unintended administrator at genesis: seller approvals, treasury reads, canary publishing, role changes | low: needs the deployment's first moment and a race, but the window is real on PostgreSQL under READ COMMITTED | the claim is a row in `bootstrap_claims`, taken with `INSERT … ON CONFLICT DO NOTHING RETURNING` inside the same transaction as the account (migration 027, ADR-0104) | `test/authz_fuzz.test.ts` | fixed |
| SEC-2026-003 | LOW | `src/shared/crypto/ratchet.ts` | parser fuzzing, `test/fuzz.test.ts` (block 141–180) | `decodeMessage` read `.v` off the result of `JSON.parse`, so `null`, `7` and `"x"` produced a `TypeError` from inside the parser instead of its own refusal | post an envelope whose payload is valid JSON but not an object; the recipient's client decodes it | none today — `receiveMessages` catches per envelope and acknowledges — but a parser that throws the wrong error is one refactor away from a caller that does not expect it | high to trigger, no consequence | shape check before the fields, and the parser's own `Error` | `test/fuzz.test.ts` | fixed |
| SEC-2026-004 | INFO | `src/server/routes/moderation.ts` | the staff-route sweep in `test/authz_fuzz.test.ts` (block 141–180) | `POST /api/moderation/reports` sits under the staff prefix and is deliberately open to any authenticated account — filing a report is a user action, reading the queue is not | none: the route is authenticated and rate-limited, and it writes a report owned by the caller | naming only: a reviewer scanning the route table for staff-only paths can misread which routes are privileged | n/a | kept as is, and named in the sweep's allowlist with the reason, so the exception is visible instead of implied. Moving it would break clients for a cosmetic gain (`docs/API.md`) | `test/authz_fuzz.test.ts` | accepted |
| SEC-2026-005 | LOW | `src/server/security.ts` | the `timing-unsafe-secret-compare` rule, `scripts/security.mjs` (block 141–180) | the CSRF double-submit token was compared with `!==`, which returns as soon as two bytes differ; two other places had each grown a private constant-time helper | measure the response time of a cross-site request while guessing the token byte by byte — awkward through a browser, and the token is 24 random bytes | small on its own; the reason to fix it is that a `!==` on a secret is what the next handler copies | low | one `constantTimeEqual()` in `src/server/lib/ids.ts`, used by the CSRF check, the proof-of-work MAC and the payout worker's bearer token; the static rule keeps a fourth copy from appearing | `test/security_pipeline.test.ts` | fixed |
| SEC-2026-006 | INFO | `src/server/routes/deliveries.ts` | the stranger-identifier sweep in `test/authz_fuzz.test.ts` (block 141–180) | `GET`/`DELETE /api/attachments/:id` have no owner column: any authenticated caller who presents an id may read or delete that blob, and an unknown id answers `{deleted: 0}` rather than 404 | guess a 128-bit client-chosen id, inside the `write` rate bucket | with the id: read ciphertext the caller cannot decrypt, or delete bytes the recipient already has. Without it: nothing | negligible — the id is the capability and it is random | unchanged by design (ADR-0043): an owner column would be the recipient list this table exists without. The sweep asserts a stranger's *other* identifiers delete nothing, which is the property that could regress | `test/authz_fuzz.test.ts` | accepted |

## What a row is for

The columns nobody wants to fill in are the ones that make the register useful a year later.
*Attack path* is what an attacker actually does, in order — if it cannot be written, the
finding is a guess and says so. *Likelihood* is about this system: a race that needs the
first second of a deployment is not the same as a header anybody can send. *Regression test*
is the permanent part (point 158): the fix is finished when the test that fails without it
exists, and the register names it so that deleting the test breaks the scan.

## What is not in here

Not every fix is a finding. A hardening change nobody had exploited — a new rule, a tighter
default, a limit — belongs in `docs/DECISIONS.md` and the release notes. This register is for
defects: something that was wrong, with a path from an input to a consequence.

Design decisions that leave a residual risk are not findings either; they are rows in
`docs/THREAT_MODEL.md` and items in `docs/ROADMAP.md`. The two `accepted` rows above are the
boundary case — a sweep flagged them, they were judged, and the judgement is written where
the sweep will show it again.
