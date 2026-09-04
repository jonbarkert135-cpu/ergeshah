# Security changelog

Point 178: every significant security fix, with its date, the component, what was wrong, the
root cause, what was done, the test that keeps it done, and how it was verified. The
findings register (`docs/SECURITY_FINDINGS.md`) is the working list; this file is the history,
and it is append-only.

**What is deliberately not here.** No proof-of-concept, no exact payload for anything a
running deployment might still be exposed to, and no timing details of an unfixed issue. The
description says what class of defect it was and where, which is what an operator needs to
decide whether to update; a reader who wants to reproduce it has the test.

`node scripts/security.mjs scan` fails if a finding marked `fixed` in the register is not
mentioned here.

---

## 2026-09-04 — malformed cookie turned every request into a 500 (SEC-2026-001)

- **Component:** `src/server/lib/cookies.ts`, and the same shape in `src/client/api.ts`.
- **Issue:** cookie values were percent-decoded without a guard. A malformed escape made
  `decodeURIComponent` throw, and cookies are parsed before authentication on every request,
  so one bad cookie was answered by the error handler on every route.
- **Root cause:** an unguarded decode at a trust boundary — the general form of the bug, not
  the one route it was noticed on. Point 156: the fix went into the shared parser, and point
  157's variant analysis found the second copy in the browser client.
- **Remediation:** decode inside `try`, keep the raw value when it will not decode. The value
  is then compared against a stored token, does not match, and is refused with the 401 or 403
  the request had earned.
- **Regression test:** `test/fuzz.test.ts` — a corpus of malformed cookie headers against the
  parser, and against a live server, asserting no 5xx and that a mangled session cookie is
  not a session.
- **Verification:** `npm test`, plus the fuzz corpus that found it (it fails against the
  previous parser).

## 2026-09-04 — a second administrator could be created by racing the first registration (SEC-2026-002)

- **Component:** `src/server/routes/auth.ts`, migration `027_bootstrap_claims.sql`.
- **Issue:** the first account of a deployment is its administrator. That was decided by
  reading `users` and then inserting — two statements with nothing between them, so two
  simultaneous registrations against an empty database could both be given the role.
- **Root cause:** an authorization decision derived from a read instead of from a write.
  SQLite's single writer hid it; PostgreSQL under READ COMMITTED does not.
- **Remediation:** the role is claimed by `INSERT INTO bootstrap_claims … ON CONFLICT DO
  NOTHING RETURNING id`, inside the transaction that writes the account, so exactly one
  registration can win and a failed registration releases the claim (ADR-0104).
- **Regression test:** `test/authz_fuzz.test.ts` — two registrations in one `Promise.all`
  against a fresh deployment produce exactly one administrator, a third produces none, and a
  registration that fails validation leaves the claim untaken.
- **Verification:** `npm test` on both drivers (the PostgreSQL job in CI is where the original
  window was real).

## 2026-09-04 — a ratchet frame that was valid JSON but not an object threw the wrong error (SEC-2026-003)

- **Component:** `src/shared/crypto/ratchet.ts`.
- **Issue:** `decodeMessage` read a property off the result of `JSON.parse` before checking
  that it was an object, so `null` produced a `TypeError` from inside the parser rather than
  its own "malformed message".
- **Root cause:** trusting the *shape* of parsed JSON, which is the same class of mistake as
  trusting its contents.
- **Remediation:** shape check first, then the fields.
- **Regression test:** `test/fuzz.test.ts` — the text corpus asserts that no parser answers
  with a `TypeError` or a `RangeError`.
- **Verification:** `npm test`; no behaviour change for well-formed frames
  (`test/protocol.test.ts`).

## 2026-09-04 — secrets compared with `===` in one place, and three copies of the fix (SEC-2026-005)

- **Component:** `src/server/security.ts`, `src/server/lib/pow.ts`,
  `src/server/routes/payouts.ts`, `src/server/lib/ids.ts`.
- **Issue:** the CSRF double-submit token was compared with `!==`. The proof-of-work MAC and
  the payout worker's bearer token were compared in constant time, each with its own private
  helper.
- **Root cause:** no shared primitive for "compare two secrets", so each site decided for
  itself and one decided wrong.
- **Remediation:** one exported `constantTimeEqual()` in `src/server/lib/ids.ts`; the two
  private helpers deleted; a static rule (`timing-unsafe-secret-compare` in
  `scripts/security.mjs`) fails the build on a secret-shaped `===` in server code.
- **Regression test:** `test/security_pipeline.test.ts` — the rule detects a planted example
  and the tree is clean under it.
- **Verification:** `npm run check && npm test && npm run audit`.
