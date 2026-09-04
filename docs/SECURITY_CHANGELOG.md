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

## 2026-09-04 — full application-security audit: fifteen fixes (SEC-2026-007 … SEC-2026-021)

One pass over every route, the money layer, sessions, the client's trust boundary, the backup
tooling and the audit scripts, with every finding verified against the code before it was
written down. The full narrative is `SECURITY-REPORT.md` at the repository root; the changed
files are in `SECURITY-FIXES.md`. Per finding:

- **SEC-2026-007 — percent-encoded API path skipped the freeze and the CSRF check.**
  Component: `src/server/app.ts`, `src/server/security.ts`. Root cause: a security decision
  derived from the raw request line rather than from the route the router matched. Remediation:
  `isApiRequest()` over `request.routeOptions.url`, used by every hook. Test:
  `test/security.test.ts` (three encodings, the freeze, the version header).
- **SEC-2026-008 — the bond could be credited twice.** Component: `src/server/lib/bonds.ts`.
  Root cause: read-then-write on a money column, safe on SQLite only. Remediation: guarded
  `UPDATE … RETURNING` before the ledger moves (ADR-0106). Test: `test/bonds.test.ts`, staging
  the stale READ COMMITTED snapshot.
- **SEC-2026-009 — a seller could delete an account with open orders.** Component:
  `src/server/routes/auth.ts`. Root cause: the pre-deletion check looked at the deleter's balance,
  and the escrow is on the buyer's. Remediation: `409 orders_open` while party to an open order.
  Test: `test/wallet.test.ts`.
- **SEC-2026-010 — payouts could be split past the automatic ceiling.** Component:
  `src/server/routes/wallet.ts`, migration 028. Root cause: an application check where a constraint
  was needed. Remediation: partial unique index (ADR-0105). Test: `test/wallet.test.ts`.
- **SEC-2026-011 — the rate limiter could be beaten by concurrency.** Component:
  `src/server/lib/rate_limit.ts`. Root cause: as SEC-2026-008. Remediation: one conditional
  `UPDATE` with the refill computed in SQL. Test: `test/limits.test.ts`.
- **SEC-2026-012 — a moderator could decide about their own order.** Component:
  `src/server/routes/bonds.ts`, `src/server/routes/market.ts`. Root cause: staff role granted
  without a conflict-of-interest check; a precondition satisfiable by any account. Remediation:
  parties are refused the claim and lose the staff role on their own orders; the report must be
  the buyer's (ADR-0108). Test: `test/bonds.test.ts`.
- **SEC-2026-013 — the bond was releasable while a buyer's report waited.** Component:
  `src/server/lib/bonds.ts`. Root cause: the hold looked at `orders.status` only. Remediation:
  open buyer reports hold the bond too. Test: `test/bonds.test.ts`.
- **SEC-2026-014 — cookies had no `__Host-` prefix.** Component: `src/server/lib/cookies.ts` and
  callers, `src/client/api.ts`. Root cause: cookie names shared with every sibling host.
  Remediation: prefixed names on `Secure` responses (ADR-0107). Test: `test/hardening.test.ts`.
  Operators: every browser signs in once more after this ships.
- **SEC-2026-015 — a hostile peer could blank the Messages screen.** Component:
  `src/client/incoming.ts` (new), `src/client/messaging.ts`, `src/client/views/chat.ts`,
  `src/client/api.ts`, `src/client/ui.ts`. Root cause: an authenticated plaintext trusted for its
  shape. Remediation: field-by-field validation before storage, ratchet committed first; the
  server's 428 body and the `/\host` URL spelling checked on the same boundary. Test:
  `test/abuse.test.ts`, `test/hardening.test.ts`.
- **SEC-2026-016 — backups wrote the plaintext database to a shared `/tmp`.** Component:
  `scripts/backup.mjs`. Root cause: scratch files with default permissions. Remediation:
  `mkdtemp` directories, `0600` files. Test: `test/backup.test.ts`.
- **SEC-2026-017 — daily session rotation raced with itself.** Component:
  `src/server/lib/sessions.ts`. Remediation: compare-and-swap (ADR-0106). Test:
  `test/sessions.test.ts`.
- **SEC-2026-018 — numeric limits parsed with a bare `Number()`.** Component:
  `src/server/config.ts`. Remediation: strict parsers for all fifteen. Test:
  `test/environments.test.ts`.
- **SEC-2026-019 — sixteen routes charged no bucket.** Component: `src/server/routes/*.ts`,
  `src/server/lib/rate_limit.ts`. Remediation: the documented bucket on each, a `payout_worker`
  bucket, a sweep over the route files. Test: `test/limits.test.ts`.
- **SEC-2026-020 — a payout without a destination was parked in `sending`.** Component:
  `src/server/lib/ledger.ts`. Remediation: `address IS NOT NULL` in the claim. Test:
  `test/monero.test.ts`.
- **SEC-2026-021 — the lockfile was invisible to the secret scanners.** Component:
  `scripts/audit.mjs`. Remediation: URL-credential rules, lockfile scanned, supply check refuses
  userinfo. Test: `test/audit.test.ts`.

**Verification:** `npm run check`, `npm test` (the full suite, every new test shown to fail on
the previous commit), `npm run audit`. What remains open, accepted or not applicable after this
pass is in the register, not here (point 178: nothing unfixed gets a description in the changelog).

## 2026-09-04 — an invite from a third account could land inside an existing conversation (SEC-2026-024)

- **Component:** `src/client/incoming.ts` (`strangerInvite`), `src/client/messaging.ts` (receive
  path), `src/server/routes/keys.ts` (one new read-only route).
- **Issue:** the sender chooses an envelope's channel id, and an order conversation's channel id
  is known to both parties. A third account that learned it could post an X3DH invite into the
  conversation, and the recipient's client accepted the new session and showed the message under
  whatever display name the plaintext carried. The AUTH-6 banner flagged the new key; nothing
  refused it.
- **Root cause:** trust on first use applied to every unknown key, including one arriving inside a
  conversation whose peer was already known — the one situation where there is something to
  check it against.
- **Remediation:** before a key the conversation has never seen may open a session in it, the
  client asks `GET /api/keys/identity/:username` whether the peer's directory lists that key; a
  key it does not list is acknowledged and dropped. The route publishes only the identity keys the
  bundle route already publishes, without consuming a one-time prekey, so the check costs the peer
  nothing and stays under the ordinary `read` bucket. A directory that cannot be reached leaves
  the envelope for the next poll (ADR-0112).
- **Regression test:** `test/client.test.ts` — a third account posts into an order channel; the
  recipient stores only the peer's message, opens no session with the stranger's key, raises no
  key-change banner, and the server holds no parked envelope. Fails on the previous commit.
- **Verification:** `npm run check`, `npm test`, `npm run audit`.
