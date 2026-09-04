# Security fixes — 2026-09-04

What changed, file by file, in the fifteen `fix(security)` commits and the `docs(security)`
commit that followed them. The findings themselves are in `SECURITY-REPORT.md` and in the
register `docs/SECURITY_FINDINGS.md`; this file is the map from a path to a reason.

Baseline: `b07913e` on `main`. Every commit was verified with `npm run check`; the whole
series with `npm run check && npm test && npm run audit` (output in `SECURITY-REPORT.md` §4).

## Commits

| Commit | Finding | One line |
| --- | --- | --- |
| `f1671ad` | SEC-2026-007 | API hooks gate on the routed pattern, not the raw URL |
| `bd3ab66` | SEC-2026-008 | Bond debited with a guarded `UPDATE … RETURNING` |
| `2382275` | SEC-2026-009 | Account deletion refused while party to an open order |
| `3f92ba3` | SEC-2026-010 | One payout in flight per account, as a partial unique index |
| `4209e2c` | SEC-2026-011 | Rate limiter spends in one conditional `UPDATE` |
| `9a81d2b` | SEC-2026-012/013 | Staff conflict of interest; open report holds the bond |
| `84e4360` | SEC-2026-014 | `__Host-` prefix on session and CSRF cookies over HTTPS |
| `9bee4e3` | SEC-2026-015 | Client validates decrypted payloads, the 428 body and `/\host` URLs |
| `9ca85ea` | SEC-2026-016 | Backup scratch files in a private directory |
| `bfb15b1` | SEC-2026-017 | Session rotation is a compare-and-swap |
| `576de6e` | SEC-2026-018 | Strict parsing of every numeric limit in the environment |
| `2c3ab0f` | SEC-2026-019 | Every route charges a bucket; `payout_worker` bucket; `device.revoked` event |
| `f4759de` | SEC-2026-020 | Payout worker never claims a row without a destination |
| `d54fc25` | SEC-2026-021 | Secret scanners cover the lockfile and credentials in URLs |
| `37b8be0` | — | Register rows, changelog, ADR-0105…0108, mechanisms, roadmap, review checklist |

## Server

| File | Change |
| --- | --- |
| `src/server/app.ts` | New `isApiRequest()` (reads `request.routeOptions.url`); the global `preHandler` and the `onSend` version header use it. Cookie names come from `cookieName()` with the `__Host-` prefix when `cookiesAreSecure()`; `enforceCsrf` receives `config`. |
| `src/server/security.ts` | CSRF cookie minted and read under the prefixed name; `enforceCsrf(config, …)` reads both cookies by their per-request name; `x-api-version` and `Onion-Location` decisions use `isApiRequest()`. |
| `src/server/lib/cookies.ts` | `SESSION_COOKIE`, `CSRF_COOKIE`, `cookieName(base, secure)` — the single place the `__Host-` rule lives. |
| `src/server/lib/sessions.ts` | Daily rotation `UPDATE … WHERE id = ? AND token_hash = ? AND last_seen_day = ? RETURNING id`; only the winner receives `rotatedToken`. |
| `src/server/lib/bonds.ts` | `releaseBond`: compare-and-swap on `bond_pico` before the ledger moves; `claimBond`: `bond_pico >= ?` guard first. New `openReportCount()`; release refused while a buyer's report on one of the seller's orders is open. |
| `src/server/lib/rate_limit.ts` | `consume()`: `INSERT … ON CONFLICT DO NOTHING` then one conditional `UPDATE … RETURNING` with the refill computed in SQL (`CASE`, dialect-neutral); the `SELECT` runs only on refusal for `retryAfterSeconds`. New `payout_worker` bucket (120 burst, 60/min). |
| `src/server/lib/ledger.ts` | `claimWithdrawal()`: `address IS NOT NULL` in both the sub-select and the guard. |
| `src/server/config.ts` | New `nonNegativeInteger()`; fifteen `Number(process.env.X ?? d)` reads replaced by `positiveInteger` / `nonNegativeInteger`. |
| `src/server/routes/auth.ts` | `POST /api/auth/delete` refuses (`409 orders_open`) while the account is buyer or seller of an open order. `app.limit` on logout, logout-everywhere, me, security-events, sessions, sessions/:id. |
| `src/server/routes/bonds.ts` | Bond claim: party check (`403`), qualifying report must be the buyer's, `asId` for the order id, `app.limit(request, "moderation")`. Bond status returns `openReports` and factors it into `releasable`. |
| `src/server/routes/market.ts` | `POST /api/market/orders/:id/status`: the `moderator` actor role is granted only when the caller is not a party. |
| `src/server/routes/wallet.ts` | `requestWithdrawal` / `refundBelowMinimum` wrapped in `orConflict(…, payout_pending)` for the new index. |
| `src/server/routes/keys.ts` | `app.limit` on status, revoke, vault GET; `recordSecurityEvent(db, user.id, "device.revoked")` on revoke. |
| `src/server/routes/messages.ts` | `app.limit(request, "write")` on `POST /api/messages/ack`. |
| `src/server/routes/deliveries.ts` | `app.limit(request, "write")` on `DELETE /api/market/orders/:id/delivery`. |
| `src/server/routes/moderation.ts` | `app.limit(request, "moderation")` on `POST /api/admin/users/:username/role`. |
| `src/server/routes/payouts.ts` | `app.limit(request, "payout_worker")` before `requireWorker` on all three routes. |
| `src/server/db/migrations/028_one_open_payout.sql` | New: partial unique index `withdrawals_one_open_per_user`. |
| `src/server/db/migrations/CHECKSUMS.txt` | Regenerated (`npm run migrate:checksums`). |

## Client

| File | Change |
| --- | --- |
| `src/client/incoming.ts` | New module: `parseIncoming()` (field-by-field validation of a decrypted payload) and `validAttachment()` (id, key, nonce, name ≤ 255 → `safeFileName`, integer `bytes` ≤ `MAX_FILE_BYTES`). |
| `src/client/messaging.ts` | `receiveMessages()` commits the ratchet state, then validates via `parseIncoming()`; invalid envelopes are acknowledged and dropped. `searchMessages` coerces `text` defensively. Validators moved out to `incoming.ts`. |
| `src/client/views/chat.ts` | The two list-view `text.slice()` sinks coerce with `String(… ?? "")` for vaults written before the fix. |
| `src/client/api.ts` | `solvablePow()` / `MAX_POW_BITS = 24`: the 428 body is validated before `solveProofOfWork`. CSRF cookie regex accepts `__Host-csrf`. |
| `src/client/ui.ts` | `safeUrl()` refuses `/\…` (WHATWG reads it as protocol-relative). |

## Scripts

| File | Change |
| --- | --- |
| `scripts/backup.mjs` | `privateScratchDir()` (`mkdtempSync`, 0700) for snapshot, verify and drill; `chmodSync(…, 0o600)` / `{ mode: 0o600 }`; recursive cleanup in `finally`; `Object.hasOwn` for command dispatch. |
| `scripts/audit.mjs` | Rules `credential in URL` and `npm auth token`; `package-lock.json` and `*.lock` scanned with the key-material rules in both `secrets` and `history`; `supply` refuses a resolved URL with userinfo; non-failing notice when `.github/workflows/ci.yml` differs from `deploy/github-ci.yml`. |

## Tests (new or extended)

| File | What it proves now |
| --- | --- |
| `test/security.test.ts` | `/%61pi/…`, `/%61%70%69/…`, `/api/%61uth/…` meet the CSRF check (403), the freeze (503) and carry `x-api-version`. |
| `test/bonds.test.ts` | Stale-snapshot release and claim are refused; report holds the bond, stranger's report does not; moderator-as-buyer refused the claim and the staff role. |
| `test/wallet.test.ts` | Seller with open orders cannot delete; ledger-level and 4-way concurrent payout requests leave exactly one in flight. |
| `test/limits.test.ts` | Limiter refuses after the burst with stale reads; every route file charges a bucket (allowlist `/`, `/healthz`); `payout_worker` reaches 429. |
| `test/hardening.test.ts` | `__Host-` names and flags on HTTPS, bare names on onion, planted bare cookies ignored; `safeUrl` backslash cases; `solvablePow` bounds. |
| `test/abuse.test.ts` | Seven hostile payloads through a real session: nothing stored, session survives, views and search do not throw. |
| `test/backup.test.ts` | No scratch path in the shared temp dir; empirical create/verify with `TMPDIR` redirected leaves nothing behind. |
| `test/sessions.test.ts` | Four concurrent resolutions rotate once; every issued token survives the grace window. |
| `test/environments.test.ts` | Fifteen limits refuse `30d`, `1.5`, `-1`, naming the variable; `0` off switches kept. |
| `test/monero.test.ts` | A queued payout with no destination is never claimed. |
| `test/audit.test.ts` | URL credentials caught in a lockfile fixture; placeholders and `integrity` hashes ignored. |
| `test/helpers.ts` | `TestClient.cookie()` resolves the `__Host-` spelling; `cookieNames()` for tests about names. |

## Documentation

| File | Change |
| --- | --- |
| `docs/SECURITY_FINDINGS.md` | Rows SEC-2026-007 … SEC-2026-025. |
| `docs/SECURITY_CHANGELOG.md` | One entry for the audit, per finding. |
| `docs/DECISIONS.md`, `docs/adr/README.md` | ADR-0105 (payout index), ADR-0106 (guarded `UPDATE` idiom), ADR-0107 (`__Host-`), ADR-0108 (staff conflict of interest, report hold). |
| `docs/MECHANISMS.md` | Five rows: routed-pattern gating, guarded counted columns, one payout index, `__Host-`, incoming payload validation. |
| `docs/CHANGE_REVIEW.md` | Two rows in the "did this reduce security" table: read-then-write on a counted column; a security decision reading the raw request. |
| `docs/DATABASE.md` | Invariant row for `withdrawals_one_open_per_user`. |
| `docs/API.md` | `orders_open` error code; bond release/status semantics; buckets on bond-claim and the payout routes. |
| `docs/ENVIRONMENT.md` | Nineteen scopes, `payout_worker` added. |
| `docs/ARCHITECTURE.md` | `client/incoming.ts` in the module map. |
| `docs/THREAT_MODEL.md` | CSRF row mentions the `__Host-` prefix. |
| `docs/ROADMAP.md` | MD-5 (sealed-sender revocation epoch), MD-6 (invite pinning). |
