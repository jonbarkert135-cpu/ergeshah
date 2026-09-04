# Security audit report — Symvolon, 2026-09-04

Full application-security audit of this repository at `b07913e` (`main`), followed by fixes,
delivered as fifteen atomic `fix(security)` commits plus one documentation commit on `main`.
The register of record is `docs/SECURITY_FINDINGS.md` (rows SEC-2026-007 … 025); the file map
is `SECURITY-FIXES.md`. This document is the narrative: what was looked at, what was found,
how each finding is exploited, what was done, and what remains.

**Rules followed.** Nothing was tested against a live deployment; every claim below was
verified by reading the code and, where marked *reproduced*, by running the real application
in-process (`app.inject` against `startTestServer()`) or the real script. No finding is a guess:
each has a file, a line-level location and an attack path. Where certainty was not reached the
item is under §2.4 "needs verification" rather than in the table.

## Summary

- **Found:** 0 Critical · 3 High · 7 Medium · 6 Low · 3 Info (19 findings; SEC-2026-001 … 006
  from the previous pass were re-verified in place and are not re-reported).
- **Fixed:** all 3 High, all 7 Medium, 5 of 6 Low — 15 findings, each with a regression test
  that fails on the previous commit and passes on the fix.
- **Not fixed, with a decision:** 1 Low needs the owner (the CI workflow copy — the agent may not
  write `.github/workflows/`); 1 Low accepted by design (sealed-sender tokens outlive a
  suspension — ADR-0084/0089, roadmap MD-5); 1 Info is a protocol change (roadmap MD-6); 1 Info
  not applicable in the shipped topology.
- **Most dangerous:** SEC-2026-007 — one percent-encoded character in the path
  (`/%61pi/…`) made every write route skip the operator's breach freeze and the CSRF check
  (reproduced); SEC-2026-008 — on PostgreSQL a seller could be paid twice for one bond;
  SEC-2026-009 — a seller could delete their account with orders open and strand every buyer's
  escrow.
- **Systemic root cause behind five findings:** read-then-write on counted columns. Correct on
  SQLite (serialised transactions, which is what the test suite runs), a race on PostgreSQL
  (READ COMMITTED, no row locks). Fixed with the ledger's own guarded-`UPDATE` idiom and written
  down as ADR-0106 and a review-checklist row so the pattern is caught next time.
- **Owner actions (within 24 h):** §5. No leaked secret was found anywhere in the tree or in
  1416 historical blobs, so no key rotation is required; the checklist is about the CI copy, a
  one-time re-login after the cookie change, a backup, and a look at the audit log for the
  bond/claim patterns described here.

## 1. Inventory (Stage 0)

**Stack.** Fastify 5.12.1 on Node ≥ 22.5 (TypeScript run with `--experimental-strip-types`,
no build step server-side); PostgreSQL or SQLite behind a 40-line `Db` interface with 28
migrations; a vanilla-TypeScript browser client bundled by esbuild 0.28.2 with SRI and a
Trusted-Types CSP; libsodium-wrappers-sumo 0.7.15 for X3DH + double ratchet + XChaCha20-Poly1305;
openpgp 6.3.1 server-side only (PGP second factor); pg 8.x. Dev: vitest 4, typescript 5.9.
~20.4k lines of TypeScript, 71 → 71 test files (739 tests after this pass).

**Entry points.** ~90 HTTP routes in `src/server/routes/` — auth, recovery, keys, messages,
market, bonds, deliveries, evidence, wallet, payouts, moderation, notifications, health, canary,
static. No webhooks; the only inbound automation is the payout worker (`scripts/payout-worker.mjs`)
calling three bearer-token routes. Background jobs in `src/server/lib/jobs.ts` (sweeps, deposit
scanning via monero-wallet-rpc). Operator CLIs: `scripts/{backup,incident,release,audit,security}.mjs`.

**Trust boundaries.** Browser → server: cookies (`HttpOnly` session, readable CSRF), JSON
bodies validated by `lib/validate.ts`, sealed-sender tokens. Server → third parties: only
monero-wallet-rpc (allow-listed methods). Peer → peer: end-to-end encrypted envelopes the
server relays blind; the *client* is the boundary for their contents. Operator → server: env
(`config.ts`, strict), CLI scripts, the `lockdown` row.

**Roles and session.** `user` / `moderator` / `admin` in `users.role`; the first account of a
deployment becomes admin via `bootstrap_claims`. Session = 32 random bytes, SHA-256 at rest,
absolute + idle expiry, daily rotation with 60 s grace. PGP challenge as second factor; recovery
via Ed25519 key from a BIP-39 phrase.

**Money.** Custodial XMR ledger (`balances`, `ledger_entries`, integer pico-XMR, CHECK ≥ 0),
escrow per order, seller bonds, withdrawals through a worker that holds the spend key elsewhere.
Deposits credited from wallet-RPC transfers with a unique `(txid, subaddress, amount)` key.

**Most valuable data and who could take it.** (1) Platform float and user balances — an
authenticated user via a logic or concurrency defect; a moderator via a privilege defect.
(2) Vaults and message ciphertext — unreadable to the server; the client is the target.
(3) The operator's database — anyone with a foothold on the host (backups, `/tmp`).
(4) Sessions — a sibling host, a related-domain cookie, a CSRF gap.

## 2. Findings

### 2.1 Table, by risk

| # | Finding | Severity | Where | How it is exploited | Consequence | Fix |
| --- | --- | --- | --- | --- | --- | --- |
| 007 | Percent-encoded API path skips the freeze, CSRF and session pre-resolution (*reproduced*) | **High** | `src/server/app.ts` preHandler (`request.url.startsWith("/api/")`), `security.ts` onSend | `POST /%61pi/auth/logout` with a session cookie and no CSRF token → 200; with lockdown on → the write runs instead of 503 | The breach freeze (ADR-0080) is defeatable by anyone with a session; two of three CSRF layers gone on every route | `isApiRequest()` from `request.routeOptions.url`; all hooks use it |
| 008 | Bond credited twice under concurrency (PostgreSQL) | **High** | `src/server/lib/bonds.ts` `releaseBond`/`claimBond` | Seller with bond N and any other hold ≥ N fires two releases at once; both read N, both pass the ledger guard, both credit | Seller paid 2N for N — platform insolvency; claims can overdraw a bond | Guarded `UPDATE … WHERE bond_pico = ? RETURNING` before the ledger moves (ADR-0106) |
| 009 | Seller can delete an account with open orders; buyers' escrow stranded | **High** | `src/server/routes/auth.ts` `POST /api/auth/delete` | Check looked at the deleter's balance; a seller has nothing held on an open order; `orders` cascades from `users` | Buyers' `held_pico` has no order to settle/release against — frozen; history and evidence gone | `409 orders_open` while buyer or seller of an open order |
| 010 | Payouts split past the automatic ceiling (PostgreSQL) | Medium | `routes/wallet.ts`, `lib/ledger.ts` `queueWithdrawal` | k parallel `POST /api/wallet/withdrawals` each under `AUTO_PAYOUT_MAX_XMR`; pre-check `SELECT` and 24 h `SUM` see no uncommitted rows | A balance far above the ceiling leaves without an admin signature — the control that bounds a stolen session | Partial unique index `withdrawals_one_open_per_user` (migration 028, ADR-0105) |
| 011 | Rate limiter beaten by concurrency (PostgreSQL) | Medium | `src/server/lib/rate_limit.ts` `consume` | Send the burst in parallel; each request reads the same level and writes `level − 1` | Every quota (login, register, upload bytes, wallet writes) divided by the attacker's concurrency | One conditional `UPDATE … WHERE refilled ≥ cost RETURNING`, refill computed in SQL |
| 012 | Moderator decides about their own order | Medium | `routes/bonds.ts` bond-claim, `routes/market.ts` status | Moderator buys from a bonded seller, completes, reports from their own account (any account may report any order id), claims up to the price; or settles their own dispute | Drains an honest seller's bond by the value of self-placed orders | Parties refused the claim (403) and the staff role on their own orders; report must be the buyer's (ADR-0108) |
| 013 | Bond releasable while a buyer's report is open | Medium | `lib/bonds.ts` `openDisputeCount` only | Complete → get reported → release before the moderator reaches the queue | The bond defeated in the one scenario it exists for | Open buyer report holds the bond; `openReports` in status |
| 014 | No `__Host-` prefix on session/CSRF cookies | Medium | `lib/cookies.ts`, `app.ts`, `security.ts`, `client/api.ts` | A sibling host sets `session=<attacker token>; Domain=…`; victim's browser sends the attacker's session | Forced login / session fixation without a stolen credential; forgeable CSRF token | `__Host-session`/`__Host-csrf` on Secure responses (ADR-0107) |
| 015 | Client stores an authentic but malformed payload; Messages view blanks | Medium | `client/messaging.ts` (cast after `JSON.parse`), `views/chat.ts` | One envelope with no string `text` from an edited client | Victim's Messages screen throws on every load until localStorage is cleared; search throws | `client/incoming.ts` validation after ratchet commit; defensive sinks; 428 body and `/\host` URL checked on the same boundary |
| 016 | Backup writes the plaintext DB to shared `/tmp` at 0644 (*reproduced*) | Medium | `scripts/backup.mjs` `snapshot`/`inspect`/`drill` | Another login copies `/tmp/symvolon-*.sqlite` in a loop | Whole database in the clear on a shared host | `mkdtemp` (0700) + 0600, recursive cleanup |
| 017 | Session rotation races with itself (*reproduced*) | Low | `lib/sessions.ts` | First page load of a new day: parallel requests all rotate; last write wins | Random sign-outs read as breaches; grace window re-armed | Compare-and-swap on the presented hash |
| 018 | Numeric env limits parsed with bare `Number()` (*reproduced*) | Low | `config.ts` (15 variables) | `SESSION_TTL_MS=30d` boots with `NaN` | Sign-in outage blamed on the DB, or expiry silently off | `positiveInteger`/`nonNegativeInteger` for all |
| 019 | Sixteen routes charge no bucket | Low | `routes/*.ts`, incl. the three worker routes | Loop `GET /api/keys/vault` (256 KiB), `POST /api/messages/ack` (200 deletes), `/api/payouts/claim` anonymously | Resource exhaustion the limiter cannot see; worker routes an anonymous amplifier | Documented bucket on each; `payout_worker` bucket; sweep test with allowlist |
| 020 | Payout with `NULL` address parked in `sending` | Low | `lib/ledger.ts` `claimWithdrawal` | Any queued row without a destination | Owner's hold frozen until manual resolution, one row per poll | `address IS NOT NULL` in the claim |
| 021 | Lockfile invisible to the secret scanners | Low | `scripts/audit.mjs` | `npm install --registry https://user:TOKEN@…` then commit | A leaked registry token passes both gates | URL-credential rules; lockfile scanned; supply check refuses userinfo |
| 022 | Live CI workflow is a stale copy; PostgreSQL job never runs | Low | `.github/workflows/ci.yml` vs `deploy/github-ci.yml` | A PostgreSQL-only regression merges green | The driver with five concurrency findings in this report is the one CI does not run | **Owner:** copy the source over the live file (§5); `npm run audit` prints a notice until then |
| 023 | Sealed-sender tokens outlive suspension/deletion (≤ 7 days) | Low | `routes/messages.ts`, `lib/send_tokens.ts` | Stockpile 32 tokens/min, get suspended, keep sending | Moderation does not stop delivery for the TTL | **Accepted** by design (ADR-0084/0089); operators may lower `SEND_TOKEN_TTL_MS`; roadmap MD-5 |
| 024 | Channel-id injection with a spoofed display name | Info | `client/messaging.ts` `resolveConversation` | Third account learns an order channel id, posts an invite with `from: "seller"` | A spoofed line inside an existing chat, flagged by the key-change banner | **Not fixed:** protocol change (ADR-0091); roadmap MD-6 |
| 025 | `.env.example` ships `TRUST_PROXY=true` | Info | `.env.example` | Hand-rolled deployment exposing the app port + spoofed `X-Forwarded-For` | Address-keyed anonymous buckets bypassed | **Not applicable** in the shipped compose topology (no published port; Caddy *sets* XFF); documented |

### 2.2 Attack paths in detail (Critical/High only — the rest are in the register)

**SEC-2026-007.** find-my-way (Fastify's router) percent-decodes static path segments, so
`/%61pi/auth/logout` is dispatched to the handler registered at `/api/auth/logout`. Every
hook in `app.ts`/`security.ts` that decided "is this the API?" did so with
`request.url.startsWith("/api/")` on the still-encoded raw URL — false — and returned early.
Reproduced in the new test: with a valid session cookie and *no* CSRF header,
`POST /%61pi/auth/logout` answered **200** and the session was destroyed; with the `lockdown`
row present the same request was performed instead of answering 503. Consequence for the
threat model: an attacker inside a stolen session could keep moving money during the operator's
freeze by encoding one letter. Full drive-by CSRF remained blocked by `SameSite=Strict` and the
JSON-only body parser; the fix restores the other two layers and the freeze.

**SEC-2026-008.** `releaseBond` read `bond_pico` (inside the transaction, with a comment
saying the re-read was for exactly this race), then called `apply(+N available, −N held)`,
then `UPDATE sellers SET bond_pico = 0`. PostgreSQL's `BEGIN` here is READ COMMITTED with no
`FOR UPDATE` anywhere in the repository, so two transactions both read N. The ledger guard
`held_pico − N ≥ 0` passes for both whenever the seller has any other hold of ≥ N (a payout in
flight, or an open order as buyer). Result: `available_pico` credited 2N. The suite runs on
SQLite, whose single-handle transaction queue hides it, which is why the regression test stages
the stale snapshot explicitly. Now the bond is taken first with
`UPDATE … WHERE user_id = ? AND bond_pico = ? RETURNING user_id`; the loser gets a 409.

**SEC-2026-009.** `POST /api/auth/delete` refused deletion only for a non-empty `balances` row
of the deleter. Escrow on an open order is held on the *buyer's* account, so a seller with
accepted orders passed the check; `orders.seller_user_id … ON DELETE CASCADE` removed the
orders; `ledger_entries.order_id` was set to NULL; the buyers' `held_pico` stayed held with no
row that could ever settle or release it. Reproduced in the new test (deletion returned 200, the
buyer's held balance remained). Now `409 orders_open` while the account is party to an order in
`placed/accepted/delivered/disputed`.

### 2.3 Checked and clean (coverage)

- **Authorization.** Every route was swept twice (mechanically and by reading): the only routes
  without a session check are the intentional public ones (register, login, link claim,
  recovery, canary, four public market reads, `/`, `/healthz`, the three worker routes). Every
  object lookup is scoped by the caller (`orderFor`, `requireOwnDevice`, `accountFor`,
  `user_id` in every wallet/session/vault query); strangers get 404, not 403. `requireRole`
  audits refusals with the route pattern. No mass assignment: `onlyKeys` on every money/upload
  body; `register` cannot set `role`; listing PATCH builds columns from literals.
- **Injection.** Every SQL statement is parameterised; the only SQL string manipulation is the
  `?`→`$n` rewrite. Search terms are `\p{L}\p{N}` tokens and still bound; cursors regex-validated.
  No `eval`, `new Function`, `child_process` with a shell, dynamic `require`, or `Math.random` in
  `src/`. Client: no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`srcdoc`;
  `el()` builds text nodes only and allow-lists URL attributes; CSP has no `unsafe-inline`.
- **Uploads.** Opaque ciphertext into DB rows, never files; size capped in decoded bytes; served
  as JSON with `nosniff`; names sanitised by `safeFileName` on both ends.
- **Authentication.** Client Argon2id → server scrypt (N=2¹⁵) with `timingSafeEqual`; a missing
  account costs a full derivation (no enumeration oracle). Challenges are domain-separated,
  purpose-bound, deleted before verification (one-time). Ed25519 verification wraps raw keys in
  a fixed SPKI header and never throws; PGP verification refuses private blocks, requires a
  signing-capable key, `expectSigned: true`. Password change, recovery, PGP enrol/rotate/remove
  revoke other credentials in one transaction. Device link codes: 32 bytes, hashed, 5 min,
  single-use. Recovery issues a decoy challenge for unknown usernames.
- **Sessions/cookies.** `HttpOnly`, `SameSite=Strict`, `Secure` off onion; token hash only at
  rest; absolute + idle expiry enforced on read, not just by housekeeping.
- **Money.** Prices always from the listing row; string arithmetic with `isSafeInteger` gates;
  the pg INT8 parser refuses unsafe integers; the worker uses BigInt. `ledger.apply` is one
  guarded `UPDATE … RETURNING` with CHECK constraints behind it. Order state machine is a CAS on
  `status`; settlement sums to zero with the fee floored in the seller's favour; refunds claim
  deposits conditionally first; deposit idempotency by unique key; withdrawal lifecycle every
  step conditional; dual approval one row per (payout, admin). No endpoint credits or transfers.
  Reviews: buyer-only, once per order (UNIQUE), averaged over distinct authors.
- **Anti-automation.** PoW MAC with the server pepper, constant-time compare, clock-skew bounds,
  replay closed by the `auth_challenges` primary key.
- **Crypto (client).** X3DH verifies the signed prekey before any DH; AD binds both identity
  keys; ratchet decrypts into a clone and commits only after authentication; header encryption;
  nonces HKDF-derived from single-use keys; skipped keys bounded and zeroed; padding fails closed
  behind the AEAD; vault v3 only; all derived material zeroed in `finally`.
- **Secrets/config.** Pepper and worker token ≥ 32 chars, no development prefix in production,
  `_FILE` indirection; `NODE_ENV` is a closed set. `.env`, `data/`, `*.sqlite*` ignored.
  **Git history:** 1416 distinct blobs scanned for key material — only the scanner's own fixtures,
  all allow-listed with reasons. A deleted `hive/` Python orchestrator in history holds no
  credentials.
- **Logging.** One writer with a fixed field set, forbidden-key redaction, secret- and
  address-shaped scrubbing; the 500 handler logs the route *pattern* and a random reference,
  returns no stack/body/user. Request logging off.
- **Dependencies.** `npm audit`: 0 vulnerabilities (177 packages). Lockfile v3, every entry
  from `registry.npmjs.org` with integrity; two install scripts (esbuild, fsevents) neutralised
  by `.npmrc ignore-scripts=true`; esbuild pinned exactly.
- **CI/CD.** Trigger `pull_request` (not `pull_request_target`), `permissions: contents: read`,
  `persist-credentials: false`, actions pinned by SHA, no secrets referenced.
- **Containers/proxy/Tor.** Digest-pinned multi-stage images, `USER node`, no published app
  port, `cap_drop: ALL`, `read_only`, tmpfs `/tmp`; Caddy `admin off`, access log discarded,
  TLS ≥ 1.2, `X-Forwarded-For` set from the real peer; Tor `SocksPort 0`, intro-DoS defences.
  `deploy/postgres-roles.sql`: `REVOKE ALL FROM PUBLIC`, `NOSUPERUSER … NOBYPASSRLS`.

### 2.4 Needs verification (not asserted as findings)

- `toPostgresPlaceholders` rewrites every `?`, including one inside a string literal or a JSON
  operator; no current query has one. A round-trip test would make it safe to rely on.
- Two identical outputs to the same subaddress in one Monero transaction would be credited once
  (unique key on amount) — a loss for the payer, never a gain; needs a real `get_transfers`
  fixture to confirm how wallet-rpc reports them.
- Concurrent dual approval: two admins approving at the same instant each count 1 and both park
  the payout — fails safe; a PostgreSQL integration test would confirm.
- `PUT /api/keys/vault` from two devices is last-writer-wins with no version; arguably by design
  for an opaque blob, not stated anywhere.
- `GET /api/keys/bundle/:username` is on the `OPEN_TO_STRANGERS` allowlist in
  `test/authz_fuzz.test.ts` but the handler authenticates — the test and the code disagree in
  the safe direction. `test/idor.test.ts` probes `/api/moderation/seller-applications`, a route
  that no longer exists (the assertion passes against a 404).
- Lazy libsodium chunk is not covered by SRI directly (the entry that names it by content hash is).

## 3. Fixes (Stage 3)

Fifteen commits on `main`, one per finding or tightly coupled pair, ordered High → Low. Every
fix is server-side where the property is server-side (authorization, money, sessions, limits),
client-side where the boundary is the client's (decrypted payloads, the server's 428 body, URL
sinks). No feature was removed or simplified; public behaviour is unchanged except where the
behaviour was the defect:

- a seller with open orders now gets `409 orders_open` on deletion;
- a bond cannot be released while a buyer's report is open (`409`), and `GET /api/market/seller/bond`
  gains `openReports`;
- a moderator who is party to an order is refused its bond claim (`403`) and acts on it only as
  that party;
- on a TLS deployment every browser signs in once more after the cookie rename (ADR-0107);
- a second concurrent payout request now gets the same `409 payout_pending` the sequential one did;
- sixteen routes are now rate-limited as `docs/API.md` already said they were.

Centralisation: one `isApiRequest()`, one `cookieName()`, one `parseIncoming()`, one
`privateScratchDir()`, one guarded-`UPDATE` idiom named in ADR-0106 and the review checklist.
No placeholders, no `// TODO`, no disabled checks, no `catch {}` without handling were added.
Migration 028 is additive and reversible (`DROP INDEX`); no data migration was needed.

## 4. Verification (Stage 4)

Run on the final tree, in this order, all in the sandbox on Node 22 / SQLite (no PostgreSQL
instance was available; see §5 for why the owner should run the suite there once):

```
$ npm run check            # tsc --noEmit + scripts/lint.mjs
> tsc --noEmit
(clean; lint: 0 findings)

$ npm test
 Test Files  71 passed (71)
      Tests  739 passed (739)

$ npm run audit
found 0 vulnerabilities
dependency audit: 4 direct, 65 in the production tree (budget 68), every one justified, every licence allowed
bundle audit: 5 files, no external references, no secrets
secret audit: 292 tracked files, nothing that looks like a credential
history audit: 102 commits, 1431 distinct blobs (1 reviewed fixtures allowed), no credential ever committed
migration audit: 28 migrations, ordered, unmodified since release
supply-chain audit: 177 locked packages, all from the public registry with integrity hashes
  NOTICE: .github/workflows/ci.yml differs from deploy/github-ci.yml — copy the source over it (SEC-2026-022)
cost audit: (one operator tool, accounted for)
egress audit: 6 outbound call site(s), all accounted for; 178 packages, no telemetry, no host written into the source
inventory audit: 177 packages (65 production, 112 development), frozen and matching docs/DEPENDENCY_INVENTORY.md
security scan: 187 files, 12 rules, clean
  register: 25 finding(s) tracked in docs/SECURITY_FINDINGS.md; open by severity: CRITICAL 0, HIGH 0, MEDIUM 0, LOW 1, INFO 1
security baseline (recorded 2026-09-04): every counter at its baseline
```

**Per finding, how the fix is proven.** Each regression test was run against the commit before
its fix and observed to fail, then against the fix and observed to pass:

| Finding | Test | Fails on old code with |
| --- | --- | --- |
| 007 | `security.test.ts` "percent-encoded API path" | `expected 200 to be 403` |
| 008 | `bonds.test.ts` "credits a bond once…", "refuses a claim…" | promise resolved instead of rejecting |
| 009 | `wallet.test.ts` "party to an open order" | `expected 200 to be 409` |
| 010 | `wallet.test.ts` "exactly one payout however many requests" | ledger-level call resolved instead of rejecting |
| 011 | `limits.test.ts` "spends in one statement" | resolved `undefined` instead of rejecting |
| 012/013 | `bonds.test.ts` three cases | all three fail |
| 014 | `hardening.test.ts` "__Host-" | cookie names |
| 015 | `abuse.test.ts` "hostile peer" | `expected 5 to be 1` (five hostile messages stored) |
| 016 | `backup.test.ts` "scratch files" | source assertions |
| 017 | `sessions.test.ts` "rotates exactly once" | `expected […] to have a length of 1 but got 4` |
| 018 | `environments.test.ts` "numeric limit" | both cases fail |
| 019 | `limits.test.ts` "every route charges a bucket" | 16 routes listed |
| 020 | `monero.test.ts` "no destination" | `status: 'sending'` |
| 021 | `audit.test.ts` "credential in a URL" | rule missing |

**Re-scan after the fixes.** The same categories were walked again over the diff: no new
unparameterised SQL, no new read-then-write on a counted column, no new route without
`authenticate`/`requireRole`/`limit` (the new sweep enforces the last), no new sink in the
client, no secret in the tree (`audit:secrets`, `audit:history` clean including the new files),
no dependency added. The `__Host-` change was checked for the onion path (bare names kept) and
for logout (clears the prefixed names).

**What could not be run here.** A PostgreSQL instance. The five concurrency fixes are written in
dialect-neutral SQL and are correct by construction under READ COMMITTED (a conditional `UPDATE`
re-evaluates its `WHERE` after acquiring the row lock), and the tests stage the READ COMMITTED
symptom on SQLite — but the suite has not been executed against PostgreSQL in this session, and
because of SEC-2026-022 it is not being executed in CI either. Running it once
(`DATABASE_URL=… npm test`) is item 1 of the owner checklist.

## 5. Owner checklist (within 24 hours)

1. **Copy the CI workflow** so the PostgreSQL job runs:
   `cp deploy/github-ci.yml .github/workflows/ci.yml && git commit -am "ci: sync workflow from deploy/" && git push`.
   Then run the suite against PostgreSQL once yourself: `DATABASE_URL=postgres://… npm test`.
2. **Deploy, and expect one re-login.** After this release every browser on the TLS host is
   signed out once (cookie rename, ADR-0107). Nothing else changes for users. Onion users are
   unaffected.
3. **Run migration 028** — it is applied automatically at boot (`migrate`); it only adds an index.
   If any account has more than one payout in `queued`/`approval_required`/`sending` *right
   now*, the index creation will fail and boot will stop with the constraint name: resolve those
   rows first (`npm run incident -- status` lists in-flight payouts).
4. **Look at the books for the two money findings.** Neither can be exploited on SQLite and no
   evidence of exploitation was sought on a live system (out of scope), so check:
   `GET /api/admin/treasury` — `shortfallXmr` should be 0; the audit log for `bond.claimed`
   rows where the acting moderator is the order's buyer; `ledger_entries` with kind
   `bond_release` appearing twice for one seller within a second; accounts whose `held_pico` > 0
   with no open order, withdrawal or bond to explain it (a stranded escrow from SEC-2026-009).
5. **Backups.** Take one now (`npm run backup`) — the new code keeps the scratch private. If the
   host has other logins, treat any backup made before today as having possibly been readable
   by them for a few seconds; rotating the backup key is cheap (`npm run backup:keygen`).
6. **No secret rotation is required** from this audit: no credential was found in the tree, the
   bundle, the history (1416 blobs) or the lockfile. If your `.npmrc`/registry configuration
   ever carried `user:TOKEN@`, the new scanner will now say so.
7. **Optional hardening you may choose:** lower `SEND_TOKEN_TTL_MS` (default 7 days) to shorten
   the window in which a suspended account's stockpiled sealed-sender tokens still post
   (SEC-2026-023, accepted by design).

## 6. Residual risks

- SEC-2026-023 (sealed-sender tokens survive suspension for the TTL) — accepted; roadmap MD-5.
- SEC-2026-024 (invite into a known channel with a spoofed name) — mitigated by the key-change
  banner; roadmap MD-6.
- The concurrency class in general: five instances were fixed and the idiom is now written down
  (ADR-0106, review checklist, mechanisms register), but the test suite still runs on SQLite by
  default and cannot observe a real PostgreSQL race. The durable answer is the PostgreSQL CI job
  (SEC-2026-022) plus, eventually, a PostgreSQL-only interleaving test.
- Items in §2.4 remain unverified by design: they are stated as such rather than as findings.
