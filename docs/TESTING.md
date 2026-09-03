# Testing

```
npm test              # everything, ~20 s
npx vitest run test/limits.test.ts
npx vitest            # watch mode
```

One runner (Vitest), no mocks of our own code, no fixtures database. Every test that needs a
server starts a real one on an in-memory SQLite database with the real routes, the real
middleware and the real crypto — `startTestServer()` in `test/helpers.ts`. A test that lies
about the system is worse than no test, and the cheapest way to lie is to test a mock.

## What the suites are for

| File | Kind | What it defends |
| --- | --- | --- |
| `hkdf.test.ts`, `protocol.test.ts`, `padding.test.ts` | Unit / property | Key derivation against published vectors; the ratchet's properties (forward secrecy, out-of-order delivery, replay refusal); padding round-trips and bucket boundaries |
| `recovery.test.ts`, `verification.test.ts`, `pgp.test.ts`, `linking.test.ts` | Integration | Recovery phrases against an independent BIP-39 implementation, safety numbers and the QR encoder against an independent decoder, PGP login, second-device linking |
| `auth.test.ts`, `messaging.test.ts`, `market.test.ts`, `delivery.test.ts`, `moderation.test.ts` | Integration | The API as a browser uses it: cookies, CSRF header, state machines, ownership |
| `authorization.test.ts` | **Security** | Walks Fastify's whole route table and calls every endpoint anonymously; anything not on an explicit public allowlist must answer 401. Also ownership and staff-role refusals, and that refusals are audited |
| `limits.test.ts` | **Security** | Per-operation buckets, per-account fairness, oversized bodies, 500s that leak nothing, login responses that do not reveal whether an account exists |
| `hardening.test.ts` | **Security** | Security headers, URL-scheme allowlist in the DOM builder, timeouts, parameter length |
| `defaults.test.ts` | **Security** | Privacy by default: the shipped configuration is the private one, and no protection is a setting |
| `migrations.test.ts` | Integration | Migrations apply to an empty database, twice is a no-op, hot columns are indexed |
| `client.test.ts` | Unit | The DOM builder escapes, and the router does not trust the fragment |
| `audit.test.ts` | Unit | The audit scanners themselves — a scanner with a broken regex is a green CI that checks nothing |
| `security.test.ts` | **Security** | One suite per attack class in point 53: the attacks that cross two other suites, and the sweeps nobody could keep by hand (every unsafe route without a CSRF token, every table checked for a message plaintext) |
| `cryptography.test.ts` | **Security** | Point 54, per kind: published vectors, negative, malformed input, replay, corrupted ciphertext, wrong key, wrong identity, nonce misuse, session reset |
| `incident.test.ts` | **Security** | `scripts/incident.mjs` against a real database: a procedure that has never been run is a wish |
| `observability.test.ts` | **Security** | Health is administrator-only, and the document it returns is numbers, booleans and four fixed words — a field that names a route or an account fails here (point 85) |
| `resources.test.ts` | **Security** | The ceilings a token bucket cannot enforce: concurrent connections, socket timeouts, body size, PostgreSQL statement and idle-transaction timeouts (point 86) |
| `api.test.ts` | **Security** | The interface itself: the `/api/v1` prefix, `X-API-Version`, every error code documented, one error envelope everywhere, `Retry-After` on a 429, no database structure in a message, and no WebSocket anywhere (points 87–89) |
| `environments.test.ts` | **Security** | Development, test and production are separated: production refuses a missing secret and a `development-only-` placeholder, `NODE_ENV` typos stop the boot, and a test database is in memory (point 91) |
| `adr.test.ts` | Documentation | Every ADR is indexed under `docs/adr/`, every index link resolves, records keep their template, and `docs/CHANGE_REVIEW.md` carries both regression questions and the priority ladder in order (points 92–95) |
| `docs.test.ts` | Documentation | Every route, table and environment variable is documented, and nothing documented has disappeared |

The suites marked **Security** are the ones that would catch a regression an attacker
could use directly. They are not separated into a different command on purpose: a security
check you can skip is a security check that gets skipped.

## The attack classes of point 53, and where each one is covered

| Class | Primary | Also |
| --- | --- | --- |
| Authentication | `auth.test.ts` | `security.test.ts` (forged, truncated, expired and orphaned tokens), `pgp.test.ts`, `recovery.test.ts` |
| Authorization | `authorization.test.ts` | `security.test.ts` (a demotion takes effect on the next request), `moderation.test.ts` |
| E2EE | `messaging.test.ts`, `protocol.test.ts` | `security.test.ts` (a substituted signed prekey is refused; no column holds a plaintext) |
| Replay | `protocol.test.ts` | `security.test.ts` (a cookie captured before a password change; a device-link code), `cryptography.test.ts`, `recovery.test.ts` |
| Key rotation | `protocol.test.ts` | `security.test.ts` (the rotated prekey is served, a revoked identity never returns) |
| Session invalidation | `auth.test.ts` | `security.test.ts` (revoke one from another, sign out everywhere, suspension) |
| XSS | `client.test.ts`, `hardening.test.ts` | `security.test.ts` (markup stored as data, CSP on every response including errors) |
| CSRF | `auth.test.ts` | `security.test.ts` (a sweep of every unsafe route with no token, and a token from another browser) |
| Injection | `search.test.ts` | `security.test.ts` (SQL as data, prototype pollution, line breaks in single-line fields) |
| IDOR | `authorization.test.ts` | `security.test.ts` (another pair's order, delivery, notification and envelopes), `notifications.test.ts`, `delivery.test.ts` |
| Race conditions | `integrity.test.ts` | `security.test.ts` (contested registration, concurrent prekey claims) |
| Rate limits | `limits.test.ts` | `security.test.ts` (prekey exhaustion) |
| Privilege escalation | `moderation.test.ts` | `security.test.ts` (role in a registration body, suspended account, staff and messages) |

The nine cryptographic test kinds of point 54 are mapped in the header comment of
`test/cryptography.test.ts`, next to the file that covers each one.

## Writing a test

- Use `startTestServer()`, `register()`, `promote()`, `approveSeller()` from `test/helpers.ts`.
  The test client solves the proof-of-work challenge and retries by itself, exactly as the
  browser client does, so a test that registers or logs in exercises that gate without
  saying anything about it. Pass a fifth argument (`retried = true`) to `client.request()`
  to see the raw `428`, and `startTestServer({ powBits: 0 })` to turn the gate off for a
  suite that is about something else (`test/onion.test.ts` does).
  `TestClient` behaves like a browser: it keeps cookies and sends the CSRF header.
- `FAST_KDF` lowers Argon2id parameters. Use it everywhere except tests *about* the KDF —
  the real parameters take a second each and the plumbing is what is under test.
- **Assert on the database, not only on the response.** The most valuable tests here read
  every table afterwards and check what is *not* there — `test/delivery.test.ts` dumps the
  whole schema and asserts a shipping address appears nowhere.
- No `.only` (the linter rejects it: it silently disables the suite while CI stays green).
- No `Math.random` (the linter rejects it: use `node:crypto`, so a failure reproduces).
- A regression test names the bug in the test name, not in a comment.

## What is not covered, honestly

- **PostgreSQL** is exercised only through the shared driver interface; CI runs SQLite.
  A Postgres job in CI is OPS-2 in `docs/ROADMAP.md`.
- **The browser** is not driven end-to-end. The client is tested at the module level
  (`client.test.ts`) and by the shared crypto tests; there is no Playwright run, because a
  browser harness is a large dependency tree for the class of bug our CSP already forbids.
- **Load and traffic analysis.** Rate limits are tested for correctness, not under real
  concurrency; the metadata claims in `docs/THREAT_MODEL.md` are argued, not measured.
