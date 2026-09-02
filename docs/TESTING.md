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
| `docs.test.ts` | Documentation | Every route, table and environment variable is documented, and nothing documented has disappeared |

The three suites marked **Security** are the ones that would catch a regression an attacker
could use directly. They are not separated into a different command on purpose: a security
check you can skip is a security check that gets skipped.

## Writing a test

- Use `startTestServer()`, `register()`, `promote()`, `approveSeller()` from `test/helpers.ts`.
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
