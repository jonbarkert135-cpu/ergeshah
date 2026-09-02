# Testing

- [`../TESTING.md`](../TESTING.md) — how to run the suite, what each file defends, the map
  from the attack classes in point 53 and the cryptographic test kinds in point 54 to the
  files that cover them, and an honest list of what is *not* covered.
- [`../AUDIT.md`](../AUDIT.md) — the checks that are not tests: bundle budget, secret scan,
  git history, migration checksums, supply chain.
- [`../SECURITY_REVIEW.md`](../SECURITY_REVIEW.md) — every review finding names the test
  that closed it. A finding without one is not closed.

**Code:** `test/` (one runner, no mocks of our own code, a real server on an in-memory
database), `test/helpers.ts` (`startTestServer`, a browser-shaped `TestClient`),
`scripts/lint.mjs` and `scripts/audit.mjs` (checks that run in `npm run check` / `audit`).

**Kept honest by:** `test/audit.test.ts` — the scanners are tested too, because a scanner
with a broken regex is a green pipeline that checks nothing.
