# Testing

- [`../TESTING.md`](../TESTING.md) — how to run the suite, what each file defends, the map
  from the attack classes in point 53 and the cryptographic test kinds in point 54 to the
  files that cover them, and an honest list of what is *not* covered.
- [`../AUDIT.md`](../AUDIT.md) — the checks that are not tests: bundle budget, secret scan,
  git history, migration checksums, supply chain.
- [`../RELEASE.md`](../RELEASE.md) — the gate that runs all of it from a clean clone, and the
  security baseline every release is compared against.
- [`../SECURITY_REVIEW.md`](../SECURITY_REVIEW.md) — every review finding names the test
  that closed it. A finding without one is not closed.

**Code:** `test/` (one runner, no mocks of our own code, a real server on an in-memory
database), `test/helpers.ts` (`startTestServer`, a browser-shaped `TestClient`),
`scripts/lint.mjs`, `scripts/audit.mjs`, `scripts/audit-inventory.mjs` (checks that run in
`npm run check` / `audit`), `scripts/release.mjs` and `scripts/clean-clone.mjs`.

**Kept honest by:** `test/audit.test.ts` — the scanners are tested too, because a scanner
with a broken regex is a green pipeline that checks nothing.
