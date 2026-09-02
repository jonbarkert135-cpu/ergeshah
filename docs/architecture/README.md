# Architecture

- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — the four boxes (browser, proxy, app,
  database), the trust boundaries between them, the module layout, the domain boundaries of
  the modular monolith, and the request lifecycle.
- [`../DECISIONS.md`](../DECISIONS.md) — every architectural decision with its alternatives
  and its cost. New decisions get an ADR; changed ones get a superseding entry.
- [`../PERFORMANCE.md`](../PERFORMANCE.md) — where the time goes, and the budgets the tests
  enforce.
- [`../ROADMAP.md`](../ROADMAP.md) — what is deliberately not built yet.

**Code:** `src/server/app.ts` (wiring), `src/server/routes/` (one module per domain),
`src/server/lib/` (what two domains share), `src/shared/` (imported by both sides).

**Kept honest by:** `test/architecture.test.ts` reads every import in `src/` and fails when
one crosses a domain boundary, and fails when a route module is missing from the domain
table in `ARCHITECTURE.md`.
