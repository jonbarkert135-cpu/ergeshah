# Database

- [`../DATABASE.md`](../DATABASE.md) — every table and column, with what it is allowed to
  hold and what it must never hold.
- [`../PRIVACY.md`](../PRIVACY.md) — the same schema read as a privacy question: why a
  column exists at all, and why its precision is what it is.
- [`../BACKUPS.md`](../BACKUPS.md) — what a copy of this database is worth to an attacker,
  and how long copies are kept.

**Code:** `src/server/db/` — the small driver interface, the SQLite and PostgreSQL drivers,
`migrate.ts`, and `migrations/` (append-only; an applied migration is never edited, and
`npm run migrate:checksums` records their digests).

**Kept honest by:** `test/migrations.test.ts` (they apply to an empty database, a second run
is a no-op, hot columns are indexed), `test/integrity.test.ts` (the invariants hold under
concurrency, in the database rather than in the order requests arrived),
`test/docs.test.ts` (every table the migrations create is documented), and
`npm run audit:migrations`.
