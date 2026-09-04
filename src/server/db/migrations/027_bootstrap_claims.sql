-- 027_bootstrap_claims: one row that says the first administrator has been created
-- (finding SEC-2026-002, ADR-0104).
--
-- `POST /api/auth/register` gives the first account of a fresh deployment the `admin` role,
-- because somebody has to be able to approve the first seller. It decided that by asking
-- "is the users table empty?" and then inserting — two statements, no lock between them. On
-- SQLite one writer at a time (ADR-0036) hides it; on PostgreSQL under READ COMMITTED two
-- registrations that arrive in the same instant both read an empty table and both insert an
-- administrator. That is the same shape as the one-time prekey race in
-- `docs/SELF_CRITIQUE.md` finding 9, and it has the same answer here: the claim is a row,
-- and the primary key is the lock (ADR-0028, ADR-0060).
--
--   * `id`         — the name of the thing claimed. Exactly one value is used today,
--                    `admin`; the column is text rather than a boolean so that a second
--                    once-per-deployment step (should one ever exist) needs no migration.
--   * `claimed_at` — when it was claimed, in milliseconds. Operational, not user data: it
--                    describes the deployment, and there is no account it can be joined to.
--
-- The claim is inserted in the *same transaction* as the user row, with
-- `ON CONFLICT DO NOTHING RETURNING id`. The winner gets a row back and is the
-- administrator; the loser gets nothing back and is an ordinary user; a registration that
-- fails after the claim rolls both back, so a deployment cannot end up with the claim taken
-- and no administrator to show for it.
--
-- reversible: yes — drop the table. Registration falls back to nothing: the check that
-- reads it would fail, so a rollback means reverting the route with it.

CREATE TABLE bootstrap_claims (
  id TEXT PRIMARY KEY,
  claimed_at BIGINT NOT NULL
);
