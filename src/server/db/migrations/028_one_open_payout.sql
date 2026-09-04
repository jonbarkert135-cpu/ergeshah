-- 028_one_open_payout: one payout in flight per account, as a constraint (finding
-- SEC-2026-010, ADR-0105).
--
-- `POST /api/wallet/withdrawals` and `POST /api/wallet/refund` refuse a second payout while
-- one is `queued`, `approval_required` or `sending` ("finish or cancel your pending payout
-- first"). That rule did two jobs: it kept the queue readable, and it made the automatic
-- ceiling (`AUTO_PAYOUT_MAX_XMR`, ADR-0076) mean something — the rolling 24-hour sum in
-- `queueWithdrawal` only sees payouts that have committed. It was enforced by a `SELECT`
-- before the transaction. On PostgreSQL under READ COMMITTED, several requests arriving
-- together each saw no pending row and each queued a payout under the ceiling, so a balance
-- well above the ceiling could leave in pieces with no administrator's signature on any of
-- them — the control that limits what a stolen session can take, undone by concurrency.
--
-- The same shape as migration 007: the rule becomes a partial unique index, so the database
-- holds it for every request at once, and the loser of a race gets the constraint violation
-- that the route maps to the existing `409 payout_pending`.
--
-- reversible: yes — drop the index. The application check stays and keeps the sequential
-- case correct; only the concurrent guarantee goes with it.

CREATE UNIQUE INDEX withdrawals_one_open_per_user
  ON withdrawals(user_id)
  WHERE status IN ('queued', 'approval_required', 'sending');
