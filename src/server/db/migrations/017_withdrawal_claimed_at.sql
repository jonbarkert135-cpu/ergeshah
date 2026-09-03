-- 017_withdrawal_claimed_at: when the payout worker took the row (ADR-0073).
--
-- `sending` is a one-way door by design (ADR-0070): nothing re-queues a payout, because only
-- the process holding the spend key knows whether a transaction was signed, and an automatic
-- retry on an uncertain outcome pays somebody twice. The cost of that decision is a row an
-- operator has to resolve by hand — and until now nothing recorded *when* it entered
-- `sending`, so "is this stuck or did the worker take it four seconds ago" was a question the
-- database could not answer.
--
-- One nullable column, written by `claimWithdrawal` in the same statement that marks the row
-- `sending`. Millisecond precision rather than the day granularity used for long-lived dates
-- (ADR-0018): this is an operational timer measured in minutes, it is deleted with the row,
-- and rounding it to a day would make it useless for the one question it exists to answer.
--
-- reversible: yes — drop the column. The queue works exactly as before; an operator loses the
-- age of a stuck payout and gets it back from the worker's own logs.

ALTER TABLE withdrawals ADD COLUMN claimed_at INTEGER;
