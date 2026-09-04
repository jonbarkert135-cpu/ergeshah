-- 030_widen_timestamps_again (PostgreSQL only): the millisecond columns added since 012.
--
-- Found the first time the PostgreSQL suite ran in CI (SEC-2026-022 closed, 2026-09-04):
-- every INSERT of a `Date.now()` value into a column created after migration 012 failed with
-- `value "1788557607548" is out of range for type integer` — the same defect 012 fixed, on
-- the six columns six later migrations declared INTEGER. Sending a message, committing
-- evidence, minting a sealed-sender token, claiming a payout, recording a dual approval and
-- engaging the lockdown were all 500 on this driver. SQLite's INTEGER is 64 bits, so the
-- shared migrations were correct there and untested here.
--
-- `rate_limits.tokens` is widened too: REAL is float4 on PostgreSQL (24-bit mantissa), and
-- the `upload_bytes` bucket holds up to 134 217 728 tokens, past the point where every
-- integer is representable. SQLite's REAL was always a double.
--
-- reversible: yes — ALTER TABLE … ALTER COLUMN … TYPE INTEGER (and TYPE REAL for tokens) on
-- the same columns, which succeeds only while every value still fits, i.e. never for a live
-- database. The real rollback is a restore, as for every migration here.

ALTER TABLE envelopes ALTER COLUMN available_at TYPE BIGINT;
ALTER TABLE lockdown ALTER COLUMN engaged_at TYPE BIGINT;
ALTER TABLE order_evidence ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE send_tokens ALTER COLUMN expires_at TYPE BIGINT;
ALTER TABLE withdrawal_approvals ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE withdrawals ALTER COLUMN claimed_at TYPE BIGINT;
ALTER TABLE rate_limits ALTER COLUMN tokens TYPE DOUBLE PRECISION;
