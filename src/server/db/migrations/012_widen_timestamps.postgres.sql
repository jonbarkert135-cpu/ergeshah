-- 012_widen_timestamps (PostgreSQL only): millisecond timestamps need 64 bits.
--
-- Found by running the test suite against PostgreSQL for the first time (OPS-2): every
-- INSERT of a `Date.now()` value failed with `value "1788434609691" is out of range for type
-- integer`. SQLite's INTEGER is up to 64 bits, PostgreSQL's is exactly 32, and a millisecond
-- epoch passed int4 in 1970. The PostgreSQL driver had therefore never worked — not "worked
-- slowly", not "worked except under load": the server could not finish its own migrations.
--
-- The released migrations are not edited (docs/DATABASE.md); this widens the columns
-- afterwards, on the only dialect that needs it. Day numbers (`*_day`, ~20000) and the
-- small counters (`rating`, `key_id`, `signed_prekey_id`, `price_minor`) stay INTEGER —
-- widening them would be cargo cult, and `price_minor` in int4 is a documented ceiling of
-- about 21 million currency units per listing.
--
-- reversible: yes — ALTER TABLE … ALTER COLUMN … TYPE INTEGER on the same columns, which
-- succeeds only while every value still fits in 32 bits (i.e. never, for a live database).
-- The real rollback is a restore, as it is for every migration here.

ALTER TABLE sessions ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE sessions ALTER COLUMN expires_at TYPE BIGINT;
ALTER TABLE sessions ALTER COLUMN rotated_at TYPE BIGINT;
ALTER TABLE devices ALTER COLUMN revoked_at TYPE BIGINT;
ALTER TABLE one_time_prekeys ALTER COLUMN claimed_at TYPE BIGINT;
ALTER TABLE envelopes ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE envelopes ALTER COLUMN expires_at TYPE BIGINT;
ALTER TABLE orders ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE orders ALTER COLUMN updated_at TYPE BIGINT;
ALTER TABLE order_events ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE audit_log ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE rate_limits ALTER COLUMN updated_at TYPE BIGINT;
ALTER TABLE device_links ALTER COLUMN expires_at TYPE BIGINT;
ALTER TABLE auth_challenges ALTER COLUMN expires_at TYPE BIGINT;
ALTER TABLE deliveries ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE deliveries ALTER COLUMN expires_at TYPE BIGINT;
ALTER TABLE notifications ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE notifications ALTER COLUMN read_at TYPE BIGINT;
ALTER TABLE attachments ALTER COLUMN created_at TYPE BIGINT;
ALTER TABLE attachments ALTER COLUMN expires_at TYPE BIGINT;
