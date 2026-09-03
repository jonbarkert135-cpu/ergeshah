-- 010_session_rotation: a session token that does not stay the same for thirty days.
--
-- The `sessions` row already had `expires_at` (absolute lifetime) and `last_seen_day`,
-- but nothing read the second one: an abandoned session stayed valid for its full TTL,
-- and the token itself never changed. Two columns fix both halves.
--
-- `previous_token_hash` exists only so that rotation is not a race. Two requests can be
-- in flight when the token changes; the one that left before the new cookie arrived
-- still carries the old value. It is accepted for a short grace window after
-- `rotated_at` and refused afterwards, so a captured cookie ages out on its own.

ALTER TABLE sessions ADD COLUMN previous_token_hash TEXT;
ALTER TABLE sessions ADD COLUMN rotated_at INTEGER NOT NULL DEFAULT 0;

CREATE INDEX sessions_previous_token_idx ON sessions(previous_token_hash);
