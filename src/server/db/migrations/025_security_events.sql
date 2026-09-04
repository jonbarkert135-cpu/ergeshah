-- 025_security_events: an account's own security history, counted by day (ADR-0090).
--
-- A user cannot notice a sign-in they did not make unless something records that sign-ins
-- happened. The obvious shape for that — one row per event, with a timestamp, an address
-- and a user agent — is a surveillance log with a helpful name, and this project has spent
-- twenty-four migrations not building one.
--
-- So this table stores the smallest thing that still answers the question:
--
--   * `user_id` — whose history it is. Cascades, so a deleted account takes it along.
--   * `kind`    — one of a fixed list in `lib/security_events.ts`. Never free text.
--   * `day`     — days since the epoch, the same coarse clock the rest of the schema uses
--                 for anything long-lived. Not a timestamp: an exact time is a timeline.
--   * `count`   — how many of that kind happened that day, upserted rather than appended.
--
-- What is deliberately absent: an IP address, a user agent, a session id, a device id, a
-- location, a counterparty, a free-text note. Nothing here can be joined to a network
-- identity, and nothing distinguishes two events on the same day from each other.
--
-- The counter also bounds the table: a failed-login flood against one account adds one row
-- a day, not one row an attempt, so an attacker cannot fill the disk through the log that
-- exists to tell on them. Housekeeping deletes anything older than
-- SECURITY_EVENT_RETENTION_DAYS (90 by default).
--
-- reversible: yes — drop the table; the account keeps working and loses only its history.

CREATE TABLE security_events (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  day INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id, kind, day)
);
CREATE INDEX security_events_day_idx ON security_events(day);
