-- 006_audit_result: an audit entry records how the action ended, and does not live forever.
--
-- `result` closes the obvious gap in an administrative trail: without it the log answers
-- "who tried what" but not "did it work", which is exactly the question asked after an
-- incident. Three values only — ok, denied, failed — because free text in this column
-- would become the place where someone writes a reason containing personal data.
--
-- Existing rows are backfilled as 'ok': every entry written before this migration was
-- written after the action succeeded, so that is the truthful value rather than a guess.

ALTER TABLE audit_log ADD COLUMN result TEXT NOT NULL DEFAULT 'ok';

-- Retention is enforced by a sweep (see `pruneAuditLog`), which needs this index to be
-- cheap; `audit_log_created_idx` already covers it, so nothing further is added here.
