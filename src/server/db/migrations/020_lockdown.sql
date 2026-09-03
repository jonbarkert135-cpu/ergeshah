-- 020_lockdown: the switch an operator throws during a breach (ADR-0080).
--
-- The proposal this replaces was a self-destruct: on detecting unauthorised access, delete
-- the users, the orders and the payments. That is worse than the breach it answers. The
-- ledger is the only record of what this platform *owes people*, so destroying it converts a
-- security incident into a theft from every seller with a balance; a detector that can be
-- triggered is a permanent denial of service handed to whoever can trigger it; and there is
-- no readable message content on this server to save — it is already end-to-end encrypted.
--
-- The correct move in an incident is to freeze, not to burn: stop the bleeding, keep the
-- evidence, keep the books. One row, written by `scripts/incident.mjs`, read by the
-- application before every write:
--
--   * `engaged_at` — when the freeze started, so the log and the operator agree.
--   * `note` — a short line from the operator, shown to nobody: it is for the audit entry.
--
-- What the freeze does is in `lib/lockdown.ts`: every write refused, no new session, no
-- payout claimed, everything still readable. It deliberately does not revoke sessions —
-- `sessions:revoke-all` is a separate command for a separate belief about what was stolen.
--
-- reversible: yes — delete the row (`lockdown:off`), or drop the table and the application
-- stops asking.

CREATE TABLE lockdown (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  engaged_at INTEGER NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
