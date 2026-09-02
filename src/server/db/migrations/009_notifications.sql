-- 009_notifications: an internal notification inbox (point 48).
--
-- The hard part of this table is what it must *not* hold. A notification about a message is
-- exactly the kind of row that quietly undoes end-to-end encryption: a sender, a channel, a
-- preview or even a count per conversation would hand the server the social graph and the
-- traffic pattern the messaging design refuses to store (see docs/PRIVACY.md).
--
-- So: no free text, no sender column, no channel column. `kind` is a closed set, `subject`
-- points at a marketplace record that is already server-visible (an order, a listing, an
-- application), and `detail` is a status word from a closed set of statuses — never anything
-- a user typed. A message notification carries no subject at all: it says "something arrived
-- for you", which the client already knows how to resolve by fetching its envelopes.
CREATE TABLE notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN (
    'message', 'order', 'seller_application', 'moderation', 'review', 'dispute'
  )),
  subject_type TEXT NOT NULL CHECK (subject_type IN ('', 'order', 'listing', 'review', 'user')),
  subject_id TEXT NOT NULL DEFAULT '' CHECK (length(subject_id) <= 64),
  detail TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 32),
  created_at INTEGER NOT NULL,
  read_at INTEGER
);

-- The inbox query: newest first for one account, keyset-paginated like listing search.
CREATE INDEX notifications_inbox_idx ON notifications(user_id, created_at, id);

-- At most one unread "you have mail" row per account. Without this, the table would count
-- messages per recipient — a traffic-analysis column with a friendly name. Coalescing is
-- enforced by the schema rather than by the writer remembering to.
CREATE UNIQUE INDEX notifications_one_unread_message
  ON notifications(user_id) WHERE kind = 'message' AND read_at IS NULL;
