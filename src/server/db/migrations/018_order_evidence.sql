-- 018_order_evidence: a commitment to the bytes, since the bytes stay encrypted (ADR-0074).
--
-- A dispute used to be two stories: "he sent a broken file", "I sent the right one". The
-- channel is end-to-end encrypted and this server cannot read it, so there was nothing a
-- moderator could compare. What a server that must not see a file can still do is hold a
-- commitment to it.
--
--  * `digest` — 64 characters of hex, computed *in the browser* as
--    `HMAC-SHA256(order id, file bytes)`. Keyed, not a bare hash, deliberately: a bare
--    SHA-256 of a widely circulated file is recognisable to anybody holding that file, which
--    would make this table an index of who exchanged which known file. Keyed with an
--    unguessable order id it means nothing to anyone who does not already know the order —
--    and both parties and the moderator do.
--  * `kind` — a word from a fixed list (`lib/evidence.ts`), never the party's own text. The
--    one piece of dispute prose this platform stores is the buyer's reason, and it already
--    lives in `reports`.
--  * `created_at` — milliseconds, because `beforeDispute` compares it against the dispute's
--    own `order_events` row and a day would not answer that. It is published as a day
--    (ADR-0018) and deleted with the order.
--
-- The unique key makes a re-commitment of the same bytes a no-op rather than a second row: a
-- party who clicks twice has not produced new evidence.
--
-- reversible: yes — drop the table. Disputes go back to being decided on prose, which is what
-- they were before this migration.

CREATE TABLE order_evidence (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (order_id, user_id, digest)
);

CREATE INDEX order_evidence_order_idx ON order_evidence(order_id, created_at);
