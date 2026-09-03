-- 015_seller_standing: a seller's level, and the catalogue order that pays for it (ADR-0068).
--
-- The chat is end-to-end encrypted and unread, so nothing here can *detect* a deal taken off
-- the platform. What it can do is make an on-platform sale the only one that counts. Two
-- columns and a sort key:
--
--  * `sellers.settled_pico` — the seller's on-platform earnings, added to inside the same
--    transaction that settles an order. It is a sum of ledger movements that already
--    happened, never a number a request supplies, so it cannot be inflated without moving
--    real money through an escrow that charges a fee to do it.
--  * `sellers.level` — 0 to 3, derived from `settled_pico` and the count of completed
--    orders (`lib/reputation.ts`). Derived, so it is recomputed rather than granted.
--  * `listings.rank_key` — `level * 100000 + created_day`, the catalogue's sort key. It
--    lives on the listing because keyset pagination sorts by one indexed expression on the
--    driving table (ADR-0030), and a join's column cannot be that. Maintained by the code
--    that writes a listing and by the level change itself; a seller has few listings.
--
-- The day count is under 20,800 today and the multiplier is 100,000, so a level boundary is
-- worth more than any age difference and the two never overlap — until the year 2243, which
-- is a comfortable margin for a marketplace.
--
-- reversible: yes — DROP INDEX listings_rank_idx, then drop the three columns. Nothing else
-- references them, and losing them costs a recomputation, not a fact: `settled_pico` can be
-- re-derived from `ledger_entries`, and everything else from it.

ALTER TABLE sellers ADD COLUMN settled_pico BIGINT NOT NULL DEFAULT 0 CHECK (settled_pico >= 0);
ALTER TABLE sellers ADD COLUMN level INTEGER NOT NULL DEFAULT 0 CHECK (level BETWEEN 0 AND 3);
ALTER TABLE listings ADD COLUMN rank_key BIGINT NOT NULL DEFAULT 0;

-- Existing listings keep their age and start at level 0, which is exactly what the formula
-- says about a seller whose settled volume is not yet recorded.
UPDATE listings SET rank_key = created_day;

CREATE INDEX listings_rank_idx ON listings(status, rank_key, id);
