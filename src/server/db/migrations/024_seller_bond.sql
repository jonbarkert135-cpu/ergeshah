-- 024_seller_bond: money a seller stakes on their own honesty (MKT-6, ADR-0086).
--
-- The proposal this comes from burnt a vendor's bond after three complaints. Both halves of
-- that are wrong: three complaints is three coordinated accounts away from robbing an honest
-- seller, and burning the money — or keeping it — makes the platform the beneficiary of
-- forfeiture, which is the last thing that should ever pay. Here a bond is held, never spent
-- by us, and it moves in exactly one direction that is not back to the seller: to a buyer a
-- moderator found was harmed.
--
--   * `bond_pico` — how much of this seller's balance is staked. The money itself lives where
--     all money lives, as `held_pico` on their account with `bond_hold` entries in the
--     ledger; this column is the marketplace's view of it.
--   * `bond_posted_at` — when it was last topped up, which starts the cool-off. A bond that
--     can be pulled the moment a dispute looks likely is a bond that guarantees nothing.
--
-- reversible: yes — drop the columns and release the holds; the ledger keeps the history
-- either way, because the ledger is the record and these two columns are not.

ALTER TABLE sellers ADD COLUMN bond_pico BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sellers ADD COLUMN bond_posted_at BIGINT;
