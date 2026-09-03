-- 016_seller_standing_decay: a level that can fall (ADR-0072).
--
-- Migration 015 gave a seller a level and the catalogue position that comes with it, and made
-- it impossible to fake: only money this escrow moved counts. What it could not do is take a
-- level away. A seller who traded for a month and left kept their place above everybody who
-- is trading today, and a suspended seller came back to exactly the standing they had when
-- they were suspended — the catalogue hid their listings and forgot nothing else.
--
-- Two columns fix both, and neither destroys history: `settled_pico` and the count of
-- completed orders remain the earned level, and these two say how much of it is *shown*.
--
--  * `sellers.last_settled_day` — the day of the seller's most recent settled sale, at day
--    granularity like every other long-lived date here (ADR-0018). NULL means no sale has
--    been settled since this column existed; the sweep in `lib/reputation.ts` starts the
--    clock for anyone who already has standing, so decay begins at deployment rather than
--    retroactively punishing a seller for a column that did not exist when they traded.
--  * `sellers.level_penalty` — steps subtracted for suspensions, one per suspension, capped
--    at 3 (which is level 0 for any seller). It is not a second reputation number: it only
--    ever subtracts from the level the seller's own trade earned, so the way back up is more
--    trade rather than an administrator's forgiveness.
--
-- The effective level is `max(0, earned - dormancy_steps - level_penalty)`, computed in one
-- function (`standingLevel`) and materialised into `sellers.level` and `listings.rank_key`
-- by the two writers that already maintain them: a settled sale, and a daily sweep.
--
-- reversible: yes — drop both columns. `sellers.level` then stops falling and nothing else
-- changes; the earned level is still derivable from `settled_pico` and `orders`.

ALTER TABLE sellers ADD COLUMN last_settled_day INTEGER;
ALTER TABLE sellers ADD COLUMN level_penalty INTEGER NOT NULL DEFAULT 0
  CHECK (level_penalty BETWEEN 0 AND 3);
