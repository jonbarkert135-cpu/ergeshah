-- 007_integrity: invariants the database enforces itself, so that a race between two
-- requests cannot produce a state the application would never have written on purpose.
--
-- Points 43 and 44 of the brief. Every rule here already existed as an application check
-- (a SELECT followed by an INSERT); a check like that is only as strong as the gap between
-- the two statements, and on PostgreSQL that gap is a network round trip.
--
-- Partial unique indexes are the tool of choice: they cost nothing on the rows that do not
-- match, and both SQLite and PostgreSQL accept the same syntax.

-- One application under review per account. Two concurrent submissions used to produce
-- two pending rows, and two moderators could approve both.
CREATE UNIQUE INDEX seller_applications_one_pending
  ON seller_applications(user_id) WHERE status = 'pending';

-- One *open* order per buyer per listing. A buyer who double-clicks (or replays the
-- request) gets one order, not two; buying the same thing again is allowed once the
-- previous order has finished either way.
CREATE UNIQUE INDEX orders_one_open_per_listing
  ON orders(listing_id, buyer_user_id)
  WHERE status IN ('placed', 'accepted', 'delivered', 'disputed');

-- `orders.listing_id` is a foreign key with no index: every listing lookup that joins
-- orders, and every DELETE cascade check, scanned the table.
CREATE INDEX orders_listing_idx ON orders(listing_id);

-- The moderation queue looks reports up by what they are about; disputes are reports
-- about an order, so this path is now hot.
CREATE INDEX reports_target_idx ON reports(target_type, target_id, status);

-- Reputation is computed per author (see ADR-0028): one buyer, one voice per seller.
CREATE INDEX reviews_author_seller_idx ON reviews(seller_user_id, author_user_id, status);
