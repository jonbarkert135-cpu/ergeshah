-- 008_search: an index for listing search, so that browsing stops scanning the table.
--
-- Point 47 of the brief. Until now search was `LOWER(title) LIKE '%term%'`, which no index
-- can serve: every query read every active listing and its description. That is both slow
-- and a denial-of-service lever — one cheap request per attacker, unbounded work per
-- request.
--
-- The replacement is the oldest trick there is: an inverted index of words, one row per
-- (term, listing). It is portable (no FTS5, no tsvector, so SQLite and PostgreSQL run the
-- same SQL), it needs no extension, and a lookup is an index range scan.
CREATE TABLE listing_terms (
  term TEXT NOT NULL CHECK (length(term) BETWEEN 2 AND 32),
  listing_id TEXT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
  PRIMARY KEY (term, listing_id)
);

-- Re-indexing one listing deletes its rows first, and that lookup goes the other way round.
CREATE INDEX listing_terms_listing_idx ON listing_terms(listing_id);

-- Keyset pagination orders by (created_day, id) within the active listings, so the index
-- carries the sort as well as the filter and a page is a seek, never an offset scan.
CREATE INDEX listings_page_idx ON listings(status, created_day, id);
