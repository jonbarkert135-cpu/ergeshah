-- 021_category_folding: one category, not three spellings of it (ADR-0082).
--
-- Categories are the sellers' own words — a fixed enum is an argument about what belongs in
-- it, and this marketplace does not want to have that argument for every seller. What it did
-- want, and did not have, is folding: "Consulting", "consulting " and "CONSULTING" were three
-- categories, each with its own page of results and none of them complete.
--
-- `asCategory` in `lib/validate.ts` now folds on write. This brings the rows that were
-- written before it existed into the same shape, as far as portable SQL can: lowercase and
-- trimmed. The rest of the folding — accents, punctuation, inner runs of whitespace — needs
-- Unicode normalisation, which is not SQL; those rows are folded the next time their listing
-- is edited, and the count on `GET /api/market/categories` is the only place a leftover
-- spelling can still show, where it is visible rather than silent.
--
-- The index is for that endpoint: a grouped count over active listings, which otherwise
-- walks the catalogue.
--
-- reversible: the index, yes. The folding is a data change and is not undone — the original
-- capitalisation of a category name is not a fact worth keeping.

UPDATE listings SET category = LOWER(TRIM(category));

CREATE INDEX listings_category_idx ON listings(status, category);
