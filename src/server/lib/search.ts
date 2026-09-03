/**
 * Listing search: an inverted index of words, and pages that are seeks (point 47).
 *
 * Three properties the previous `LIKE '%term%'` did not have:
 *
 * - **Indexed.** A term lookup is a range scan over `listing_terms`, whose primary key
 *   starts with the term. No query in this module reads a row it will not return.
 * - **Bounded.** The number of terms per query and the page size are both capped, so the
 *   work one request can ask for has a ceiling that does not grow with the catalogue.
 * - **Injection-proof by construction.** A term is what the tokeniser produced: letters and
 *   digits only. It is still passed as a bound parameter, and it can carry no `%`, `_` or
 *   quote even if a future caller forgets to.
 */
import { badRequest } from "./errors.ts";
import type { Db } from "../db/index.ts";

/** Longer than this is a paste, not a word; shorter than two characters is not selective. */
const MIN_TERM = 2;
const MAX_TERM = 32;
/** Per query. Each term costs one index range scan, so the cost of a request is capped. */
const MAX_QUERY_TERMS = 6;
/** Per listing. A description is indexed until this many distinct words, then it stops. */
const MAX_LISTING_TERMS = 200;

/**
 * Words, lowercased, accent-normalised, letters and digits only.
 *
 * NFKD then dropping combining marks means "Gitárok" and "gitarok" index and match the
 * same way; `\p{L}\p{N}` means no punctuation, no wildcard, no control character and no
 * emoji ever becomes a term. That last part also keeps the prefix range below correct
 * under any collation: every term is ASCII-or-letter text with no byte above the range
 * `term < prefix + '\uFFFF'` covers.
 */
export function tokenize(text: string): string[] {
  const words = text
    .normalize("NFKD")
    .replace(/\p{M}+/gu, "")
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((word) => word.length >= MIN_TERM)
    .map((word) => word.slice(0, MAX_TERM));
  return [...new Set(words)];
}

/** The terms a search request asks for, capped. An unparseable query yields none. */
export function queryTerms(text: string): string[] {
  return tokenize(text).slice(0, MAX_QUERY_TERMS);
}

/**
 * (Re)index one listing. Called in the same transaction as the write that changed it, so
 * the index cannot describe a listing that was never committed.
 */
export async function indexListing(
  db: Db,
  listingId: string,
  fields: { title: string; description: string; category: string },
): Promise<void> {
  const terms = tokenize(`${fields.title} ${fields.category} ${fields.description}`).slice(
    0,
    MAX_LISTING_TERMS,
  );
  await db.run("DELETE FROM listing_terms WHERE listing_id = ?", [listingId]);
  for (const term of terms) {
    await db.run("INSERT INTO listing_terms (term, listing_id) VALUES (?, ?)", [term, listingId]);
  }
}

/**
 * SQL fragments that restrict a listing query to the rows matching every term (AND, not
 * OR: a two-word search should narrow, not widen).
 *
 * Each term becomes an `EXISTS` over the index. The range comparison is what the index
 * serves; the `LIKE` next to it is the exact prefix test, kept separate so that a database
 * whose collation orders text differently still returns the right rows rather than
 * silently more of them.
 */
export function termConditions(terms: string[]): { sql: string[]; params: unknown[] } {
  const sql: string[] = [];
  const params: unknown[] = [];
  for (const term of terms) {
    // `IN (subquery)` rather than `EXISTS`: it makes the term index the driving table, so
    // the database reads the handful of listings that match the word instead of walking the
    // active listings and asking about each one. `test/search.test.ts` asserts the plan.
    sql.push(
      `l.id IN (SELECT listing_id FROM listing_terms
                 WHERE term >= ? AND term < ? AND term LIKE ?)`,
    );
    params.push(term, `${term}\uFFFF`, `${term}%`);
  }
  return { sql, params };
}

const CURSOR_RE = /^(\d{1,15})\.([A-Za-z0-9_-]{8,64})$/;

/**
 * A cursor is the sort key of the last row of the previous page: `<sort key>.<id>` — the
 * rank key (seller level and day, ADR-0068) for listings, a millisecond timestamp for the notification inbox. Opaque
 * enough that nobody builds one by hand, cheap enough that the server keeps no state, and
 * stable under inserts — which `OFFSET` is not, and `OFFSET` also makes page 500 cost five
 * hundred pages of work. There is no total count for the same reason.
 */
export function parseCursor(value: unknown): { key: number; id: string } | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw badRequest("cursor must be a string");
  const match = CURSOR_RE.exec(value);
  if (!match) throw badRequest("cursor is not a cursor this server issued", "invalid_cursor");
  return { key: Number(match[1]), id: match[2]! };
}

export function cursorFor(row: { rank_key: number; id: string }): string {
  return `${row.rank_key}.${row.id}`;
}

/**
 * Indexes listings that predate the index (or that a restored backup brought back). Runs
 * once at boot and costs one query when there is nothing to do, which is every boot after
 * the first — a migration cannot do this, because tokenising is not SQL.
 */
export async function backfillSearchIndex(db: Db): Promise<number> {
  const rows = await db.all<{ id: string; title: string; description: string; category: string }>(
    `SELECT id, title, description, category FROM listings
      WHERE NOT EXISTS (SELECT 1 FROM listing_terms t WHERE t.listing_id = listings.id)`,
  );
  for (const row of rows) await indexListing(db, row.id, row);
  return rows.length;
}
