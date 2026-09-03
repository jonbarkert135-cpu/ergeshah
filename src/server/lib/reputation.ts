/**
 * Reputation that is hard to buy (point 46).
 *
 * A rating is an average over *authors*, not over reviews: if one account reviews a seller
 * ten times (ten completed orders, ten five-star reviews) it counts once, with its latest
 * verdict. That removes the cheapest manipulation — a seller's own second account buying
 * from itself on repeat — without a heuristic and without collecting anything new. The
 * number of distinct reviewers is published beside the average, so "5.0 from 1 buyer" reads
 * as exactly what it is; and disputes are counted where they happened, in `order_events`,
 * so a seller cannot make one disappear by settling it.
 *
 * What this does not stop: ten accounts. That needs identity, which this project refuses to
 * collect; the honest residual is in `docs/THREAT_MODEL.md`.
 */
import type { Db } from "../db/index.ts";
import { PICO_PER_XMR } from "../../shared/money.ts";

/**
 * One row per (author, subject): the author's visible review of their most recent order.
 * Reviews carry only a day, so two on the same day are ordered by the order they belong to.
 */
const LATEST_PER_AUTHOR = (column: "seller_user_id" | "listing_id") => `
  SELECT r.rating
    FROM reviews r
   WHERE r.${column} = ? AND r.status = 'visible'
     AND r.id = (SELECT r2.id FROM reviews r2
                  WHERE r2.${column} = r.${column} AND r2.author_user_id = r.author_user_id
                    AND r2.status = 'visible'
                  ORDER BY (SELECT o.created_at FROM orders o WHERE o.id = r2.order_id) DESC LIMIT 1)`;

async function ratingOver(db: Db, column: "seller_user_id" | "listing_id", id: string) {
  const stats = await db.get<{ reviewers: number; average: number | null }>(
    // audit:allow — the interpolated text is one of two literal column names, never input.
    `SELECT COUNT(*) AS reviewers, AVG(rating) AS average FROM (${LATEST_PER_AUTHOR(column)}) latest`,
    [id],
  );
  const total = await db.get<{ count: number }>(
    // audit:allow — same two literal column names.
    `SELECT COUNT(*) AS count FROM reviews WHERE ${column} = ? AND status = 'visible'`,
    [id],
  );
  return {
    reviewCount: Number(total?.count ?? 0),
    distinctReviewers: Number(stats?.reviewers ?? 0),
    averageRating:
      stats?.average === null || stats?.average === undefined
        ? null
        : Number(Number(stats.average).toFixed(2)),
  };
}

export const listingRating = (db: Db, listingId: string) => ratingOver(db, "listing_id", listingId);

/**
 * Levels, and what each one costs in on-platform trade (ADR-0068). Both conditions have to
 * hold: volume alone is one large sale, orders alone are a hundred free listings. Ordered
 * highest first, so the first row that matches is the answer.
 */
const LEVELS: Array<{ level: number; settledPico: number; completedOrders: number }> = [
  { level: 3, settledPico: 50 * PICO_PER_XMR, completedOrders: 100 },
  { level: 2, settledPico: 5 * PICO_PER_XMR, completedOrders: 20 },
  { level: 1, settledPico: PICO_PER_XMR / 2, completedOrders: 3 },
];

export function levelFor(settledPico: number, completedOrders: number): number {
  return (
    LEVELS.find(
      (row) => settledPico >= row.settledPico && completedOrders >= row.completedOrders,
    )?.level ?? 0
  );
}

/**
 * A settled sale, counted where it happened.
 *
 * Called inside the transaction that settles the order, with what the seller actually
 * earned — so a sale taken off the platform adds nothing here, and the seller's level and
 * their place in the catalogue are the price of taking it (ADR-0068). Nothing in this
 * function reads the chat, and nothing needs to: it only counts money this escrow moved.
 *
 * When the level changes, the seller's listings are re-keyed in the same transaction. A
 * seller has tens of listings, not thousands.
 * ponytail: one UPDATE over a seller's listings; a batched rebuild if a seller ever has
 * enough listings for it to matter.
 */
export async function recordSettledSale(
  tx: Db,
  sellerUserId: string,
  earningsPico: number,
): Promise<void> {
  const row = await tx.get<{ settled_pico: number; level: number }>(
    `UPDATE sellers SET settled_pico = settled_pico + ? WHERE user_id = ?
      RETURNING settled_pico, level`,
    [earningsPico, sellerUserId],
  );
  if (!row) return; // the seller row is gone (a deleted account); the ledger still balances
  const completed = await tx.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM orders WHERE seller_user_id = ? AND status = 'completed'",
    [sellerUserId],
  );
  const level = levelFor(Number(row.settled_pico), Number(completed?.count ?? 0));
  if (level === Number(row.level)) return;
  await tx.run("UPDATE sellers SET level = ? WHERE user_id = ?", [level, sellerUserId]);
  await tx.run("UPDATE listings SET rank_key = ? * 100000 + created_day WHERE seller_user_id = ?", [
    level,
    sellerUserId,
  ]);
}

/** The catalogue sort key: level first, then age. Kept in one place so the two writers agree. */
export const rankKey = (level: number, createdDay: number) => level * 100_000 + createdDay;

export async function sellerReputation(db: Db, sellerUserId: string) {
  const rating = await ratingOver(db, "seller_user_id", sellerUserId);
  const orders = await db.get<{ completed: number; disputed: number }>(
    `SELECT
       (SELECT COUNT(*) FROM orders WHERE seller_user_id = ? AND status = 'completed') AS completed,
       (SELECT COUNT(DISTINCT e.order_id) FROM order_events e JOIN orders o ON o.id = e.order_id
         WHERE o.seller_user_id = ? AND e.to_status = 'disputed') AS disputed`,
    [sellerUserId, sellerUserId],
  );
  const standing = await db.get<{ settled_pico: number; level: number }>(
    "SELECT settled_pico, level FROM sellers WHERE user_id = ?",
    [sellerUserId],
  );
  return {
    ...rating,
    /** 0-3, earned on this platform only (ADR-0068). Volume itself is nobody else's business. */
    level: Number(standing?.level ?? 0),
    completedOrders: Number(orders?.completed ?? 0),
    /** Orders that were disputed at any point, whichever way they were settled. */
    disputedOrders: Number(orders?.disputed ?? 0),
  };
}
