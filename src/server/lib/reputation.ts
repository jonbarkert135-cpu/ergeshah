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

export async function sellerReputation(db: Db, sellerUserId: string) {
  const rating = await ratingOver(db, "seller_user_id", sellerUserId);
  const orders = await db.get<{ completed: number; disputed: number }>(
    `SELECT
       (SELECT COUNT(*) FROM orders WHERE seller_user_id = ? AND status = 'completed') AS completed,
       (SELECT COUNT(DISTINCT e.order_id) FROM order_events e JOIN orders o ON o.id = e.order_id
         WHERE o.seller_user_id = ? AND e.to_status = 'disputed') AS disputed`,
    [sellerUserId, sellerUserId],
  );
  return {
    ...rating,
    completedOrders: Number(orders?.completed ?? 0),
    /** Orders that were disputed at any point, whichever way they were settled. */
    disputedOrders: Number(orders?.disputed ?? 0),
  };
}
