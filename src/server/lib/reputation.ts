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
import { today as dayNow } from "./time.ts";

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
 * The level a seller's trade has *earned*, less what dormancy and suspensions take off it
 * (ADR-0072).
 *
 * Decay is deliberately reversible and not punitive: one step per `decayDays` without a
 * settled sale, and a single sale sets the clock back to today, which restores the level the
 * volume already paid for. The catalogue is meant to answer "who is trading here", and a
 * level that only ever rises answers "who once was".
 *
 * A suspension is different, and subtracts permanently: `level_penalty` stays, so the way
 * back is more trade rather than the passage of time. `lastSettledDay` of null means the
 * clock has not started (a seller with no settled sale since the column existed) and nothing
 * is taken off for dormancy.
 */
export function standingLevel(input: {
  settledPico: number;
  completedOrders: number;
  lastSettledDay: number | null;
  penalty: number;
  today: number;
  decayDays: number;
}): number {
  const earned = levelFor(input.settledPico, input.completedOrders);
  const idle =
    input.lastSettledDay === null
      ? 0
      : Math.floor(Math.max(0, input.today - input.lastSettledDay) / input.decayDays);
  return Math.max(0, earned - idle - Math.max(0, input.penalty));
}

/**
 * Writes a seller's level and re-keys their listings, when — and only when — the level
 * actually changed. Every writer of standing goes through here, so the two places that must
 * agree (the level a profile shows and the key the catalogue sorts by) cannot drift apart.
 *
 * ponytail: one UPDATE over a seller's listings; a batched rebuild if a seller ever has
 * enough listings for it to matter.
 */
async function writeLevel(tx: Db, sellerUserId: string, level: number, current: number): Promise<boolean> {
  if (level === current) return false;
  await tx.run("UPDATE sellers SET level = ? WHERE user_id = ?", [level, sellerUserId]);
  await tx.run("UPDATE listings SET rank_key = ? * 100000 + created_day WHERE seller_user_id = ?", [
    level,
    sellerUserId,
  ]);
  return true;
}

interface Standing {
  settled_pico: number;
  level: number;
  level_penalty: number;
  last_settled_day: number | null;
}

async function completedOrdersFor(db: Db, sellerUserId: string): Promise<number> {
  const row = await db.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM orders WHERE seller_user_id = ? AND status = 'completed'",
    [sellerUserId],
  );
  return Number(row?.count ?? 0);
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
  options: { decayDays: number; today?: number },
): Promise<void> {
  const day = options.today ?? dayNow();
  // The sale and the clock in one statement: a settled order is exactly what "still trading"
  // means, so the day it happened is the day dormancy counts from (ADR-0072).
  const row = await tx.get<Standing>(
    `UPDATE sellers SET settled_pico = settled_pico + ?, last_settled_day = ? WHERE user_id = ?
      RETURNING settled_pico, level, level_penalty, last_settled_day`,
    [earningsPico, day, sellerUserId],
  );
  if (!row) return; // the seller row is gone (a deleted account); the ledger still balances
  const level = standingLevel({
    settledPico: Number(row.settled_pico),
    completedOrders: await completedOrdersFor(tx, sellerUserId),
    lastSettledDay: day,
    penalty: Number(row.level_penalty),
    today: day,
    decayDays: options.decayDays,
  });
  await writeLevel(tx, sellerUserId, level, Number(row.level));
}

/**
 * The daily sweep that lets a level fall (ADR-0072).
 *
 * It only ever looks at sellers who have something to lose, and it is idempotent: running it
 * twice in one day is two identical no-op comparisons. Sellers who already had standing when
 * this feature shipped get their clock started here rather than being decayed retroactively
 * for a column that did not exist while they were trading.
 *
 * ponytail: a loop over sellers with a level, one query each. A marketplace with more sellers
 * than that wants a single UPDATE joined against a count of completed orders, and it can have
 * one when the loop shows up in the metrics.
 */
export async function decaySellerLevels(
  db: Db,
  options: { decayDays: number; today?: number },
): Promise<number> {
  const day = options.today ?? dayNow();
  await db.run(
    "UPDATE sellers SET last_settled_day = ? WHERE last_settled_day IS NULL AND settled_pico > 0",
    [day],
  );
  const rows = await db.all<Standing & { user_id: string }>(
    "SELECT user_id, settled_pico, level, level_penalty, last_settled_day FROM sellers WHERE level > 0",
  );
  let changed = 0;
  for (const row of rows) {
    const level = standingLevel({
      settledPico: Number(row.settled_pico),
      completedOrders: await completedOrdersFor(db, row.user_id),
      lastSettledDay: row.last_settled_day,
      penalty: Number(row.level_penalty),
      today: day,
      decayDays: options.decayDays,
    });
    if (await writeLevel(db, row.user_id, level, Number(row.level))) changed += 1;
  }
  return changed;
}

/**
 * A suspension costs a level, and the loss survives the reinstatement (ADR-0072).
 *
 * Before this, a suspension hid a seller's listings and left the standing behind them
 * untouched: an account reinstated after a fraud investigation came back above every honest
 * seller who had been trading throughout. The penalty is a step, not a reset — the volume and
 * the orders are still theirs, and crossing the next threshold earns the step back.
 */
export async function penaliseSellerStanding(
  db: Db,
  sellerUserId: string,
  options: { decayDays: number; today?: number },
): Promise<void> {
  const row = await db.get<Standing>(
    `UPDATE sellers SET level_penalty = MIN(level_penalty + 1, 3) WHERE user_id = ?
      RETURNING settled_pico, level, level_penalty, last_settled_day`,
    [sellerUserId],
  );
  if (!row) return; // not a seller: there is no standing to take away
  await applyStanding(db, sellerUserId, row, options);
}

/**
 * Recomputes a seller's level after a reinstatement. It does not undo the penalty — that is
 * the point of the penalty — it puts the seller back in the catalogue at the standing their
 * own trade currently supports, dormancy during the suspension included.
 */
export async function restoreSellerStanding(
  db: Db,
  sellerUserId: string,
  options: { decayDays: number; today?: number },
): Promise<void> {
  const row = await db.get<Standing>("SELECT settled_pico, level, level_penalty, last_settled_day FROM sellers WHERE user_id = ?", [
    sellerUserId,
  ]);
  if (!row) return;
  await applyStanding(db, sellerUserId, row, options);
}

async function applyStanding(
  db: Db,
  sellerUserId: string,
  row: Standing,
  options: { decayDays: number; today?: number },
): Promise<void> {
  const level = standingLevel({
    settledPico: Number(row.settled_pico),
    completedOrders: await completedOrdersFor(db, sellerUserId),
    lastSettledDay: row.last_settled_day,
    penalty: Number(row.level_penalty),
    today: options.today ?? dayNow(),
    decayDays: options.decayDays,
  });
  await writeLevel(db, sellerUserId, level, Number(row.level));
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
