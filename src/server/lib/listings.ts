/**
 * Presenting a listing, and the check that the person writing one may.
 *
 * Split out of `routes/market.ts` because that file reached the 700-line ceiling
 * (`docs/CHANGE_REVIEW.md`), and this is the seam: the route module decides *what happens*,
 * these two functions decide what a listing looks like to a reader and who counts as a
 * seller. No behaviour changed in the move.
 */
import type { FastifyInstance } from "fastify";
import { forbidden } from "./errors.ts";
import { dayToIsoDate } from "./time.ts";
import { listingRating } from "./reputation.ts";
import { xmrString } from "../../shared/money.ts";

export interface ListingRow {
  id: string;
  title: string;
  description: string;
  category: string;
  kind: string;
  price_pico: number;
  created_day: number;
  rank_key: number;
  display_name: string;
  /** The seller's level, earned on this platform only (ADR-0068). */
  level: number;
  username: string;
  /** Staked against their own conduct (ADR-0086). Absent on queries that do not select it. */
  bond_pico?: number;
}

export async function presentListing(app: FastifyInstance, row: ListingRow) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    category: row.category,
    kind: row.kind,
    priceXmr: xmrString(row.price_pico),
    seller: {
      username: row.username,
      displayName: row.display_name,
      level: row.level,
      // Only when there is one: an absent bond is not a zero to display, it is a seller who
      // has not staked anything, and a row of zeroes teaches a reader to ignore the field.
      ...(Number(row.bond_pico ?? 0) > 0
        ? { bondXmr: xmrString(Number(row.bond_pico)) }
        : {}),
    },
    listedOn: dayToIsoDate(row.created_day),
    ...(await listingRating(app.db, row.id)),
  };
}

export async function requireSeller(
  app: FastifyInstance,
  userId: string,
): Promise<{ user_id: string; level: number }> {
  const seller = await app.db.get<{ user_id: string; status: string; level: number }>(
    "SELECT user_id, status, level FROM sellers WHERE user_id = ?",
    [userId],
  );
  if (!seller) throw forbidden("you need an approved seller application first");
  if (seller.status !== "active") throw forbidden("your seller account is suspended");
  return seller;
}
