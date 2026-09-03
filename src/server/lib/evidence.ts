/**
 * Dispute evidence, without the evidence (ADR-0074).
 *
 * The channel between a buyer and a seller is end-to-end encrypted and this server cannot
 * read it, which is the point of the whole project and also the reason disputes were decided
 * on prose: a buyer said "he sent me a broken file", the seller said "I sent the right one",
 * and a moderator had two stories and no way to tell which file either of them meant.
 *
 * What a server that must not see the file can still do is hold a **commitment**: a party
 * publishes a digest of the bytes they say they exchanged, and it is written down with the
 * moment they published it. Neither side can later substitute a different file, because the
 * digest of the substitute will not match what they committed to — and the counterparty,
 * who has the file from the channel, can check that themselves.
 *
 * Two properties are worth being exact about, because a commitment scheme that is oversold is
 * worse than none:
 *
 * 1. **The key is the order id.** The browser computes `HMAC-SHA256(order id, file bytes)`,
 *    not a bare hash. A bare SHA-256 of a widely circulated file is recognisable by anybody
 *    who has that file, which would turn this table into a "who exchanged which known file"
 *    index — exactly the metadata this project refuses to keep. Keyed with an unguessable
 *    order id, a digest means nothing to anyone who does not already know the order, and both
 *    parties and the moderator do.
 * 2. **It proves an order of events, not a truth.** A commitment says "this party claimed
 *    this digest at this time", which is enough to stop a story changing after a dispute is
 *    filed and is not evidence that a file was good, delivered, or ever sent. The moderator
 *    interface says so in those words.
 *
 * This server never computes a digest and never sees a file: it stores 64 characters of hex
 * it validated the shape of, and `test/evidence.test.ts` asserts there is no column that
 * could hold anything else.
 */
import type { Db } from "../db/index.ts";
import { dayToIsoDate } from "./time.ts";

/** What the party says the bytes were. A word from this list, never their own text. */
export const EVIDENCE_KINDS = ["delivery", "attachment", "screenshot", "other"] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

/**
 * How many commitments one party may make on one order. Ten is more than any honest dispute
 * needs and small enough that this table cannot be used as free storage or as a log of a
 * counterparty's file collection.
 */
export const MAX_EVIDENCE_PER_PARTY = 10;

export interface EvidenceRecord {
  id: string;
  /** The party's role on this order, not their username: a moderator needs the side. */
  by: "buyer" | "seller";
  kind: string;
  digest: string;
  on: string;
  /**
   * Whether it was committed before the order was disputed. A digest published *after* the
   * argument started is not worthless, but it is worth less, and a moderator should not have
   * to work that out from two timestamps.
   */
  beforeDispute: boolean;
}

/**
 * Every commitment on one order, oldest first, with the side that made it.
 *
 * Shared by the order screen and the moderation queue on purpose: a dispute where the
 * moderator sees a different list from the parties is a dispute nobody can trust.
 */
export async function evidenceForOrder(
  db: Db,
  order: { id: string; buyer_user_id: string; seller_user_id: string },
): Promise<EvidenceRecord[]> {
  const rows = await db.all<{
    id: string;
    user_id: string;
    kind: string;
    digest: string;
    created_at: number;
  }>(
    `SELECT id, user_id, kind, digest, created_at FROM order_evidence
      WHERE order_id = ? ORDER BY created_at ASC, id ASC`,
    [order.id],
  );
  if (rows.length === 0) return [];
  const disputed = await db.get<{ created_at: number }>(
    `SELECT created_at FROM order_events
      WHERE order_id = ? AND to_status = 'disputed' ORDER BY created_at ASC LIMIT 1`,
    [order.id],
  );
  return rows.map((row) => ({
    id: row.id,
    by: row.user_id === order.seller_user_id ? "seller" : "buyer",
    kind: row.kind,
    digest: row.digest,
    // Day granularity in the answer, like every other date this API publishes (ADR-0018).
    // The exact minute is kept in the row because `beforeDispute` needs it, and it dies with
    // the order.
    on: dayToIsoDate(Math.floor(row.created_at / 86_400_000)),
    // `<=`, not `<`: two requests can land in the same millisecond, and a commitment that
    // arrived in the same millisecond as the dispute was not published *after* it. The
    // window a party would have to hit to abuse this is one millisecond wide.
    beforeDispute: disputed === null || row.created_at <= disputed.created_at,
  }));
}
