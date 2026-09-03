/**
 * A seller's level, and the two ways it can fall (PAY-5, ADR-0072).
 *
 * ADR-0068 made standing expensive to fake and impossible to lose, which is half a mechanism:
 * a catalogue sorted by a number that only rises answers "who once traded here". These tests
 * ask the questions a seller who is trading *today* would ask. Does someone who left a year
 * ago still outrank me? Does one sale bring their level back — and should it? And does an
 * account that was suspended for fraud come back above me?
 *
 * `standingLevel` is pure and tested directly, because dates are the part that is easy to get
 * wrong and expensive to discover in production; the sweep and the suspension go through the
 * database and the moderation route, because that is where the two writers of `rank_key`
 * could drift apart.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  approveSeller,
  fund,
  promote,
  register,
  startTestServer,
  type TestClient,
  type TestServer,
} from "./helpers.ts";
import { decaySellerLevels, standingLevel } from "../src/server/lib/reputation.ts";
import { PICO_PER_XMR } from "../src/shared/money.ts";
import { today } from "../src/server/lib/time.ts";

const DECAY_DAYS = 90;

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root"); // the first account is the instance's administrator
});
afterEach(async () => {
  await server.close();
});

describe("what the level formula does with time", () => {
  const level2 = { settledPico: 6 * PICO_PER_XMR, completedOrders: 25, penalty: 0 };

  it("keeps a level while the seller is trading", () => {
    expect(
      standingLevel({ ...level2, lastSettledDay: 1_000, today: 1_089, decayDays: DECAY_DAYS }),
    ).toBe(2);
  });

  it("takes one step per idle period, and stops at nothing", () => {
    const at = (day: number) =>
      standingLevel({ ...level2, lastSettledDay: 1_000, today: day, decayDays: DECAY_DAYS });
    expect(at(1_090)).toBe(1);
    expect(at(1_180)).toBe(0);
    // Five years away is level 0, not a negative number that would sort below a new seller's
    // listing and break the catalogue's key.
    expect(at(1_000 + 365 * 5)).toBe(0);
  });

  it("restores the earned level the moment a sale settles again", () => {
    // The volume was always theirs; dormancy only decided how much of it was shown.
    expect(
      standingLevel({ ...level2, lastSettledDay: 2_000, today: 2_000, decayDays: DECAY_DAYS }),
    ).toBe(2);
  });

  it("subtracts a suspension permanently, and a suspension does not go negative either", () => {
    expect(
      standingLevel({ ...level2, penalty: 1, lastSettledDay: 500, today: 500, decayDays: DECAY_DAYS }),
    ).toBe(1);
    expect(
      standingLevel({ ...level2, penalty: 3, lastSettledDay: 500, today: 500, decayDays: DECAY_DAYS }),
    ).toBe(0);
  });

  it("does not decay a seller whose clock has not started", () => {
    expect(
      standingLevel({ ...level2, lastSettledDay: null, today: 9_999, decayDays: DECAY_DAYS }),
    ).toBe(2);
  });
});

describe("the sweep that lets a level fall", () => {
  /** A seller at level 1, earned the only way it can be: three settled orders on-platform. */
  async function veteranSeller(
    name: string,
  ): Promise<{ userId: string; listingId: string; seller: TestClient }> {
    const seller = await register(server, name);
    await approveSeller(server, seller, `${name} Works`);
    const buyer = await register(server, `${name}buyer`);
    await fund(server, buyer, "3");
    let listingId = "";
    for (let index = 0; index < 3; index += 1) {
      const listing = await seller.post<{ id: string }>("/api/market/listings", {
        title: `${name} service ${index}`,
        description: "Work delivered through this platform, honestly described in full.",
        category: "consulting",
        kind: "service",
        priceXmr: "0.2",
      });
      listingId = listing.body.id;
      const order = await buyer.post<{ id: string }>("/api/market/orders", {
        listingId: listing.body.id,
      });
      await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
      await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
      const done = await buyer.post(`/api/market/orders/${order.body.id}/status`, {
        status: "completed",
      });
      expect(done.status).toBe(200);
    }
    const row = await server.db.get<{ user_id: string; level: number; last_settled_day: number }>(
      "SELECT user_id, level, last_settled_day FROM sellers WHERE display_name = ?",
      [`${name} Works`],
    );
    expect(row?.level).toBe(1);
    // The clock started at the sale, not at the account.
    expect(row?.last_settled_day).toBe(today());
    return { userId: row!.user_id, listingId, seller };
  }

  it("lowers a dormant seller and re-keys their listings, then puts it back on the next sale", async () => {
    const { userId, listingId, seller } = await veteranSeller("dormant");
    const ranked = async () =>
      (
        await server.db.get<{ rank_key: number }>("SELECT rank_key FROM listings WHERE id = ?", [
          listingId,
        ])
      )?.rank_key;
    expect(await ranked()).toBeGreaterThan(100_000);

    // Nothing happens on the day of the sale, or on any day inside the window.
    expect(await decaySellerLevels(server.db, { decayDays: DECAY_DAYS, today: today() + 89 })).toBe(0);
    // A full period later the level falls, and the catalogue key falls with it — this is the
    // pair that used to be able to drift.
    expect(await decaySellerLevels(server.db, { decayDays: DECAY_DAYS, today: today() + 90 })).toBe(1);
    const dormant = await server.db.get<{ level: number }>(
      "SELECT level FROM sellers WHERE user_id = ?",
      [userId],
    );
    expect(dormant?.level).toBe(0);
    expect(await ranked()).toBeLessThan(100_000);

    // Running it again the same day changes nothing: the sweep is idempotent.
    expect(await decaySellerLevels(server.db, { decayDays: DECAY_DAYS, today: today() + 90 })).toBe(0);

    // And the volume was never deleted — one settled sale brings the standing back, because
    // the seller is trading again and that is what the level is for.
    const buyer = await register(server, "returningbuyer");
    await fund(server, buyer, "1");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "Back at work",
      description: "Work delivered through this platform, honestly described in full again.",
      category: "consulting",
      kind: "service",
      priceXmr: "0.2",
    });
    const order = await buyer.post<{ id: string }>("/api/market/orders", {
      listingId: listing.body.id,
    });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
    const back = await server.db.get<{ level: number }>(
      "SELECT level FROM sellers WHERE user_id = ?",
      [userId],
    );
    expect(back?.level).toBe(1);
  });

  it("starts the clock for a seller who earned their level before the column existed", async () => {
    const { userId } = await veteranSeller("grandfathered");
    // The state migration 016 leaves behind for anyone who traded before it: standing, no
    // date. It must not be read as "idle since the epoch".
    await server.db.run("UPDATE sellers SET last_settled_day = NULL WHERE user_id = ?", [userId]);
    expect(await decaySellerLevels(server.db, { decayDays: DECAY_DAYS, today: today() })).toBe(0);
    const row = await server.db.get<{ level: number; last_settled_day: number | null }>(
      "SELECT level, last_settled_day FROM sellers WHERE user_id = ?",
      [userId],
    );
    // The level survived, and the clock now runs from today rather than retroactively.
    expect(row?.level).toBe(1);
    expect(row?.last_settled_day).toBe(today());
  });
});

describe("a suspension costs standing, not just visibility", () => {
  it("takes a level on suspension and does not hand it back on reinstatement", async () => {
    const seller = await register(server, "suspect");
    await approveSeller(server, seller, "Suspect Works");
    const buyer = await register(server, "suspectbuyer");
    await fund(server, buyer, "3");
    for (let index = 0; index < 3; index += 1) {
      const listing = await seller.post<{ id: string }>("/api/market/listings", {
        title: `Suspect service ${index}`,
        description: "Work delivered through this platform, honestly described in full.",
        category: "consulting",
        kind: "service",
        priceXmr: "0.2",
      });
      const order = await buyer.post<{ id: string }>("/api/market/orders", {
        listingId: listing.body.id,
      });
      await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
      await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
      await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
    }
    const standing = async () =>
      await server.db.get<{ level: number; level_penalty: number }>(
        "SELECT level, level_penalty FROM sellers WHERE display_name = 'Suspect Works'",
      );
    expect((await standing())?.level).toBe(1);

    const admin = await register(server, "standingadmin");
    await promote(server, "standingadmin", "admin");
    const suspended = await admin.post("/api/moderation/users/suspect/status", {
      status: "suspended",
      reason: "under investigation",
    });
    expect(suspended.status).toBe(200);
    expect(await standing()).toMatchObject({ level: 0, level_penalty: 1 });

    const reinstated = await admin.post("/api/moderation/users/suspect/status", {
      status: "active",
    });
    expect(reinstated.status).toBe(200);
    // Back in the catalogue, and not back at the top: the step is earned again with trade,
    // never returned by the decision that ended the suspension.
    expect(await standing()).toMatchObject({ level: 0, level_penalty: 1 });
    const keys = await server.db.all<{ rank_key: number }>(
      `SELECT l.rank_key FROM listings l JOIN sellers s ON s.user_id = l.seller_user_id
        WHERE s.display_name = 'Suspect Works'`,
    );
    expect(keys.every((row) => row.rank_key < 100_000)).toBe(true);
  });

  it("does nothing to an account that was never a seller", async () => {
    const buyer = await register(server, "justabuyer");
    expect(buyer).toBeTruthy();
    const admin = await register(server, "buyeradmin");
    await promote(server, "buyeradmin", "admin");
    const suspended = await admin.post("/api/moderation/users/justabuyer/status", {
      status: "suspended",
      reason: "spam",
    });
    expect(suspended.status).toBe(200);
    expect(await server.db.all("SELECT user_id FROM sellers")).toHaveLength(0);
  });
});
