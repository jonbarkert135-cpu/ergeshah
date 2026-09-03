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

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

async function seller(name: string, xmr = "5"): Promise<TestClient> {
  const client = await register(server, name);
  await approveSeller(server, client, `${name} the vendor`);
  await fund(server, client, xmr);
  return client;
}

async function listingBy(client: TestClient, priceXmr = "0.5"): Promise<string> {
  const { body } = await client.post<{ id: string }>("/api/market/listings", {
    title: "A thing worth arguing about later",
    description: "A description long enough to satisfy the validator on this route, honestly.",
    category: "software",
    kind: "digital_good",
    priceXmr,
  });
  return body.id;
}

/** Buy it, have the seller accept, and complete it: escrow is now empty. */
async function completedOrder(
  buyer: TestClient,
  vendor: TestClient,
  listingId: string,
): Promise<string> {
  const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
  await vendor.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
  // Delivery is its own route (a manual one here: no blob, the goods changed hands
  // elsewhere), and it is what moves an order to `delivered`.
  const delivered = await vendor.post(`/api/market/orders/${order.body.id}/delivery`, {
    manual: true,
  });
  const completed = await buyer.post(`/api/market/orders/${order.body.id}/status`, {
    status: "completed",
  });
  if (completed.status !== 200) {
    throw new Error(`order did not complete: ${delivered.status} ${JSON.stringify(completed.body)}`);
  }
  return order.body.id;
}

describe("the seller bond (ADR-0086)", () => {
  it("moves the stake into the seller's own held balance and publishes it", async () => {
    const vendor = await seller("vera");
    const listingId = await listingBy(vendor);
    const staked = await vendor.post<{ bondXmr: string }>("/api/market/seller/bond", {
      amountXmr: "1",
    });
    expect(staked.status).toBe(200);
    expect(staked.body.bondXmr).toBe("1");

    const wallet = await vendor.get<{ availableXmr: string; heldXmr: string }>("/api/wallet");
    expect(wallet.body.heldXmr).toBe("1");
    expect(wallet.body.availableXmr).toBe("4");

    // A buyer reading the catalogue sees the number without asking anybody.
    const anyone = await register(server, "reader");
    const listing = await anyone.get<{ listing: { seller: { bondXmr?: string } } }>(
      `/api/market/listings/${listingId}`,
    );
    expect(listing.body.listing.seller.bondXmr).toBe("1");
  });

  it("refuses a stake below the minimum, and one the balance cannot cover", async () => {
    const vendor = await seller("wanda", "0.5");
    expect((await vendor.post("/api/market/seller/bond", { amountXmr: "0.01" })).status).toBe(400);
    expect((await vendor.post("/api/market/seller/bond", { amountXmr: "9" })).status).toBe(402);
  });

  it("is not something a buyer can stake", async () => {
    const buyer = await register(server, "xena");
    await fund(server, buyer, "2");
    expect((await buyer.post("/api/market/seller/bond", { amountXmr: "1" })).status).toBe(403);
  });

  it("holds the bond through the cool-off and while an order is disputed", async () => {
    const vendor = await seller("yuri");
    const listingId = await listingBy(vendor);
    await vendor.post("/api/market/seller/bond", { amountXmr: "1" });

    // Straight away: no.
    const early = await vendor.post("/api/market/seller/bond/release", {});
    expect(early.status).toBe(409);

    // Cool-off served, but an argument is running: still no.
    await server.db.run("UPDATE sellers SET bond_posted_at = ? WHERE user_id IS NOT NULL", [
      Date.now() - 30 * 86_400_000,
    ]);
    const buyer = await register(server, "zack");
    await fund(server, buyer, "2");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await vendor.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, {
      status: "disputed",
      reason: "Nothing arrived and the seller has stopped answering me entirely.",
    });
    const duringDispute = await vendor.post("/api/market/seller/bond/release", {});
    expect(duringDispute.status).toBe(409);

    // Settled, and the money comes back whole.
    const moderator = await register(server, "arbiter");
    await promote(server, "arbiter", "moderator");
    await moderator.post(`/api/market/orders/${order.body.id}/status`, {
      status: "cancelled",
      reason: "The buyer is right: nothing was delivered.",
    });
    const released = await vendor.post<{ bondXmr: string }>("/api/market/seller/bond/release", {});
    expect(released.status).toBe(200);
    expect(released.body.bondXmr).toBe("0");
    const wallet = await vendor.get<{ heldXmr: string }>("/api/wallet");
    expect(wallet.body.heldXmr).toBe("0");
  });

  it("pays a harmed buyer out of the bond, once, and never the platform", async () => {
    const vendor = await seller("bruno");
    const listingId = await listingBy(vendor, "0.5");
    await vendor.post("/api/market/seller/bond", { amountXmr: "1" });
    const buyer = await register(server, "clara");
    await fund(server, buyer, "2");
    const orderId = await completedOrder(buyer, vendor, listingId);
    // The problem surfaced after the order completed, which is the case escrow cannot fix:
    // the order is terminal, so the buyer's route is a report rather than a dispute.
    const report = await buyer.post("/api/moderation/reports", {
      targetType: "order",
      targetId: orderId,
      reason: "fraud",
      details: "The licence key stopped working the day after I confirmed the order.",
    });
    expect(report.status).toBe(200);

    const moderator = await register(server, "judge");
    await promote(server, "judge", "moderator");
    const claim = await moderator.post<{ paidXmr: string; remainingBondXmr: string }>(
      `/api/market/moderation/orders/${orderId}/bond-claim`,
      { amountXmr: "0.5", note: "Key revoked by the seller after completion; buyer refunded." },
    );
    expect(claim.status).toBe(200);
    expect(claim.body).toEqual({ paidXmr: "0.5", remainingBondXmr: "0.5" });

    // The buyer has the money, the seller's bond shrank, and the platform gained nothing.
    const buyerWallet = await buyer.get<{ availableXmr: string }>("/api/wallet");
    expect(buyerWallet.body.availableXmr).toBe("2");
    const platform = await server.db.get<{ available_pico: number }>(
      "SELECT available_pico FROM balances WHERE account_id = 'platform'",
    );
    // The only platform money here is the marketplace fee on the completed order — no bond
    // ever lands on this account.
    const fees = await server.db.all(
      "SELECT id FROM ledger_entries WHERE account_id = 'platform' AND kind LIKE 'bond%'",
    );
    expect(fees).toHaveLength(0);
    expect(Number(platform?.available_pico ?? 0)).toBeGreaterThan(0);

    // And a second claim on the same order is refused.
    const again = await moderator.post(`/api/market/moderation/orders/${orderId}/bond-claim`, {
      amountXmr: "0.1",
      note: "Trying the same thing twice on purpose.",
    });
    expect(again.status).toBe(409);
  });

  it("refuses a claim that is not a moderator's, not on a completed order, or over the price", async () => {
    const vendor = await seller("dima");
    const listingId = await listingBy(vendor, "0.5");
    await vendor.post("/api/market/seller/bond", { amountXmr: "1" });
    const buyer = await register(server, "elena");
    await fund(server, buyer, "2");

    // Open order: settling it is the remedy, not the bond.
    const open = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    const moderator = await register(server, "referee3");
    await promote(server, "referee3", "moderator");
    expect(
      (
        await moderator.post(`/api/market/moderation/orders/${open.body.id}/bond-claim`, {
          amountXmr: "0.1",
          note: "Should not be possible while escrow still holds the money.",
        })
      ).status,
    ).toBe(409);

    // A second listing: the buyer already has an open order on the first one.
    const otherListing = await listingBy(vendor, "0.5");
    const orderId = await completedOrder(buyer, vendor, otherListing);
    await buyer.post("/api/moderation/reports", {
      targetType: "order",
      targetId: orderId,
      reason: "fraud",
      details: "What I received was not what the listing described at all.",
    });
    // Not a moderator.
    expect(
      (
        await buyer.post(`/api/market/moderation/orders/${orderId}/bond-claim`, {
          amountXmr: "0.5",
          note: "Helping myself to the seller's bond.",
        })
      ).status,
    ).toBe(403);
    // More than the order was worth.
    expect(
      (
        await moderator.post(`/api/market/moderation/orders/${orderId}/bond-claim`, {
          amountXmr: "0.9",
          note: "Compensating more than the buyer ever paid.",
        })
      ).status,
    ).toBe(400);
    // Without a reason for the audit log.
    expect(
      (
        await moderator.post(`/api/market/moderation/orders/${orderId}/bond-claim`, {
          amountXmr: "0.2",
          note: "x",
        })
      ).status,
    ).toBe(400);
  });
});
