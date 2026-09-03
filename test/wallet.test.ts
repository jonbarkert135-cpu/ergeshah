/**
 * Money: the ledger, escrow on an order, the fee, and payouts (ADR-0066).
 *
 * These are the tests a custodial marketplace is judged by, so they are written as questions a
 * seller would ask. Does the balance equal the sum of its movements? Can an order be placed
 * with money that is not there? Does a cancelled order return every piconero? Can a payout
 * leave twice? Can somebody else's payout be cancelled?
 *
 * The invariant helper at the bottom re-adds `ledger_entries` for every account after each
 * scenario and compares it to `balances`. It is deliberately not a unit test of the ledger
 * module: it runs after flows that went through HTTP, which is where the bug would be.
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
import { PICO_PER_XMR, parseXmr, xmrString } from "../src/shared/money.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { feeFor, markWithdrawalSent } from "../src/server/lib/ledger.ts";

/** A valid-looking mainnet subaddress: 95 characters of Monero base58, starting with 8. */
const ADDRESS = `8${"A".repeat(94)}`;

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root"); // the first account of an instance is its administrator
});
afterEach(async () => {
  await ledgerReconciles();
  await server.close();
});

async function sellerWithListing(name: string, priceXmr: string) {
  const seller = await register(server, name);
  await approveSeller(server, seller, `${name} Ltd`);
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: `${name}'s careful work`,
    description: "A description long enough to satisfy the validator on this route, honestly.",
    category: "software",
    kind: "digital_good",
    priceXmr,
  });
  expect(listing.status).toBe(200);
  return { seller, listingId: listing.body.id };
}

/** The two numbers that matter, so an assertion reads as money rather than as a payload. */
async function balance(client: TestClient) {
  const wallet = await client.get<{ availableXmr: string; heldXmr: string }>("/api/wallet");
  expect(wallet.status).toBe(200);
  return { availableXmr: wallet.body.availableXmr, heldXmr: wallet.body.heldXmr };
}

describe("a balance is the sum of its movements", () => {
  it("credits a confirmed top-up once, however many times the watcher sees it", async () => {
    const buyer = await register(server, "topper");
    await fund(server, buyer, "0.5");
    expect((await balance(buyer)).availableXmr).toBe("0.5");

    const user = await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
      "topper",
    ]);
    const { creditDeposit } = await import("../src/server/lib/ledger.ts");
    const first = await creditDeposit(server.db, {
      userId: user!.id,
      amountPico: parseXmr("0.25")!,
      txid: "same-transfer",
      subaddressIndex: 3,
      confirmations: 3,
    });
    const again = await creditDeposit(server.db, {
      userId: user!.id,
      amountPico: parseXmr("0.25")!,
      txid: "same-transfer",
      subaddressIndex: 3,
      confirmations: 12,
    });
    expect(first).toBeTruthy();
    // The second sighting of one transfer is not money.
    expect(again).toBeNull();
    expect((await balance(buyer)).availableXmr).toBe("0.75");
  });

  it("records a top-up below the minimum without crediting it, and shows it to its owner", async () => {
    const owner = await register(server, "dustpayer");
    const user = await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
      "dustpayer",
    ]);
    const { creditDeposit } = await import("../src/server/lib/ledger.ts");
    const id = await creditDeposit(server.db, {
      userId: user!.id,
      amountPico: parseXmr("0.005")!,
      txid: "dust-transfer",
      subaddressIndex: 4,
      confirmations: 10,
      minPico: parseXmr("0.02")!,
    });
    expect(id).toBeTruthy();
    // Not credited...
    expect((await balance(owner)).availableXmr).toBe("0");
    const row = await server.db.get<{ status: string; credited_at: number | null }>(
      "SELECT status, credited_at FROM deposits WHERE id = ?",
      [id],
    );
    expect(row?.status).toBe("below_minimum");
    expect(row?.credited_at).toBeNull();
    // ...and not hidden either: the owner sees the amount that arrived and was not credited.
    const wallet = await owner.get<{ belowMinimumXmr: string }>("/api/wallet");
    expect(wallet.body.belowMinimumXmr).toBe("0.005");
  });

  it("credits a top-up that meets the minimum exactly", async () => {
    const owner = await register(server, "exactpayer");
    const user = await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
      "exactpayer",
    ]);
    const { creditDeposit } = await import("../src/server/lib/ledger.ts");
    await creditDeposit(server.db, {
      userId: user!.id,
      amountPico: parseXmr("0.02")!,
      txid: "exact-transfer",
      subaddressIndex: 5,
      confirmations: 10,
      minPico: parseXmr("0.02")!,
    });
    expect((await balance(owner)).availableXmr).toBe("0.02");
  });

  it("shows every movement in the account's own ledger", async () => {
    const { seller, listingId } = await sellerWithListing("ledgerseller", "0.05");
    const buyer = await register(server, "ledgerbuyer");
    await fund(server, buyer, "1");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });

    const entries = await buyer.get<{ entries: Array<{ kind: string; availableXmr: string }> }>(
      "/api/wallet/entries",
    );
    expect(entries.body.entries.map((entry) => entry.kind)).toEqual([
      "order_hold", // the settlement's buyer leg
      "order_hold", // the escrow at placement
      "deposit",
    ]);
    const sellerEntries = await seller.get<{ entries: Array<{ kind: string; availableXmr: string }> }>(
      "/api/wallet/entries",
    );
    expect(sellerEntries.body.entries[0]!.kind).toBe("order_earnings");
    expect(sellerEntries.body.entries[0]!.availableXmr).toBe("+0.0475");
  });
});

describe("escrow follows the order, and the fee follows the sale", () => {
  it("refuses an order the buyer cannot pay for, and creates nothing", async () => {
    const { listingId } = await sellerWithListing("pricyseller", "0.5");
    const buyer = await register(server, "brokebuyer");
    const refused = await buyer.post<{ error: string }>("/api/market/orders", { listingId });
    expect(refused.status).toBe(402);
    expect(refused.body.error).toBe("insufficient_balance");
    const orders = await server.db.all("SELECT id FROM orders");
    expect(orders).toHaveLength(0);
    // And the seller was told nothing about an order that does not exist.
    const notifications = await server.db.all("SELECT id FROM notifications WHERE kind = 'order'");
    expect(notifications).toHaveLength(0);
  });

  it("holds the price, then pays the seller 95% and the platform 5%", async () => {
    const { seller, listingId } = await sellerWithListing("feeseller", "1");
    const buyer = await register(server, "feebuyer");
    await fund(server, buyer, "2");

    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    expect(order.status).toBe(200);
    expect(await balance(buyer)).toEqual({ availableXmr: "1", heldXmr: "1" });

    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
    // Accepting and delivering move no money: the hold is the seller's assurance.
    expect(await balance(buyer)).toEqual({ availableXmr: "1", heldXmr: "1" });

    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
    expect(await balance(buyer)).toEqual({ availableXmr: "1", heldXmr: "0" });
    expect(await balance(seller)).toEqual({ availableXmr: "0.95", heldXmr: "0" });

    const platform = await server.db.get<{ available_pico: number }>(
      "SELECT available_pico FROM balances WHERE account_id = 'platform'",
    );
    expect(platform!.available_pico).toBe(feeFor(PICO_PER_XMR, 500));
    expect(xmrString(platform!.available_pico)).toBe("0.05");
  });

  it("returns the whole hold when an order is cancelled, and charges nothing", async () => {
    const { seller, listingId } = await sellerWithListing("cancelseller", "0.25");
    const buyer = await register(server, "cancelbuyer");
    await fund(server, buyer, "0.3");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "cancelled" });

    expect(await balance(buyer)).toEqual({ availableXmr: "0.3", heldXmr: "0" });
    const platform = await server.db.get<{ available_pico: number }>(
      "SELECT available_pico FROM balances WHERE account_id = 'platform'",
    );
    expect(platform!.available_pico).toBe(0);
  });

  it("settles a dispute the moderator's way, and only a moderator's way", async () => {
    const { seller, listingId } = await sellerWithListing("disputeseller", "0.4");
    const buyer = await register(server, "disputebuyer");
    await fund(server, buyer, "0.4");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, {
      status: "disputed",
      reason: "The delivery never arrived and the seller has stopped replying to messages.",
    });
    // Money is frozen while the dispute is open: neither party has it.
    expect(await balance(buyer)).toEqual({ availableXmr: "0", heldXmr: "0.4" });
    expect(await balance(seller)).toEqual({ availableXmr: "0", heldXmr: "0" });

    // The seller cannot settle their own dispute in their own favour.
    const grab = await seller.post(`/api/market/orders/${order.body.id}/status`, {
      status: "completed",
    });
    expect(grab.status).toBe(403);

    const moderator = await register(server, "settler");
    await promote(server, "settler", "moderator");
    const settled = await moderator.post(`/api/market/orders/${order.body.id}/status`, {
      status: "cancelled",
    });
    expect(settled.status).toBe(200);
    expect(await balance(buyer)).toEqual({ availableXmr: "0.4", heldXmr: "0" });
  });

  it("needs no escrow for a free listing", async () => {
    const { seller, listingId } = await sellerWithListing("freeseller", "0");
    const buyer = await register(server, "freebuyer");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    expect(order.status).toBe(200);
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });
    const entries = await server.db.all("SELECT id FROM ledger_entries");
    expect(entries).toHaveLength(0);
  });
});

describe("payouts leave once, and not without a limit or a person", () => {
  it("queues a payout inside the account's limit and takes it out of the balance", async () => {
    const buyer = await register(server, "payoutone");
    await fund(server, buyer, "1");
    const requested = await buyer.post<{ status: string; addressHint: string }>(
      "/api/wallet/withdrawals",
      { amountXmr: "0.5", address: ADDRESS },
    );
    expect(requested.status).toBe(200);
    expect(requested.body.status).toBe("queued");
    // The destination is never echoed in full, not even to its owner.
    expect(requested.body.addressHint).not.toContain(ADDRESS);
    expect(await balance(buyer)).toEqual({ availableXmr: "0.5", heldXmr: "0.5" });

    const row = await server.db.get<{ id: string }>("SELECT id FROM withdrawals");
    await markWithdrawalSent(server.db, {
      id: row!.id,
      txid: "abc123",
      networkFeePico: parseXmr("0.0001")!,
    });
    // Sent means gone: the held amount leaves the platform, the available balance is untouched.
    expect(await balance(buyer)).toEqual({ availableXmr: "0.5", heldXmr: "0" });
    const sent = await buyer.get<{ withdrawals: Array<{ status: string; txid: string | null }> }>(
      "/api/wallet/withdrawals",
    );
    expect(sent.body.withdrawals[0]!.status).toBe("sent");
    expect(sent.body.withdrawals[0]!.txid).toBe("abc123");
    const kept = await server.db.get<{ address: string | null }>("SELECT address FROM withdrawals");
    expect(kept!.address).toBeNull();
  });

  it("parks a payout above the limit for an administrator, who can refuse it", async () => {
    const buyer = await register(server, "payouttwo");
    await fund(server, buyer, "5");
    const requested = await buyer.post<{ status: string; id: string }>("/api/wallet/withdrawals", {
      amountXmr: "3",
      address: ADDRESS,
    });
    expect(requested.body.status).toBe("approval_required");

    // A moderator may look at the queue; only an admin decides.
    const moderator = await register(server, "watcher");
    await promote(server, "watcher", "moderator");
    const queue = await moderator.get<{ withdrawals: Array<{ id: string; status: string }> }>(
      "/api/moderation/withdrawals",
    );
    expect(queue.body.withdrawals.map((row) => row.id)).toEqual([requested.body.id]);
    const refusedByModerator = await moderator.post(
      `/api/moderation/withdrawals/${requested.body.id}/decide`,
      { decision: "approved" },
    );
    expect(refusedByModerator.status).toBe(403);

    const admin = await register(server, "purse");
    await promote(server, "purse", "admin");
    const decided = await admin.post(`/api/moderation/withdrawals/${requested.body.id}/decide`, {
      decision: "rejected",
    });
    expect(decided.status).toBe(200);
    expect(await balance(buyer)).toEqual({ availableXmr: "5", heldXmr: "0" });
    // Deciding twice is refused rather than paying twice.
    const twice = await admin.post(`/api/moderation/withdrawals/${requested.body.id}/decide`, {
      decision: "approved",
    });
    expect(twice.status).toBe(409);
    const audited = await server.db.all<{ note: string }>(
      "SELECT note FROM audit_log WHERE action = 'withdrawal.decided'",
    );
    expect(audited.map((row) => row.note)).toEqual(["rejected"]);
  });

  it("takes two different administrators to release a large payout (ADR-0076)", async () => {
    const seller = await register(server, "bigearner");
    await fund(server, seller, "40");
    const requested = await seller.post<{ status: string; id: string }>("/api/wallet/withdrawals", {
      // Above the default two-signature threshold of 10 XMR.
      amountXmr: "25",
      address: ADDRESS,
    });
    expect(requested.body.status).toBe("approval_required");

    const first = await register(server, "treasurerone");
    await promote(server, "treasurerone", "admin");
    const second = await register(server, "treasurertwo");
    await promote(server, "treasurertwo", "admin");

    const one = await first.post<{ status: string; approvals: number; approvalsRequired: number }>(
      `/api/moderation/withdrawals/${requested.body.id}/decide`,
      { decision: "approved" },
    );
    expect(one.status).toBe(200);
    // Parked, and the answer says so: an interface that reported success here would be
    // hiding the signature nobody has given yet.
    expect(one.body).toMatchObject({ status: "approval_required", approvals: 1, approvalsRequired: 2 });
    expect(await balance(seller)).toEqual({ availableXmr: "15", heldXmr: "25" });

    // The same administrator clicking again is the same signature, not a second one.
    const again = await first.post<{ approvals: number }>(
      `/api/moderation/withdrawals/${requested.body.id}/decide`,
      { decision: "approved" },
    );
    expect(again.body.approvals).toBe(1);
    const stillParked = await server.db.get<{ status: string }>(
      "SELECT status FROM withdrawals WHERE id = ?",
      [requested.body.id],
    );
    expect(stillParked?.status).toBe("approval_required");

    // A second person releases it — and only into the queue the worker reads.
    const released = await second.post<{ status: string; approvals: number }>(
      `/api/moderation/withdrawals/${requested.body.id}/decide`,
      { decision: "approved" },
    );
    expect(released.body).toMatchObject({ status: "queued", approvals: 2 });

    // The log distinguishes the signature that released it from the one that waited.
    const audited = await server.db.all<{ note: string }>(
      "SELECT note FROM audit_log WHERE action = 'withdrawal.decided' ORDER BY created_at",
    );
    expect(audited.map((row) => row.note)).toEqual(["approved_1_of_2", "approved_1_of_2", "approved"]);
  });

  it("still takes one administrator to refuse a large payout, and one to release a small one", async () => {
    const seller = await register(server, "smallearner");
    await fund(server, seller, "30");
    const admin = await register(server, "lonetreasurer");
    await promote(server, "lonetreasurer", "admin");

    // Above the account's automatic ceiling (2 XMR) but under the two-signature threshold.
    const small = await seller.post<{ id: string; status: string }>("/api/wallet/withdrawals", {
      amountXmr: "4",
      address: ADDRESS,
    });
    expect(small.body.status).toBe("approval_required");
    const releasedAlone = await admin.post<{ status: string; approvalsRequired: number }>(
      `/api/moderation/withdrawals/${small.body.id}/decide`,
      { decision: "approved" },
    );
    expect(releasedAlone.body).toMatchObject({ status: "queued", approvalsRequired: 1 });
    await markWithdrawalSent(server.db, {
      id: small.body.id,
      txid: "small-payout",
      networkFeePico: 0,
    });

    // A refusal moves nothing out of the platform, so it needs one administrator even above
    // the threshold — requiring a quorum to say "no" would only delay the safe answer.
    const large = await seller.post<{ id: string }>("/api/wallet/withdrawals", {
      amountXmr: "20",
      address: ADDRESS,
    });
    const refused = await admin.post<{ status: string }>(
      `/api/moderation/withdrawals/${large.body.id}/decide`,
      { decision: "rejected" },
    );
    expect(refused.body.status).toBe("rejected");
    expect(await balance(seller)).toEqual({ availableXmr: "26", heldXmr: "0" });
  });

  it("honours a per-account limit an admin sets, and audits the number", async () => {
    const seller = await register(server, "trusted");
    await fund(server, seller, "10");
    const admin = await register(server, "banker");
    await promote(server, "banker", "admin");
    const set = await admin.post("/api/admin/users/trusted/payout-limit", { limitXmr: "8" });
    expect(set.status).toBe(200);

    const big = await seller.post<{ status: string }>("/api/wallet/withdrawals", {
      amountXmr: "7",
      address: ADDRESS,
    });
    // Seven XMR would need approval on the default limit of two; this account has eight.
    expect(big.body.status).toBe("queued");
    const audited = await server.db.all<{ note: string }>(
      "SELECT note FROM audit_log WHERE action = 'payout_limit.set'",
    );
    expect(audited.map((row) => row.note)).toEqual(["8"]);
  });

  it("refuses a payout below the minimum, a bad address, and a second pending one", async () => {
    // A loose bucket for this one: the `wallet_write` limit is deliberately tight (six in a
    // burst), and this test makes eight requests on purpose. That the bucket exists at all is
    // asserted in test/limits.test.ts.
    const loose = await startTestServer({
      rateLimits: { ...DEFAULT_LIMITS, wallet_write: { burst: 50, perMinute: 50 } },
    });
    const previous = server;
    server = loose;
    try {
      await refusals();
    } finally {
      server = previous;
      await loose.close();
    }
  });

  async function refusals(): Promise<void> {
    const buyer = await register(server, "payoutthree");
    await fund(server, buyer, "1");
    const tiny = await buyer.post<{ error: string }>("/api/wallet/withdrawals", {
      amountXmr: "0.001",
      address: ADDRESS,
    });
    expect(tiny.status).toBe(400);
    expect(tiny.body.error).toBe("below_minimum");

    for (const address of ["", "not-an-address", `8${"A".repeat(93)}`, `1${"A".repeat(94)}`, `8${"0".repeat(94)}`]) {
      const bad = await buyer.post<{ error: string }>("/api/wallet/withdrawals", {
        amountXmr: "0.1",
        address,
      });
      expect(bad.status, address).toBe(400);
    }

    const first = await buyer.post("/api/wallet/withdrawals", { amountXmr: "0.1", address: ADDRESS });
    expect(first.status).toBe(200);
    const second = await buyer.post<{ error: string }>("/api/wallet/withdrawals", {
      amountXmr: "0.1",
      address: ADDRESS,
    });
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("payout_pending");
  }

  it("cannot be spent twice by two requests racing for the same balance", async () => {
    const buyer = await register(server, "racer");
    await fund(server, buyer, "0.1");
    // One seller with two listings: registering a second one would spend the `register`
    // bucket, which is five in a burst and is not what this test is about.
    const { seller, listingId: one } = await sellerWithListing("raceseller", "0.1");
    const second = await seller.post<{ id: string }>("/api/market/listings", {
      title: "A second thing by the same seller",
      description: "Also long enough to satisfy the validator, and also priced at a tenth.",
      category: "software",
      kind: "digital_good",
      priceXmr: "0.1",
    });
    const two = second.body.id;

    const attempts = await Promise.all([
      buyer.post<{ error?: string }>("/api/market/orders", { listingId: one }),
      buyer.post<{ error?: string }>("/api/market/orders", { listingId: two }),
    ]);
    const codes = attempts.map((attempt) => attempt.status).sort();
    expect(codes[0]).toBe(200);
    // The loser is refused by the guarded UPDATE or by the CHECK behind it; either way the
    // money was spent once.
    expect([402, 409]).toContain(codes[1]);
    const balances = await balance(buyer);
    expect(balances.availableXmr).toBe("0");
    expect(balances.heldXmr).toBe("0.1");
  });

  it("lets the owner cancel a payout, and nobody else", async () => {
    const buyer = await register(server, "canceller");
    await fund(server, buyer, "1");
    const created = await buyer.post<{ id: string }>("/api/wallet/withdrawals", {
      amountXmr: "0.5",
      address: ADDRESS,
    });
    const stranger = await register(server, "nosy");
    const theirs = await stranger.post(`/api/wallet/withdrawals/${created.body.id}/cancel`);
    // Same answer as a wrong id: a 403 would confirm that this payout exists.
    expect(theirs.status).toBe(404);

    const mine = await buyer.post(`/api/wallet/withdrawals/${created.body.id}/cancel`);
    expect(mine.status).toBe(200);
    expect(await balance(buyer)).toEqual({ availableXmr: "1", heldXmr: "0" });
  });
});

describe("what the money layer refuses to be", () => {
  it("has no endpoint that credits a balance and none that transfers between accounts", () => {
    const routes = server.app.routeInventory.map((route) => `${route.method} ${route.url}`);
    for (const forbidden of [/credit/i, /transfer/i, /topup/i, /mint/i, /adjust/i]) {
      expect(routes.filter((route) => forbidden.test(route))).toEqual([]);
    }
  });

  it("refuses to delete an account that still holds money", async () => {
    const buyer = await register(server, "leaver", "correct horse battery staple");
    await fund(server, buyer, "0.5");
    const { authSecretFor } = await import("./helpers.ts");
    const refused = await buyer.post<{ error: string }>("/api/auth/delete", {
      authSecret: authSecretFor("leaver", "correct horse battery staple"),
    });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("balance_not_empty");
    const still = await server.db.get("SELECT id FROM users WHERE username = 'leaver'");
    expect(still).toBeTruthy();
  });

  it("tells an administrator what the platform owes, without naming anybody", async () => {
    const { seller, listingId } = await sellerWithListing("bookseller", "1");
    const buyer = await register(server, "bookbuyer");
    await fund(server, buyer, "2");
    const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await seller.post(`/api/market/orders/${order.body.id}/delivery`, { manual: true });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, { status: "completed" });

    const admin = await register(server, "auditor");
    await promote(server, "auditor", "admin");
    const books = await admin.get<Record<string, string>>("/api/admin/treasury");
    expect(books.status).toBe(200);
    expect(books.body.platformEarnedXmr).toBe("0.05");
    // 1 XMR of top-up left over, 0.95 earned by the seller, 0.05 taken in fees.
    expect(books.body.liabilitiesXmr).toBe("2");
    const serialised = JSON.stringify(books.body);
    for (const name of ["bookbuyer", "bookseller", "auditor"]) {
      expect(serialised).not.toContain(name);
    }
  });
});

/**
 * The invariant, checked after every test in this file: for every account, the balance equals
 * the sum of its ledger entries, and neither column is negative. If this fails, some route
 * moved money without writing it down — which is the one bug in a custodial system that cannot
 * be argued with a seller.
 */
async function ledgerReconciles(): Promise<void> {
  const accounts = await server.db.all<{
    account_id: string;
    available_pico: number;
    held_pico: number;
  }>("SELECT account_id, available_pico, held_pico FROM balances");
  for (const account of accounts) {
    const sums = await server.db.get<{ available: number | null; held: number | null }>(
      `SELECT SUM(available_delta) AS available, SUM(held_delta) AS held
         FROM ledger_entries WHERE account_id = ?`,
      [account.account_id],
    );
    expect(Number(sums?.available ?? 0), `available on ${account.account_id}`).toBe(
      account.available_pico,
    );
    expect(Number(sums?.held ?? 0), `held on ${account.account_id}`).toBe(account.held_pico);
    expect(account.available_pico).toBeGreaterThanOrEqual(0);
    expect(account.held_pico).toBeGreaterThanOrEqual(0);
  }
}
