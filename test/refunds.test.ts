/**
 * Sending back a top-up that was too small to credit (PAY-4, ADR-0071).
 *
 * ADR-0067 is deliberately unkind: a transfer under the minimum is recorded and not credited.
 * The complaint it invites is obvious — "you have my money and I cannot touch it" — so the
 * questions here are the ones its owner would ask. Can I get it back without asking a human?
 * Does asking twice pay me twice? Does it become spendable on the way out? And does the
 * platform's own book admit it owes me the money before I ask for it?
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promote, register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";
import { creditDeposit } from "../src/server/lib/ledger.ts";
import { parseXmr } from "../src/shared/money.ts";

const ADDRESS = `8${"A".repeat(94)}`;
const xmr = (value: string) => parseXmr(value)!;

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root"); // the first account is the instance's administrator
});
afterEach(async () => {
  await ledgerReconciles();
  await server.close();
});

/** An account with `count` uncredited transfers of `each` XMR sitting in the platform wallet. */
async function withDust(
  username: string,
  each: string,
  count = 1,
): Promise<{ client: TestClient; userId: string }> {
  const client = await register(server, username);
  const user = await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = ?", [
    username,
  ]);
  for (let index = 0; index < count; index += 1) {
    await creditDeposit(server.db, {
      userId: user!.id,
      amountPico: xmr(each),
      txid: `${username}-${index}`.padEnd(64, "0"),
      subaddressIndex: 7,
      confirmations: 6,
      minPico: server.config.minDepositPico,
    });
  }
  return { client, userId: user!.id };
}

describe("an uncredited top-up can be sent back without a support conversation", () => {
  it("queues every below-minimum transfer as one payout, and credits each one in the ledger", async () => {
    const { client, userId } = await withDust("dustone", "0.005", 3);
    const before = await client.get<{
      belowMinimumXmr: string;
      canRefund: boolean;
      minRefundXmr: string;
    }>("/api/wallet");
    expect(before.body).toMatchObject({ belowMinimumXmr: "0.015", canRefund: true });

    const refund = await client.post<{ amountXmr: string; status: string; deposits: number }>(
      "/api/wallet/refunds",
      { address: ADDRESS },
    );
    expect(refund.status).toBe(200);
    // One payout for three transfers: the network fee is charged per transfer, so refunding
    // them one at a time would cost the float three times over.
    expect(refund.body).toMatchObject({ amountXmr: "0.015", status: "queued", deposits: 3 });

    // On the way out it is held, never spendable: an account cannot buy anything with money
    // that is already committed to its own refund.
    const after = await client.get<{ availableXmr: string; heldXmr: string; belowMinimumXmr: string }>(
      "/api/wallet",
    );
    expect(after.body).toMatchObject({ availableXmr: "0", heldXmr: "0.015", belowMinimumXmr: "0" });

    // Each deposit is now credited, and each has its own ledger entry naming it.
    const rows = await server.db.all<{ status: string; credited_at: number | null }>(
      "SELECT status, credited_at FROM deposits WHERE user_id = ?",
      [userId],
    );
    expect(rows.map((row) => row.status)).toEqual(["credited", "credited", "credited"]);
    expect(rows.every((row) => row.credited_at !== null)).toBe(true);
    const entries = await server.db.all<{ kind: string }>(
      "SELECT kind FROM ledger_entries WHERE account_id = ? AND deposit_id IS NOT NULL",
      [userId],
    );
    expect(entries).toHaveLength(3);
  });

  it("refuses a second refund of the same dust", async () => {
    const { client } = await withDust("dusttwice", "0.01");
    expect((await client.post("/api/wallet/refunds", { address: ADDRESS })).status).toBe(200);
    // The first refund is still queued, so this is the one-payout-at-a-time rule talking...
    const second = await client.post<{ error: string }>("/api/wallet/refunds", { address: ADDRESS });
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("payout_pending");

    // ...and with the payout cancelled there is genuinely nothing left to refund, because the
    // money is on the balance now rather than in limbo.
    const payout = await server.db.get<{ id: string }>("SELECT id FROM withdrawals");
    expect((await client.post(`/api/wallet/withdrawals/${payout!.id}/cancel`, {})).status).toBe(200);
    const third = await client.post<{ error: string }>("/api/wallet/refunds", { address: ADDRESS });
    expect(third.status).toBe(409);
    expect(third.body.error).toBe("nothing_to_refund");
    // Cancelling returned it to the spendable balance — it does not go back to being dust.
    expect((await client.get<{ availableXmr: string }>("/api/wallet")).body.availableXmr).toBe("0.01");
  });

  it("will not send back less than the transfer costs, and leaves the deposits untouched", async () => {
    const { client, userId } = await withDust("dusttiny", "0.0002");
    const view = await client.get<{ canRefund: boolean; minRefundXmr: string }>("/api/wallet");
    expect(view.body).toMatchObject({ canRefund: false, minRefundXmr: "0.001" });

    const refused = await client.post<{ error: string }>("/api/wallet/refunds", { address: ADDRESS });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("refund_too_small");
    // The claim is rolled back with the refusal: the row is still uncredited dust, not a
    // deposit that was quietly marked credited without any money moving.
    const row = await server.db.get<{ status: string }>(
      "SELECT status FROM deposits WHERE user_id = ?",
      [userId],
    );
    expect(row?.status).toBe("below_minimum");
    expect((await client.get<{ availableXmr: string }>("/api/wallet")).body.availableXmr).toBe("0");
    expect(await server.db.all("SELECT id FROM withdrawals")).toHaveLength(0);
  });

  it("refuses an address that is not a Monero address, before anything is claimed", async () => {
    const { client, userId } = await withDust("dustbadaddress", "0.01");
    const refused = await client.post<{ error: string }>("/api/wallet/refunds", {
      // Right length, wrong network byte: this is the check that catches a mangled paste.
      address: `1${"A".repeat(94)}`,
    });
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("bad_address");
    const row = await server.db.get<{ status: string }>(
      "SELECT status FROM deposits WHERE user_id = ?",
      [userId],
    );
    expect(row?.status).toBe("below_minimum");
  });

  it("belongs to the owner: nobody else's dust can be pointed at your address", async () => {
    await withDust("dustowner", "0.01");
    const stranger = await register(server, "dustthief");
    // There is no route that takes a user id — the only refund a session can ask for is its
    // own — so the stranger's request finds nothing rather than somebody else's money.
    const attempt = await stranger.post<{ error: string }>("/api/wallet/refunds", {
      address: ADDRESS,
    });
    expect(attempt.status).toBe(409);
    expect(attempt.body.error).toBe("nothing_to_refund");
    const row = await server.db.get<{ status: string }>(
      "SELECT d.status FROM deposits d JOIN users u ON u.id = d.user_id WHERE u.username = 'dustowner'",
    );
    expect(row?.status).toBe("below_minimum");
  });
});

describe("the platform's books admit what uncredited dust is", () => {
  it("counts it as a liability on the treasury, before anyone asks for it back", async () => {
    await withDust("dustliability", "0.004", 2);
    const admin = await register(server, "dustadmin");
    await promote(server, "dustadmin", "admin");
    const books = await admin.get<{
      liabilitiesXmr: string;
      uncreditedTopUpsXmr: string;
      userAvailableXmr: string;
    }>("/api/admin/treasury");
    // Not on anybody's balance, and still owed: 0.008 the wallet holds for its payer.
    expect(books.body).toMatchObject({
      userAvailableXmr: "0",
      uncreditedTopUpsXmr: "0.008",
      liabilitiesXmr: "0.008",
    });
  });
});

/**
 * The invariant this whole feature could break: a refund credits deposits and holds them in
 * one transaction, so every balance must still equal the sum of its own ledger entries.
 */
async function ledgerReconciles(): Promise<void> {
  const balances = await server.db.all<{
    account_id: string;
    available_pico: number;
    held_pico: number;
  }>("SELECT account_id, available_pico, held_pico FROM balances");
  for (const account of balances) {
    const sums = await server.db.get<{ available: number | null; held: number | null }>(
      `SELECT SUM(available_delta) AS available, SUM(held_delta) AS held
         FROM ledger_entries WHERE account_id = ?`,
      [account.account_id],
    );
    expect(Number(sums?.available ?? 0), account.account_id).toBe(account.available_pico);
    expect(Number(sums?.held ?? 0), account.account_id).toBe(account.held_pico);
  }
}
