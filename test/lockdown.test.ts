/**
 * The freeze, through the API (ADR-0080).
 *
 * The proposal this replaced was a self-destruct that deleted users, orders and payments on
 * detecting a breach. These tests are the argument for the other design: while the freeze is
 * on, nothing can be changed by anybody — including an administrator and including the payout
 * worker — and everything can still be read, because a marketplace that hides balances during
 * an incident is indistinguishable from one that has run off with them.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fund, promote, register, startTestServer, type TestServer } from "./helpers.ts";
import { forgetLockdownCache } from "../src/server/lib/lockdown.ts";

const ADDRESS = `8${"A".repeat(94)}`;

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root");
  forgetLockdownCache();
});
afterEach(async () => {
  await server.close();
  forgetLockdownCache();
});

async function freeze(): Promise<void> {
  await server.db.run("INSERT INTO lockdown (id, engaged_at, note) VALUES (1, ?, 'test')", [
    Date.now(),
  ]);
  forgetLockdownCache();
}

async function thaw(): Promise<void> {
  await server.db.run("DELETE FROM lockdown");
  forgetLockdownCache();
}

describe("while the platform is frozen", () => {
  it("refuses every write with 503 and keeps every read working", async () => {
    const buyer = await register(server, "frozenbuyer");
    await fund(server, buyer, "1");
    await freeze();

    const write = await buyer.post<{ error: string; message: string }>("/api/wallet/withdrawals", {
      amountXmr: "0.5",
      address: ADDRESS,
    });
    expect(write.status).toBe(503);
    expect(write.body.error).toBe("locked_down");
    // The message says what happened and what did not, because the alternative is a user
    // reading a 503 as "they have taken my money".
    expect(write.body.message).toContain("nothing has been lost");

    // Reads are untouched: the balance, the orders, the catalogue.
    const wallet = await buyer.get<{ availableXmr: string }>("/api/wallet");
    expect(wallet.status).toBe(200);
    expect(wallet.body.availableXmr).toBe("1");
    expect((await buyer.get("/api/market/listings")).status).toBe(200);
    expect((await buyer.get("/api/wallet/entries")).status).toBe(200);
  });

  it("closes the door to a new session as well as to a signed-in one", async () => {
    await freeze();
    // Registration and login are writes: a stolen credential cannot be turned into a fresh
    // session while the operator is looking at the incident.
    const fresh = await server.app.inject({
      method: "POST",
      url: "/api/auth/register",
      payload: { username: "latecomer", authSecret: "x".repeat(43) },
    });
    expect(fresh.statusCode).toBe(503);
  });

  it("stops an administrator too, and stops the payout worker", async () => {
    const admin = await register(server, "frozenadmin");
    await promote(server, "frozenadmin", "admin");
    const seller = await register(server, "frozenseller");
    await fund(server, seller, "5");
    const parked = await seller.post<{ id: string }>("/api/wallet/withdrawals", {
      amountXmr: "3",
      address: ADDRESS,
    });
    await freeze();

    // The point of the freeze: a stolen admin session cannot move money either.
    const decided = await admin.post<{ error: string }>(
      `/api/moderation/withdrawals/${parked.body.id}/decide`,
      { decision: "approved" },
    );
    expect(decided.status).toBe(503);
    expect(decided.body.error).toBe("locked_down");
    // An admin can still *look*: the treasury and the queue are exactly what an operator
    // needs during an incident.
    expect((await admin.get("/api/admin/treasury")).status).toBe(200);
    const health = await admin.get<{ lockdown: boolean }>("/api/admin/health");
    expect(health.body.lockdown).toBe(true);

    // And the worker's queue is frozen with everything else, so nothing leaves the wallet.
    const claim = await server.app.inject({
      method: "POST",
      url: "/api/payouts/claim",
      headers: { authorization: "Bearer any" },
    });
    expect(claim.statusCode).toBe(503);
  });

  it("changes nothing about the data, and lifts cleanly", async () => {
    const buyer = await register(server, "thawbuyer");
    await fund(server, buyer, "2");
    await freeze();
    const before = await server.db.all("SELECT account_id FROM balances");
    await thaw();
    expect(await server.db.all("SELECT account_id FROM balances")).toHaveLength(before.length);
    const write = await buyer.post<{ status: string }>("/api/wallet/withdrawals", {
      amountXmr: "0.5",
      address: ADDRESS,
    });
    expect(write.status).toBe(200);
    const health = await register(server, "thawadmin");
    await promote(server, "thawadmin", "admin");
    expect((await health.get<{ lockdown: boolean }>("/api/admin/health")).body.lockdown).toBe(false);
  });
});
