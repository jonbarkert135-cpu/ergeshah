/**
 * The Monero tier (PAY-2, ADR-0070), against a wallet that is not Monero.
 *
 * A real `monero-wallet-rpc` needs a node, a chain and twenty minutes to confirm anything,
 * which is why the deposit path has historically been the untested half of every marketplace
 * like this one. The wallet below is forty lines of `node:http` speaking the same JSON-RPC,
 * and it is enough to assert the properties that actually matter: money is credited once,
 * only when confirmed, only to the account that owns the subaddress, and never by a request
 * anyone can make.
 *
 * What this cannot prove is that the RPC vocabulary is right — that `get_transfers` really
 * returns `subaddr_index.minor`, that amounts really are atomic units. Those come from the
 * documented API (`docs/SOURCES.md`) and are checked against a stagenet node before this ever
 * touches mainnet (roadmap PAY-6).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { register, startTestServer, promote, type TestServer } from "./helpers.ts";
import { scanDeposits, solvency } from "../src/server/lib/deposits.ts";
import { walletRpc } from "../src/server/lib/monero.ts";
import { requestWithdrawal } from "../src/server/lib/ledger.ts";
import { parseXmr, xmrString } from "../src/shared/money.ts";

const ADDRESS = "4".padEnd(95, "A");
const OTHER_ADDRESS = "8".padEnd(95, "B");

interface FakeWallet {
  url: string;
  /** Confirmed incoming transfers, as `get_transfers` reports them. */
  transfers: Array<{ txid: string; amount: number; minor: number; confirmations: number }>;
  balance: number;
  created: number;
  close(): Promise<void>;
}

/** A `monero-wallet-rpc` that answers the three calls the application tier may make. */
async function fakeWallet(): Promise<FakeWallet> {
  const state = { transfers: [] as FakeWallet["transfers"], balance: 0, created: 0 };
  const server: Server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      const call = JSON.parse(body || "{}") as { method: string; params?: Record<string, unknown> };
      let result: Record<string, unknown> = {};
      if (call.method === "create_address") {
        state.created += 1;
        result = { address: `${ADDRESS.slice(0, 90)}${String(state.created).padStart(5, "0")}`, address_index: state.created };
      } else if (call.method === "get_transfers") {
        result = {
          in: state.transfers.map((transfer) => ({
            txid: transfer.txid,
            amount: transfer.amount,
            confirmations: transfer.confirmations,
            subaddr_index: { major: 0, minor: transfer.minor },
          })),
        };
      } else if (call.method === "get_balance") {
        result = { balance: state.balance, unlocked_balance: state.balance };
      } else {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: "0", error: { code: -32_601, message: "unknown method" } }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: "0", result }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    get transfers() {
      return state.transfers;
    },
    get balance() {
      return state.balance;
    },
    set balance(value: number) {
      state.balance = value;
    },
    get created() {
      return state.created;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const WORKER_TOKEN = `worker-token-${randomUUID()}`;

let wallet: FakeWallet;
let server: TestServer;

beforeEach(async () => {
  wallet = await fakeWallet();
  server = await startTestServer({
    moneroWalletRpcUrl: wallet.url,
    payoutWorkerToken: WORKER_TOKEN,
  });
});

afterEach(async () => {
  await server.close();
  await wallet.close();
});

const xmr = (value: string) => parseXmr(value)!;

/** The payout worker's shape of request: a bearer token and no session at all. */
function asWorker(url: string, body: unknown = {}, token = WORKER_TOKEN) {
  return server.app.inject({
    method: "POST",
    url,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
      cookie: "csrf=worker",
      "x-csrf-token": "worker",
    },
    payload: JSON.stringify(body),
  });
}

describe("a deposit address is the wallet's, and it is permanent", () => {
  it("creates one on first sight of the wallet screen and never a second", async () => {
    const user = await register(server, "depositor");
    const first = await user.get<{ depositAddress: string | null }>("/api/wallet");
    expect(first.body.depositAddress).toBeTruthy();
    const second = await user.get<{ depositAddress: string | null }>("/api/wallet");
    expect(second.body.depositAddress).toBe(first.body.depositAddress);
    // One RPC call, not one per page view: the pair is stored, because an account that
    // changed address would leave the money sent to the old one unattributable.
    expect(wallet.created).toBe(1);
    const row = await server.db.get<{ subaddress_index: number }>(
      "SELECT subaddress_index FROM deposit_addresses",
    );
    expect(row!.subaddress_index).toBe(1);
  });

  it("says top-ups are not open when the wallet is unreachable, rather than inventing one", async () => {
    await wallet.close();
    const user = await register(server, "unlucky");
    const response = await user.get<{ depositAddress: string | null }>("/api/wallet");
    // The request still succeeds — a wallet outage is not an outage of the marketplace.
    expect(response.status).toBe(200);
    expect(response.body.depositAddress).toBeNull();
  });
});

describe("the watcher credits what the chain confirmed, once", () => {
  async function watchedUser(name: string) {
    const user = await register(server, name);
    await user.get("/api/wallet"); // gives them an address
    const row = await server.db.get<{ user_id: string; subaddress_index: number }>(
      "SELECT user_id, subaddress_index FROM deposit_addresses ORDER BY subaddress_index DESC",
    );
    return { user, ...row! };
  }

  const scan = () =>
    scanDeposits(server.db, walletRpc(wallet.url), {
      minConfirmations: 3,
      minPico: server.config.minDepositPico,
    });

  it("waits for confirmations, then credits exactly once", async () => {
    const { user, subaddress_index } = await watchedUser("patient");
    wallet.transfers.push({ txid: "a".repeat(64), amount: xmr("1"), minor: subaddress_index, confirmations: 1 });

    expect((await scan()).credited).toBe(0);
    const early = await user.get<{ availableXmr: string }>("/api/wallet");
    expect(early.body.availableXmr).toBe("0");

    wallet.transfers[0]!.confirmations = 3;
    expect((await scan()).credited).toBe(1);
    const credited = await user.get<{ availableXmr: string }>("/api/wallet");
    expect(credited.body.availableXmr).toBe("1");

    // The wallet keeps reporting the same transfer forever. A second credit would be money
    // the platform does not have, and this is the test that says it cannot happen.
    expect((await scan()).credited).toBe(0);
    const again = await user.get<{ availableXmr: string }>("/api/wallet");
    expect(again.body.availableXmr).toBe("1");
    const rows = await server.db.all("SELECT id FROM deposits");
    expect(rows).toHaveLength(1);
  });

  it("credits the account that owns the subaddress, and nobody for one it does not know", async () => {
    const first = await watchedUser("owner-a");
    const second = await watchedUser("owner-b");
    wallet.transfers.push(
      { txid: "b".repeat(64), amount: xmr("0.5"), minor: second.subaddress_index, confirmations: 5 },
      { txid: "c".repeat(64), amount: xmr("9"), minor: 999, confirmations: 5 },
    );
    const result = await scan();
    expect(result.credited).toBe(1);
    expect(result.unattributed).toBe(1);

    expect((await first.user.get<{ availableXmr: string }>("/api/wallet")).body.availableXmr).toBe("0");
    expect((await second.user.get<{ availableXmr: string }>("/api/wallet")).body.availableXmr).toBe("0.5");
    // The unknown transfer is not credited to anyone, and not invented into a row either.
    expect(await server.db.all("SELECT id FROM deposits")).toHaveLength(1);
  });

  it("records a below-minimum top-up without crediting it (ADR-0067)", async () => {
    const { user, subaddress_index } = await watchedUser("dusty");
    wallet.transfers.push({ txid: "d".repeat(64), amount: xmr("0.005"), minor: subaddress_index, confirmations: 4 });
    const result = await scan();
    expect(result).toMatchObject({ credited: 0, belowMinimum: 1 });
    const view = await user.get<{ availableXmr: string; belowMinimumXmr: string }>("/api/wallet");
    expect(view.body.availableXmr).toBe("0");
    expect(view.body.belowMinimumXmr).toBe("0.005");
  });
});

describe("solvency is a number an operator can see", () => {
  it("compares the books against the wallet and names the shortfall", async () => {
    const { db } = server;
    const user = await register(server, "creditor");
    await user.get("/api/wallet");
    const row = await server.db.get<{ subaddress_index: number }>("SELECT subaddress_index FROM deposit_addresses");
    wallet.transfers.push({ txid: "e".repeat(64), amount: xmr("2"), minor: row!.subaddress_index, confirmations: 6 });
    await scanDeposits(db, walletRpc(wallet.url), { minConfirmations: 3, minPico: server.config.minDepositPico });

    wallet.balance = xmr("2");
    const solvent = await solvency(db, walletRpc(wallet.url));
    expect(solvent).toMatchObject({ liabilitiesPico: xmr("2"), walletPico: xmr("2"), shortfallPico: 0 });

    // The state that must never be discovered by a seller first.
    wallet.balance = xmr("1.5");
    expect((await solvency(db, walletRpc(wallet.url))).shortfallPico).toBe(xmr("0.5"));

    const admin = await register(server, "treasurer");
    await promote(server, "treasurer", "admin");
    const books = await admin.get<{ walletXmr: string; shortfallXmr: string; liabilitiesXmr: string }>(
      "/api/admin/treasury",
    );
    expect(books.body).toMatchObject({ liabilitiesXmr: "2", walletXmr: "1.5", shortfallXmr: "0.5" });
  });
});

describe("the payout queue belongs to the worker and to nobody else", () => {
  async function queuedPayout(): Promise<{ id: string; userId: string }> {
    const user = await register(server, "withdrawer");
    await user.get("/api/wallet");
    const row = await server.db.get<{ subaddress_index: number }>("SELECT subaddress_index FROM deposit_addresses");
    wallet.transfers.push({ txid: "f".repeat(64), amount: xmr("1"), minor: row!.subaddress_index, confirmations: 6 });
    await scanDeposits(server.db, walletRpc(wallet.url), { minConfirmations: 3, minPico: server.config.minDepositPico });
    const account = await server.db.get<{ id: string }>("SELECT id FROM users WHERE username = 'withdrawer'");
    const created = await requestWithdrawal(server.db, {
      userId: account!.id,
      amountPico: xmr("0.5"),
      address: OTHER_ADDRESS,
      limitPico: xmr("2"),
    });
    expect(created.status).toBe("queued");
    return { id: created.id, userId: account!.id };
  }

  it("refuses a caller with no token, a wrong token, and a browser session", async () => {
    await queuedPayout();
    for (const attempt of [
      server.app.inject({ method: "POST", url: "/api/payouts/claim", headers: { cookie: "csrf=x", "x-csrf-token": "x" } }),
      asWorker("/api/payouts/claim", {}, "not-the-token"),
    ]) {
      expect((await attempt).statusCode).toBe(401);
    }
    // A signed-in user is not a payout worker: the session is irrelevant here, which is the
    // point — this endpoint is not part of the browser API at all.
    const person = await register(server, "curious");
    const asPerson = await person.post("/api/payouts/claim", {});
    expect(asPerson.status).toBe(401);
  });

  it("hands out one payout with its destination, and only once", async () => {
    const { id } = await queuedPayout();
    const claimed = await asWorker("/api/payouts/claim");
    expect(claimed.statusCode).toBe(200);
    expect(claimed.json()).toMatchObject({ payout: { id, amountXmr: "0.5", address: OTHER_ADDRESS } });

    // Claimed means sending. A second worker, or the same one after a restart, gets nothing.
    const second = await asWorker("/api/payouts/claim");
    expect(second.json()).toEqual({ payout: null });
  });

  it("marks a payout sent, forgets the destination, and keeps the ledger square", async () => {
    const { id, userId } = await queuedPayout();
    await asWorker("/api/payouts/claim");
    const txid = "1".repeat(64);
    const sent = await asWorker(`/api/payouts/${id}/sent`, { txid, networkFeeXmr: "0.0001" });
    expect(sent.statusCode).toBe(200);

    const row = await server.db.get<{ status: string; address: string | null; txid: string }>(
      "SELECT status, address, txid FROM withdrawals WHERE id = ?",
      [id],
    );
    expect(row).toMatchObject({ status: "sent", address: null, txid });
    const balance = await server.db.get<{ available_pico: number; held_pico: number }>(
      "SELECT available_pico, held_pico FROM balances WHERE account_id = ?",
      [userId],
    );
    // 1 XMR in, 0.5 requested and now gone; nothing left held.
    expect(xmrString(balance!.available_pico)).toBe("0.5");
    expect(balance!.held_pico).toBe(0);
  });

  it("refuses a transaction id that is not one, and returns the money when a send fails", async () => {
    const { id, userId } = await queuedPayout();
    await asWorker("/api/payouts/claim");
    const nonsense = await asWorker(`/api/payouts/${id}/sent`, { txid: "not-a-hash" });
    expect(nonsense.statusCode).toBe(400);
    expect(nonsense.json()).toMatchObject({ error: "invalid_txid" });

    const failed = await asWorker(`/api/payouts/${id}/failed`);
    expect(failed.statusCode).toBe(200);
    const balance = await server.db.get<{ available_pico: number; held_pico: number }>(
      "SELECT available_pico, held_pico FROM balances WHERE account_id = ?",
      [userId],
    );
    expect(xmrString(balance!.available_pico)).toBe("1");
    expect(balance!.held_pico).toBe(0);
  });
});

describe("the application tier cannot spend, and this is what says so", () => {
  it("uses three read-only wallet calls and no fourth", () => {
    const source = readFileSync(new URL("../src/server/lib/monero.ts", import.meta.url), "utf8");
    const methods = [...source.matchAll(/call\("([a-z_]+)"/g)].map((match) => match[1]);
    expect(new Set(methods)).toEqual(new Set(["create_address", "get_transfers", "get_balance"]));
    expect(source).not.toMatch(/"transfer"|validate_address|open_wallet|restore/);
  });

  it("keeps the only spending process outside the server, where its key is", () => {
    const worker = readFileSync(new URL("../scripts/payout-worker.mjs", import.meta.url), "utf8");
    // The worker sends; it is a script an operator runs on another host, and nothing in
    // `src` imports it or can reach it.
    expect(worker).toContain('walletRpc("transfer"');
    const app = readFileSync(new URL("../src/server/app.ts", import.meta.url), "utf8");
    expect(app).not.toContain("payout-worker");
  });
});
