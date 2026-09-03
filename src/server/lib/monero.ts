/**
 * The wallet, as seen by a process that must never be able to spend.
 *
 * `monero-wallet-rpc` speaks JSON-RPC over HTTP, which is `fetch` and thirty lines rather
 * than a wallet library in the dependency list (docs/DEPENDENCIES.md). What makes this file
 * safe is not the transport but the vocabulary: it can ask for a new subaddress, read
 * incoming transfers and read a total. There is no method here that moves money, and there
 * is no key here that could sign one — the wallet this talks to is opened with a private
 * **view key** and holds nothing else (docs/PAYMENTS.md §Keys).
 *
 * Sending is a different process on a different host with a different wallet
 * (`scripts/payout-worker.mjs`), and the only thing it shares with this one is a queue.
 */
import { log } from "./log.ts";

/** The three calls this tier is allowed to make. A fourth belongs in the payout worker. */
const ALLOWED = ["create_address", "get_transfers", "get_balance"] as const;
type Method = (typeof ALLOWED)[number];

export interface IncomingTransfer {
  txid: string;
  amountPico: number;
  subaddressIndex: number;
  confirmations: number;
}

export interface WalletRpc {
  /** A fresh subaddress on the deposit account, with the index that identifies it later. */
  createAddress(label: string): Promise<{ address: string; subaddressIndex: number }>;
  /** Every confirmed incoming transfer the wallet has ever seen. */
  incoming(): Promise<IncomingTransfer[]>;
  /** What the wallet holds, locked and unlocked together, in piconero. */
  totalPico(): Promise<number>;
}

/**
 * The Monero account whose subaddresses are handed to users. Zero is the wallet's own
 * account and there is no reason here to have a second one: subaddress *indices* are what
 * separate one payer from another, and the wallet is single-purpose already.
 */
const DEPOSIT_ACCOUNT = 0;

/** A transfer this platform will not try to represent: amounts are integers, always. */
function asPico(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`the wallet returned a ${field} this server cannot represent exactly`);
  }
  return value;
}

export function walletRpc(baseUrl: string, timeoutMs = 15_000): WalletRpc {
  const endpoint = `${baseUrl.replace(/\/+$/, "")}/json_rpc`;

  async function call(method: Method, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "0", method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error(`wallet rpc ${method}: HTTP ${response.status}`);
    const body = (await response.json()) as {
      result?: Record<string, unknown>;
      error?: { message?: string };
    };
    // The message is the wallet's own and says nothing about a user; an address or an
    // amount never reaches a log line from here (docs/LOGGING.md).
    if (body.error) throw new Error(`wallet rpc ${method}: ${body.error.message ?? "failed"}`);
    if (!body.result) throw new Error(`wallet rpc ${method}: no result`);
    return body.result;
  }

  return {
    async createAddress(label) {
      const result = await call("create_address", { account_index: DEPOSIT_ACCOUNT, label });
      const address = result.address;
      const index = result.address_index;
      if (typeof address !== "string" || typeof index !== "number" || !Number.isInteger(index)) {
        throw new Error("wallet rpc create_address: unusable answer");
      }
      return { address, subaddressIndex: index };
    },

    async incoming() {
      // `pool` and `pending` are deliberately off: an unconfirmed transfer is not money, and
      // crediting one is how a marketplace pays for a transaction that never lands.
      const result = await call("get_transfers", {
        in: true,
        out: false,
        pending: false,
        failed: false,
        pool: false,
        account_index: DEPOSIT_ACCOUNT,
      });
      const rows = Array.isArray(result.in) ? (result.in as Array<Record<string, unknown>>) : [];
      const transfers: IncomingTransfer[] = [];
      for (const row of rows) {
        const subaddress = row.subaddr_index as { minor?: number } | undefined;
        if (typeof row.txid !== "string" || typeof subaddress?.minor !== "number") continue;
        transfers.push({
          txid: row.txid,
          amountPico: asPico(row.amount, "amount"),
          subaddressIndex: subaddress.minor,
          confirmations: typeof row.confirmations === "number" ? row.confirmations : 0,
        });
      }
      return transfers;
    },

    async totalPico() {
      const result = await call("get_balance", { account_index: DEPOSIT_ACCOUNT });
      // The locked part counts: it is money this platform holds, it just cannot move yet.
      // Comparing only the unlocked part against liabilities would report a shortfall every
      // time somebody topped up (docs/PAYMENTS.md §Confirmations).
      return asPico(result.balance, "balance");
    },
  };
}

/**
 * A wallet that is configured but unreachable must not take the site down: a deposit address
 * that cannot be created is a screen that says top-ups are not open, and a scan that fails is
 * a scan that runs again in a minute. Every caller here is best-effort by design, and the
 * failure is a log line an operator can alert on.
 */
export async function quietly<T>(event: string, work: () => Promise<T>): Promise<T | null> {
  try {
    return await work();
  } catch (error) {
    log({ level: "error", event, message: (error as Error).message });
    return null;
  }
}
