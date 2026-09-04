/**
 * The queue the payout worker pulls from.
 *
 * This is the seam between the process that owns the books and the process that owns a spend
 * key, and the direction of the arrows is the whole design: the worker calls *in*, takes one
 * payout, sends it from a wallet this server cannot reach, and reports what happened. The
 * application never calls the worker, never learns where it runs, and never holds anything
 * that could sign a transaction (docs/PAYMENTS.md §Keys).
 *
 * Three endpoints, one shared secret, and no session — the caller is a program on another
 * host, not a person in a browser. The token is compared in constant time and the queue does
 * not exist at all when it is unset, which is the state of every deployment that has not
 * built a payout tier yet.
 *
 * What an attacker who steals the token gets: the destination address and amount of payouts
 * as they are claimed, and the ability to mark them failed (which returns the money to its
 * owner's balance) or sent (which does not move a coin — it strands a payout that never left,
 * and shows up in the next solvency comparison as a surplus). What they do not get is a
 * transfer, because nothing on this side can make one.
 */
import type { FastifyInstance, FastifyRequest } from "fastify";
import { unauthorized, badRequest } from "../lib/errors.ts";
import { asId, asXmrAmount, onlyKeys } from "../lib/validate.ts";
import { constantTimeEqual } from "../lib/ids.ts";
import { claimWithdrawal, markWithdrawalFailed, markWithdrawalSent } from "../lib/ledger.ts";
import { xmrString } from "../../shared/money.ts";

export async function registerPayoutRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  function requireWorker(request: FastifyRequest): void {
    const expected = config.payoutWorkerToken;
    // No token configured means no payout tier: the endpoint answers exactly as it does to a
    // wrong token, so probing it says nothing about the deployment.
    if (!expected) throw unauthorized();
    const header = request.headers.authorization;
    const presented = typeof header === "string" && header.startsWith("Bearer ")
      ? header.slice("Bearer ".length)
      : "";
    // Constant-time, and false for a missing header rather than an exception (`lib/ids.ts`).
    if (!presented || !constantTimeEqual(presented, expected)) throw unauthorized();
  }

  /**
   * One payout, or nothing. The address is returned in full — it is the only moment it is
   * needed, and `markWithdrawalSent` deletes it immediately afterwards.
   */
  app.post("/api/payouts/claim", async (request) => {
    requireWorker(request);
    const claimed = await claimWithdrawal(db);
    if (!claimed) return { payout: null };
    return {
      payout: {
        id: claimed.id,
        amountXmr: xmrString(claimed.amountPico),
        address: claimed.address,
      },
    };
  });

  /**
   * It was sent. The transaction id becomes the payee's receipt, the network fee is recorded
   * for the operator's own accounting, and the destination is forgotten.
   */
  app.post("/api/payouts/:id/sent", async (request) => {
    requireWorker(request);
    const id = asId((request.params as { id: string }).id, "id");
    const body = (request.body ?? {}) as Record<string, unknown>;
    onlyKeys(body, ["txid", "networkFeeXmr"]);
    const txid = body.txid;
    if (typeof txid !== "string" || !/^[0-9a-f]{64}$/.test(txid)) {
      throw badRequest("txid must be a 64-character Monero transaction hash", "invalid_txid");
    }
    // Zero is a legitimate answer from a wallet that reports no fee, so the minimum is 0.
    const networkFeePico = asXmrAmount(body.networkFeeXmr ?? "0", "networkFeeXmr", 0);
    await markWithdrawalSent(db, { id, txid, networkFeePico });
    return { id, status: "sent" };
  });

  /**
   * It was not sent. The money returns to the owner's spendable balance, which is the only
   * safe direction: a payout that failed and stayed held is a balance its owner cannot use
   * and cannot explain.
   */
  app.post("/api/payouts/:id/failed", async (request) => {
    requireWorker(request);
    const id = asId((request.params as { id: string }).id, "id");
    // The worker may say why in its own logs; this server does not record a reason, because
    // the reasons are wallet-side ("not enough unlocked balance", "invalid address") and none
    // of them is the account owner's business to have stored against their name.
    onlyKeys((request.body ?? {}) as Record<string, unknown>, []);
    await markWithdrawalFailed(db, id);
    return { id, status: "failed" };
  });
}
