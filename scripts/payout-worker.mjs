#!/usr/bin/env node
/**
 * The payout worker: the one process in this project that can move money, and it is not the
 * one serving the website.
 *
 * It runs on its own host — a small VM, a Raspberry Pi in the operator's flat, anything with
 * no inbound reachability — beside a `monero-wallet-rpc` holding a working float. It pulls
 * from the marketplace's queue over HTTPS, asks its own wallet to send, and reports back.
 * Nothing calls *it*, so an attacker who owns the web tier has nothing to talk to: the worst
 * they can do is queue payouts, which is what the per-account limits and the approval gate
 * above them are for (docs/PAYMENTS.md §Limits).
 *
 * Run it:
 *
 *   SYMVOLON_URL=https://example.org \
 *   PAYOUT_WORKER_TOKEN=$(cat /etc/symvolon/payout-token) \
 *   WALLET_RPC_URL=http://127.0.0.1:18083 \
 *   MAX_PAYOUT_XMR=5 \
 *   node scripts/payout-worker.mjs
 *
 * Deliberately dependency-free and deliberately dull: one payout at a time, no retry of a
 * send that may already have happened, and a loud stop when the world stops making sense.
 */
const app = (process.env.SYMVOLON_URL ?? "").replace(/\/+$/, "");
const token = process.env.PAYOUT_WORKER_TOKEN ?? "";
const wallet = (process.env.WALLET_RPC_URL ?? "").replace(/\/+$/, "");
const pollMs = Number(process.env.POLL_SECONDS ?? 30) * 1000;
/**
 * The float, as a rule this process enforces on itself. A payout above it is *not* sent and
 * not silently held: it is reported failed, the money returns to its owner's spendable
 * balance, and the operator sees a payout that needs the wallet topped up. Refusing here is
 * the point of a hot/cold split — the worker can only ever lose what the float holds.
 */
const maxPayoutPico = xmrToPico(process.env.MAX_PAYOUT_XMR ?? "5");

for (const [name, value] of [["SYMVOLON_URL", app], ["PAYOUT_WORKER_TOKEN", token], ["WALLET_RPC_URL", wallet]]) {
  if (!value) {
    console.error(`${name} is required`);
    process.exit(2);
  }
}

const PICO_PER_XMR = 1_000_000_000_000n;

/** The same exact-integer parse the server uses: a decimal string, never a float. */
function xmrToPico(text) {
  const match = /^(\d+)(?:\.(\d{1,12}))?$/.exec(String(text).trim());
  if (!match) throw new Error(`not an amount of XMR: ${text}`);
  const fraction = (match[2] ?? "").padEnd(12, "0");
  return BigInt(match[1]) * PICO_PER_XMR + BigInt(fraction);
}

function picoToXmr(pico) {
  const whole = pico / PICO_PER_XMR;
  const fraction = (pico % PICO_PER_XMR).toString().padStart(12, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

/**
 * A call to the marketplace. The CSRF check compares a cookie to a header, which is a
 * browser-shaped defence: a script sets both, and the bearer token is what actually
 * authenticates this caller (src/server/routes/payouts.ts).
 */
async function marketplace(path, body) {
  const response = await fetch(`${app}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
      cookie: "csrf=payout-worker",
      "x-csrf-token": "payout-worker",
    },
    body: JSON.stringify(body ?? {}),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${path} answered ${response.status}: ${text.slice(0, 200)}`);
  return JSON.parse(text);
}

/** A call to this host's own wallet, which is the only place a spending key exists. */
async function walletRpc(method, params) {
  const response = await fetch(`${wallet}/json_rpc`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "0", method, params }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) throw new Error(`wallet ${method}: HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(`wallet ${method}: ${body.error.message ?? "failed"}`);
  return body.result;
}

/**
 * One payout, start to finish.
 *
 * The order of the two calls at the end is the only subtle thing in this file. `transfer`
 * either returns a transaction hash or throws; if it returns and the report back fails, the
 * payout is left `sending` and an operator reconciles it by hand. That is deliberate: the
 * alternative — re-queueing on an uncertain outcome — pays a person twice, and no automatic
 * rule can tell the two cases apart from this side.
 */
async function sendOne(payout) {
  const pico = xmrToPico(payout.amountXmr);
  if (pico > maxPayoutPico) {
    console.error(`payout ${payout.id} is above this worker's float; returning it to the owner`);
    await marketplace(`/api/payouts/${payout.id}/failed`, {});
    return;
  }

  const valid = await walletRpc("validate_address", { address: payout.address, any_net_type: false });
  if (!valid?.valid) {
    await marketplace(`/api/payouts/${payout.id}/failed`, {});
    return;
  }

  let sent;
  try {
    sent = await walletRpc("transfer", {
      destinations: [{ address: payout.address, amount: Number(pico) }],
      account_index: 0,
      priority: 0,
      // No transaction key, no payment id, no note: a receipt this process does not keep is
      // a receipt it cannot be compelled for. The payee has the txid and their own wallet.
      get_tx_key: false,
      do_not_relay: false,
    });
  } catch (error) {
    console.error(`payout ${payout.id} was not sent: ${error.message}`);
    await marketplace(`/api/payouts/${payout.id}/failed`, {});
    return;
  }

  await marketplace(`/api/payouts/${payout.id}/sent`, {
    txid: sent.tx_hash,
    networkFeeXmr: picoToXmr(BigInt(sent.fee ?? 0)),
  });
  console.log(`payout ${payout.id} sent`);
}

let running = true;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    running = false;
  });
}

while (running) {
  try {
    const { payout } = await marketplace("/api/payouts/claim");
    if (payout) {
      await sendOne(payout);
      continue; // there may be another one waiting
    }
  } catch (error) {
    // A marketplace that is down, a token that was rotated, a wallet that is locked: all of
    // them are "try again in a minute", and none of them is a reason to leave the queue
    // unattended. The message is printed; the amounts and addresses are not.
    console.error(`payout worker: ${error.message}`);
  }
  await new Promise((resolve) => setTimeout(resolve, pollMs));
}
