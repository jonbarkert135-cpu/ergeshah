/**
 * The watcher: the half of the Monero tier that may see money and may not move it.
 *
 * Three jobs, and they are deliberately boring:
 *
 * 1. **An address per account**, created on demand from the view-only wallet. The pair
 *    (index, address) is stored once and never regenerated — a reused address would credit
 *    the wrong person, and a second address for the same account would leave a payment
 *    unattributable.
 * 2. **A scan**, on an interval, that credits confirmed transfers through `creditDeposit`
 *    and therefore through the ledger. It is idempotent twice over: the wallet is asked for
 *    everything it has seen, the rows already recorded are skipped, and the unique key on
 *    `deposits` refuses a duplicate even if both checks are wrong.
 * 3. **A solvency comparison**, because a custodial platform that learns about a shortfall
 *    from a seller has already lost the argument.
 *
 * What is *not* here: any notion of a payment being "expected". Monero transfers name no
 * sender and carry no invoice; the subaddress an account was given is the whole of the
 * attribution, which is why it is one per account and permanent.
 */
import type { Db } from "../db/index.ts";
import { creditDeposit } from "./ledger.ts";
import { belowMinimumLiability } from "./refunds.ts";
import type { WalletRpc } from "./monero.ts";
import { log } from "./log.ts";

/**
 * This account's deposit address, creating it on first use. Returns null when the wallet is
 * not configured or not answering: the wallet screen then says top-ups are not open, which
 * is the truth, instead of showing an address nobody controls.
 */
export async function depositAddressFor(
  db: Db,
  wallet: WalletRpc | null,
  userId: string,
): Promise<string | null> {
  const existing = await db.get<{ address: string }>(
    "SELECT address FROM deposit_addresses WHERE user_id = ?",
    [userId],
  );
  if (existing) return existing.address;
  if (!wallet) return null;

  // The label is what an operator sees in their own wallet. It is the account id, which is
  // already in this database, and never a username — a wallet file is a backup that travels.
  const created = await wallet.createAddress(userId);
  try {
    await db.run(
      `INSERT INTO deposit_addresses (user_id, subaddress_index, address, created_at)
       VALUES (?, ?, ?, ?)`,
      [userId, created.subaddressIndex, created.address, Date.now()],
    );
    return created.address;
  } catch {
    // Two requests raced and the other one won. Its address is the account's address; the
    // subaddress this call generated is simply never handed out, which costs nothing.
    const row = await db.get<{ address: string }>(
      "SELECT address FROM deposit_addresses WHERE user_id = ?",
      [userId],
    );
    return row?.address ?? null;
  }
}

export interface ScanResult {
  seen: number;
  credited: number;
  belowMinimum: number;
  unattributed: number;
}

/**
 * One pass over the wallet's incoming transfers.
 *
 * A transfer is credited when it has reached the confirmations its *size* requires and its
 * subaddress belongs to an account. Small top-ups take one confirmation and larger ones take
 * `minConfirmations` (ADR-0077); nothing is ever credited from the transaction pool, because
 * an unconfirmed transfer is not money. Everything else is counted and left alone: an unconfirmed transfer will be
 * confirmed on a later pass, and a transfer to a subaddress this database does not know is
 * an operator's problem (a wallet used for something else, an address handed out by hand)
 * rather than a payment this platform may credit to somebody.
 */
export async function scanDeposits(
  db: Db,
  wallet: WalletRpc,
  options: { minConfirmations: number; minPico: number; fastCreditMaxPico?: number },
): Promise<ScanResult> {
  const transfers = await wallet.incoming();
  const result: ScanResult = { seen: transfers.length, credited: 0, belowMinimum: 0, unattributed: 0 };
  if (transfers.length === 0) return result;

  const owners = new Map<number, string>();
  for (const row of await db.all<{ user_id: string; subaddress_index: number }>(
    "SELECT user_id, subaddress_index FROM deposit_addresses",
  )) {
    owners.set(row.subaddress_index, row.user_id);
  }
  // The rows already recorded, so a steady state costs one SELECT and no failed INSERTs.
  const known = new Set<string>(
    (
      await db.all<{ txid: string; subaddress_index: number; amount_pico: number }>(
        "SELECT txid, subaddress_index, amount_pico FROM deposits",
      )
    ).map((row) => `${row.txid}:${row.subaddress_index}:${row.amount_pico}`),
  );

  for (const transfer of transfers) {
    if (transfer.confirmations < confirmationsFor(transfer.amountPico, options)) continue;
    if (known.has(`${transfer.txid}:${transfer.subaddressIndex}:${transfer.amountPico}`)) continue;
    const userId = owners.get(transfer.subaddressIndex);
    if (!userId) {
      result.unattributed += 1;
      continue;
    }
    const id = await creditDeposit(db, {
      userId,
      amountPico: transfer.amountPico,
      txid: transfer.txid,
      subaddressIndex: transfer.subaddressIndex,
      confirmations: transfer.confirmations,
      minPico: options.minPico,
    });
    if (id === null) continue; // already credited: the unique key said so
    if (transfer.amountPico >= options.minPico) result.credited += 1;
    else result.belowMinimum += 1;
  }

  if (result.unattributed > 0) {
    // Counted, never described: an amount or an index in a log line is a payment record in
    // a file with a different retention policy from the database (docs/LOGGING.md).
    log({ level: "info", event: "deposit.unattributed", metrics: { count: result.unattributed } });
  }
  return result;
}

/**
 * How many confirmations this amount has to have. One for a small top-up, the configured
 * count for everything else, and never zero: the fast lane is faster, not free (ADR-0077).
 */
export function confirmationsFor(
  amountPico: number,
  options: { minConfirmations: number; fastCreditMaxPico?: number },
): number {
  const fastMax = options.fastCreditMaxPico ?? 0;
  if (fastMax > 0 && amountPico <= fastMax) return Math.min(1, options.minConfirmations);
  return options.minConfirmations;
}

export interface Solvency {
  liabilitiesPico: number;
  walletPico: number;
  shortfallPico: number;
}

/**
 * What the platform owes against what the wallet holds.
 *
 * Liabilities are every balance in the table, the platform's own fee account included: the
 * fee is earned money that has not been swept, and a comparison that ignored it would report
 * a surplus that is really somebody's payout waiting to happen. Uncredited top-ups count too
 * (ADR-0071): they are in the wallet, they are owed to the people who sent them, and leaving
 * them out would show a surplus exactly the size of what the platform owes its dust payers. A shortfall is logged loudly
 * because it has exactly two causes, and both need a human today: a bug in the ledger, or a
 * wallet that is not the one this deployment thinks it is.
 */
export async function solvency(db: Db, wallet: WalletRpc): Promise<Solvency> {
  const row = await db.get<{ available: number | null; held: number | null }>(
    "SELECT SUM(available_pico) AS available, SUM(held_pico) AS held FROM balances",
  );
  const liabilitiesPico =
    Number(row?.available ?? 0) + Number(row?.held ?? 0) + (await belowMinimumLiability(db));
  const walletPico = await wallet.totalPico();
  const shortfallPico = Math.max(0, liabilitiesPico - walletPico);
  if (shortfallPico > 0) {
    log({ level: "error", event: "treasury.shortfall", metrics: { shortfallPico } });
  }
  return { liabilitiesPico, walletPico, shortfallPico };
}
