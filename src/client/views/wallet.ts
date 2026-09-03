import { api } from "../api.ts";
import {
  clear,
  el,
  emptyState,
  errorState,
  field,
  input,
  notice,
  price,
  skeleton,
  table,
  toast,
  withBusy,
} from "../ui.ts";

interface Wallet {
  availableXmr: string;
  heldXmr: string;
  depositAddress: string | null;
  minDepositXmr: string;
  belowMinimumXmr: string;
  minRefundXmr: string;
  canRefund: boolean;
  fastCreditMaxXmr: string;
  confirmations: number;
  minWithdrawalXmr: string;
  reviewAboveXmr: string;
  orderFeePercent: number;
}

interface Entry {
  kind: string;
  label: string;
  availableXmr: string;
  heldXmr: string;
  orderId: string | null;
  on: string;
}

interface Withdrawal {
  id: string;
  amountXmr: string;
  addressHint: string;
  status: string;
  txid: string | null;
  networkFeeXmr: string | null;
  requestedOn: string;
}

/**
 * The balance screen.
 *
 * Three things it must say plainly, because a custodial marketplace that is vague about them
 * is the kind people write posts about: what is spendable, what is held and why, and what
 * happens to a payout after the button is pressed.
 */
export function renderWallet(root: HTMLElement): void {
  clear(root);
  const summary = el("div", { class: "stack" });
  const status = el("div", {});
  const history = el("div", { class: "stack" });
  const payouts = el("div", { class: "stack" });

  root.append(
    el("h1", {}, "Balance"),
    el(
      "p",
      { class: "lede" },
      "Your balance is in Monero, held by this marketplace. Top it up to buy; withdraw whenever you like. Nothing here asks for your wallet's keys — only an address to send to.",
    ),
    status,
    summary,
    el("h2", {}, "Payouts"),
    payouts,
    el("h2", {}, "History"),
    history,
  );
  void load();

  async function load(): Promise<void> {
    clear(status);
    clear(summary).append(skeleton("card", 1));
    try {
      const wallet = await api<Wallet>("/api/wallet");
      clear(summary).append(
        el(
          "div",
          { class: "card" },
          el("p", { class: "figure" }, price(wallet.availableXmr)),
          el("p", { class: "meta" }, "available to spend or withdraw"),
          wallet.heldXmr === "0"
            ? null
            : el(
                "p",
                {},
                `${price(wallet.heldXmr)} is held — money committed to an open order or to a payout that has not been sent. It comes back if the order is cancelled.`,
              ),
        ),
        depositCard(wallet),
        withdrawCard(wallet),
      );
      await Promise.all([loadEntries(), loadWithdrawals()]);
    } catch {
      clear(summary).append(errorState("The balance did not load.", () => void load()));
    }
  }

  function depositCard(wallet: Wallet): HTMLElement {
    if (!wallet.depositAddress) {
      return el(
        "div",
        { class: "card" },
        el("h3", {}, "Top up"),
        el(
          "p",
          {},
          "Top-ups are not open on this instance yet: it has no Monero wallet attached. Nothing is lost by waiting — do not send anything anywhere until an address appears here.",
        ),
      );
    }
    const address = el("code", { class: "address" }, wallet.depositAddress);
    const copy = el("button", { type: "button", class: "ghost" }, "Copy address");
    copy.addEventListener("click", () => {
      void navigator.clipboard
        ?.writeText(wallet.depositAddress as string)
        .then(() => toast("Address copied"))
        .catch(() => toast("Copying failed — select the address instead", "error"));
    });
    return el(
      "div",
      { class: "card" },
      el("h3", {}, "Top up"),
      el(
        "p",
        {},
        wallet.fastCreditMaxXmr === "0"
          ? `Send XMR to the address below. It belongs to your account only and does not change, so you can save it and use it again; anything that arrives is credited after ${wallet.confirmations} confirmations — about ${wallet.confirmations * 2} minutes.`
          : `Send XMR to the address below. It belongs to your account only and does not change, so you can save it and use it again. Up to ${price(wallet.fastCreditMaxXmr)} is credited after one confirmation — about two minutes; more than that waits for ${wallet.confirmations}, about ${wallet.confirmations * 2} minutes.`,
      ),
      address,
      el("div", { class: "row" }, copy),
      el(
        "p",
        { class: "meta" },
        `Minimum ${price(wallet.minDepositXmr)}, and it is enforced: a smaller transfer is recorded against your account but not credited, because the fees to move it cost more than it is worth.`,
      ),
      wallet.belowMinimumXmr === "0" ? null : refundCard(wallet),
    );
  }

  /**
   * The way out for a top-up that was too small to credit: the owner names an address and it
   * is queued like any other payout (ADR-0071). Below the refund floor there is nothing to
   * offer but the truth — it waits until there is enough of it to be worth a transfer.
   */
  function refundCard(wallet: Wallet): HTMLElement {
    const stuck = `${price(wallet.belowMinimumXmr)} arrived below the minimum, so it is not on your balance.`;
    if (!wallet.canRefund) {
      return notice(
        `${stuck} Sending it back costs more in network fees than it is worth, so it stays on your account until there is at least ${price(wallet.minRefundXmr)} of it — or ask support and a person will settle it.`,
        "error",
      );
    }
    const address = input("refundAddress", { placeholder: "4… or 8…", spellcheck: "false" });
    const submit = el("button", { type: "submit", class: "primary" }, "Send it back");
    const form = el(
      "form",
      { class: "stack" },
      field(
        "Where to send it",
        address,
        "Your own Monero address. Paste it — this is the only place it is used, and it is deleted once the transfer is sent.",
      ),
      el("div", { class: "row" }, submit),
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void withBusy(submit, async () => {
        try {
          await api("/api/wallet/refunds", { method: "POST", body: { address: address.value.trim() } });
          toast("Refund queued — it goes out with the next payouts");
          address.value = "";
          await load();
        } catch (error) {
          toast((error as Error).message, "error");
        }
      });
    });
    return el(
      "div",
      { class: "card" },
      el("h3", {}, "Send back an uncredited top-up"),
      el("p", {}, `${stuck} You can have it back: it goes out through the ordinary payout queue, all of it at once, and the marketplace pays the network fee.`),
      form,
    );
  }

  function withdrawCard(wallet: Wallet): HTMLElement {
    const amount = input("amountXmr", { inputmode: "decimal", placeholder: wallet.minWithdrawalXmr });
    const address = input("address", { placeholder: "4… or 8…", spellcheck: "false" });
    const submit = el("button", { type: "submit", class: "primary" }, "Request payout");
    const form = el(
      "form",
      { class: "stack" },
      field("Amount in XMR", amount, `At least ${price(wallet.minWithdrawalXmr)}.`),
      field(
        "Monero address",
        address,
        "Checked before anything is sent. Paste it — a hand-typed address is how people lose money.",
      ),
      el("div", { class: "row" }, submit),
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void withBusy(submit, async () => {
        try {
          const created = await api<{ status: string }>("/api/wallet/withdrawals", {
            method: "POST",
            body: { amountXmr: amount.value.trim(), address: address.value.trim() },
          });
          toast(
            created.status === "queued"
              ? "Payout queued — it goes out on the next sweep"
              : "Payout submitted for approval",
          );
          amount.value = "";
          address.value = "";
          await load();
        } catch (error) {
          toast((error as Error).message, "error");
        }
      });
    });
    return el(
      "div",
      { class: "card" },
      el("h3", {}, "Withdraw"),
      el(
        "p",
        {},
        `Payouts up to ${price(wallet.reviewAboveXmr)} go out automatically. A larger one is fine too — it waits for an administrator to approve it, and then leaves as one transaction.`,
      ),
      form,
      el(
        "p",
        { class: "meta" },
        `You receive the amount you asked for — the marketplace pays the Monero network fee. Selling here costs ${wallet.orderFeePercent}% of a completed order, taken from the seller's side.`,
      ),
    );
  }

  async function loadEntries(): Promise<void> {
    clear(history).append(skeleton("line", 3));
    const { entries } = await api<{ entries: Entry[] }>("/api/wallet/entries");
    clear(history);
    if (entries.length === 0) {
      history.append(
        emptyState("No movements yet", "Top-ups, orders and payouts all appear here, with dates."),
      );
      return;
    }
    history.append(
      table(
        ["What", "Spendable", "Held", "Date"],
        entries.map((entry) => [
          entry.orderId ? el("a", { href: "#/orders" }, entry.label) : entry.label,
          entry.availableXmr,
          entry.heldXmr,
          entry.on,
        ]),
        { caption: "Every movement on your balance" },
      ),
    );
  }

  async function loadWithdrawals(): Promise<void> {
    clear(payouts).append(skeleton("line", 2));
    const { withdrawals } = await api<{ withdrawals: Withdrawal[] }>("/api/wallet/withdrawals");
    clear(payouts);
    if (withdrawals.length === 0) {
      payouts.append(emptyState("No payouts yet", "A payout you request shows its progress here."));
      return;
    }
    for (const payout of withdrawals) payouts.append(payoutCard(payout));
  }

  function payoutCard(payout: Withdrawal): HTMLElement {
    const cancellable = payout.status === "queued" || payout.status === "approval_required";
    const cancel = el("button", { type: "button", class: "ghost" }, "Cancel");
    cancel.addEventListener("click", () => {
      void withBusy(cancel, async () => {
        try {
          await api(`/api/wallet/withdrawals/${payout.id}/cancel`, { method: "POST" });
          toast("Payout cancelled — the money is back on your balance");
          await load();
        } catch (error) {
          toast((error as Error).message, "error");
        }
      });
    });
    return el(
      "div",
      { class: "card" },
      el("p", {}, `${price(payout.amountXmr)} → ${payout.addressHint}`),
      el("p", { class: "meta" }, describe(payout)),
      payout.txid ? el("p", { class: "meta" }, `Transaction ${payout.txid}`) : null,
      cancellable ? el("div", { class: "row" }, cancel) : null,
    );
  }
}

/**
 * Payout states in words. The server sends a state, this says what it means for the person
 * waiting — including the two that are not good news, which a screen that only ever says
 * "processing" would hide.
 */
function describe(payout: Withdrawal): string {
  switch (payout.status) {
    case "queued":
      return `Queued on ${payout.requestedOn}. It leaves on the next sweep.`;
    case "approval_required":
      return `Waiting for approval since ${payout.requestedOn}. Above the automatic limit, a person looks at it.`;
    case "sending":
      return "Being sent now.";
    case "sent":
      return `Sent${payout.networkFeeXmr ? `, network fee ${price(payout.networkFeeXmr)}` : ""}. Check your own wallet — that is the only proof worth having.`;
    case "failed":
      return "Could not be sent. The money is back on your balance; try again, and check the address.";
    case "rejected":
      return "Refused by an administrator. The money is back on your balance.";
    case "cancelled":
      return "Cancelled by you. The money is back on your balance.";
    default:
      return payout.status;
  }
}
