import { api } from "../api.ts";
import { clear, el, emptyState, errorState, formDialog, notice, price as formatPrice, skeleton, table } from "../ui.ts";

interface Queue {
  reports: Array<{
    id: string;
    targetType: string;
    targetId: string;
    reason: string;
    details: string;
    reporter: string;
    reportedOn: string;
    order: {
      id: string;
      status: string;
      title: string;
      kind: string;
      priceXmr: string;
      buyer: string;
      seller: string;
      updatedOn: string;
      sellerRecord: { completedOrders: number; disputedOrders: number; distinctReviewers: number; averageRating: number | null };
      buyerRecord: { completedOrders: number; disputedOrders: number; disputeRate: number; orders: number };
      evidence: Array<{ by: string; kind: string; digest: string; on: string; beforeDispute: boolean }>;
    } | null;
  }>;
  sellerApplications: Array<{
    id: string;
    username: string;
    displayName: string;
    statement: string;
    submittedOn: string;
  }>;
}

interface Payouts {
  withdrawals: Array<{
    id: string;
    username: string;
    amountXmr: string;
    addressHint: string;
    status: string;
    requestedOn: string;
    sendingForMinutes: number | null;
    stuck: boolean;
    approvals: number;
    approvalsRequired: number;
  }>;
}

interface Treasury {
  userAvailableXmr: string;
  userHeldXmr: string;
  platformEarnedXmr: string;
  queuedPayoutsXmr: string;
  uncreditedTopUpsXmr: string;
  liabilitiesXmr: string;
  walletXmr: string | null;
  shortfallXmr: string | null;
}

export function renderModeration(root: HTMLElement): void {
  clear(root);
  const body = el("div", {});
  root.append(
    el("h1", {}, "Moderation"),
    el(
      "p",
      { class: "lede" },
      "Moderators act on what is public: applications, listings, reviews, reports. There is no endpoint anywhere in this codebase that reveals a private message.",
    ),
    body,
  );
  void load();

  async function load() {
    clear(body).append(skeleton("line", 4));
    let queue: Queue;
    let audit: {
      entries: Array<{ actor: string | null; action: string; subjectId: string; note: string; at: string }>;
    };
    let payouts: Payouts;
    try {
      // Independent reads, in parallel: a moderator waiting three times for one screen is a
      // latency bug that nobody reports and everybody feels.
      [queue, audit, payouts] = await Promise.all([
        api<Queue>("/api/moderation/queue"),
        api<{
          entries: Array<{ actor: string | null; action: string; subjectId: string; note: string; at: string }>;
        }>("/api/moderation/audit"),
        api<Payouts>("/api/moderation/withdrawals"),
      ]);
    } catch {
      clear(body).append(errorState("The moderation queue did not load.", () => void load()));
      return;
    }
    clear(body);

    body.append(el("h2", {}, "Seller applications"));
    if (queue.sellerApplications.length === 0) {
      body.append(emptyState("No applications waiting", "Nobody has asked to sell since the last review."));
    }
    for (const application of queue.sellerApplications) {
      body.append(
        el(
          "div",
          { class: "card" },
          el("strong", {}, `${application.displayName} (@${application.username})`),
          el("p", {}, application.statement),
          el("div", { class: "muted mono" }, `submitted ${application.submittedOn}`),
          el(
            "div",
            { class: "row" },
            decideButton(application.id, "approved", "Approve"),
            decideButton(application.id, "rejected", "Reject"),
          ),
        ),
      );
    }

    body.append(el("h2", {}, "Reports"));
    if (queue.reports.length === 0) {
      body.append(emptyState("No open reports", "Nothing has been reported that is still unresolved."));
    }
    for (const report of queue.reports) {
      const order = report.order;
      body.append(
        el(
          "div",
          { class: "card" },
          el("h3", { class: "tight" }, `${report.reason} — ${report.targetType}`),
          el("div", { class: "mono muted" }, report.targetId),
          report.details ? el("p", {}, report.details) : null,
          el("div", { class: "muted mono" }, `by ${report.reporter} on ${report.reportedOn}`),
          // A dispute: the order's public facts and the seller's record, never the channel.
          order
            ? el(
                "p",
                { class: "muted" },
                `${order.title} (${order.kind}), ${formatPrice(order.priceXmr)} · buyer @${order.buyer}, seller @${order.seller} · ${order.status} since ${order.updatedOn}. ` +
                  `Seller record: ${order.sellerRecord.completedOrders} completed, ${order.sellerRecord.disputedOrders} disputed, ` +
                  (order.sellerRecord.averageRating === null ? "no reviews." : `★ ${order.sellerRecord.averageRating} from ${order.sellerRecord.distinctReviewers} buyers.`),
              )
            : null,
          order
            ? el(
                "p",
                { class: "muted small" },
                // The other side of the argument. Facts, not a verdict: the moderator decides
                // (ADR-0083).
                `Buyer record: ${order.buyerRecord.orders} orders, ${order.buyerRecord.completedOrders} completed, ` +
                  `${order.buyerRecord.disputedOrders} disputed` +
                  (order.buyerRecord.orders >= 4
                    ? ` (${order.buyerRecord.disputeRate}% of their orders).`
                    : "."),
              )
            : null,
          order && order.evidence.length > 0 ? evidenceCard(order.evidence) : null,
          el(
            "div",
            { class: "row" },
            ...(order && order.status === "disputed"
              ? [settleButton(order.id, "cancelled", "Settle: cancel order"), settleButton(order.id, "completed", "Settle: complete for seller")]
              : [resolveButton(report.id, "actioned", "Mark actioned")]),
            resolveButton(report.id, "dismissed", "Dismiss"),
            report.targetType === "listing" ? removeListingButton(report.targetId) : null,
            report.targetType === "user" ? suspendButton(report.targetId) : null,
          ),
        ),
      );
    }

    const treasury = el("div", {});
    const payoutList = el("div", { class: "stack" });
    body.append(el("h2", {}, "Payouts"), treasury, payoutList);
    // The treasury is an admin-only read, so a moderator simply does not get this block —
    // and does not get an error about it either.
    void api<Treasury>("/api/admin/treasury")
      .then((books) => treasury.append(treasuryCard(books)))
      .catch(() => undefined);
    if (payouts.withdrawals.length === 0) {
      payoutList.append(emptyState("Nothing waiting", "No payout needs a decision or a rescue."));
    }
    for (const payout of payouts.withdrawals) {
      payoutList.append(payoutCard(payout));
    }

    body.append(
      el("h2", {}, "Audit log"),
      table(
        ["When", "Actor", "Action", "Subject", "Note"],
        audit.entries.map((entry) => [
          el("span", { class: "mono" }, new Date(entry.at).toLocaleString()),
          el("span", { class: "mono" }, entry.actor ?? "—"),
          entry.action,
          el("span", { class: "mono" }, entry.subjectId.slice(0, 12)),
          entry.note,
        ]),
        { caption: "Administrative actions, newest first" },
      ),
    );
  }

  /**
   * What the two parties committed to (ADR-0074). It is not proof that a file was good or
   * even sent — it is proof that neither side's story has changed since they published it,
   * and the caption says exactly that so nobody reads more into a digest than it holds.
   */
  function evidenceCard(evidence: NonNullable<Queue["reports"][number]["order"]>["evidence"]): HTMLElement {
    return table(
      ["Side", "What they say it is", "Digest", "Committed", "Before the dispute"],
      evidence.map((entry) => [
        entry.by,
        entry.kind,
        el("span", { class: "mono" }, `${entry.digest.slice(0, 16)}…`),
        el("span", { class: "mono" }, entry.on),
        entry.beforeDispute ? "yes" : "no",
      ]),
      {
        caption:
          "Digests the parties published, keyed to this order. They show that a story has not changed; they are not evidence that a file was delivered or was any good.",
      },
    );
  }

  /**
   * The number an operator has to look at: what the books owe against what the wallet holds.
   * A shortfall is shown as an error rather than as a row in a table, because it is one.
   */
  function treasuryCard(books: Treasury): HTMLElement {
    const shortfall = books.shortfallXmr !== null && books.shortfallXmr !== "0";
    return el(
      "div",
      { class: "card" },
      el("h3", { class: "tight" }, "Treasury"),
      table(
        ["Owed to accounts", "Held for orders", "Fees earned", "Uncredited top-ups", "Liabilities", "In the wallet"],
        [
          [
            formatPrice(books.userAvailableXmr),
            formatPrice(books.userHeldXmr),
            formatPrice(books.platformEarnedXmr),
            formatPrice(books.uncreditedTopUpsXmr),
            formatPrice(books.liabilitiesXmr),
            books.walletXmr === null ? "no wallet tier" : formatPrice(books.walletXmr),
          ],
        ],
        { caption: "Reconciled against the wallet on every scan" },
      ),
      shortfall
        ? notice(
            `The books owe ${formatPrice(books.shortfallXmr as string)} more than the wallet holds. Stop payouts and reconcile before anything else.`,
            "error",
          )
        : null,
    );
  }

  /**
   * One waiting payout. A row in `sending` has been taken by the worker: nothing on this
   * server can move it back, so when it has been gone too long the only honest options are
   * the two an operator can verify in their own wallet history (ADR-0073).
   */
  function payoutCard(payout: Payouts["withdrawals"][number]): HTMLElement {
    const age =
      payout.sendingForMinutes === null
        ? `requested ${payout.requestedOn}`
        : `taken by the worker ${payout.sendingForMinutes} min ago`;
    return el(
      "div",
      { class: "card" },
      el("strong", {}, `${formatPrice(payout.amountXmr)} to @${payout.username}`),
      el("div", { class: "mono muted" }, `${payout.addressHint} · ${payout.status} · ${age}`),
      // Two administrators for a large payout (ADR-0076): the count has to be on the screen,
      // or the second signature looks like a bug rather than a rule.
      payout.status === "approval_required" && payout.approvalsRequired > 1
        ? notice(
            `This amount needs two different administrators. ${payout.approvals} of ${payout.approvalsRequired} have approved it so far — approving again from this account changes nothing.`,
            "info",
          )
        : null,
      payout.stuck
        ? notice(
            "The worker took this payout and never reported back. Check the payout wallet's own history for the transfer, then say which of the two things happened — nothing here can retry it, because a retry on an uncertain outcome pays twice.",
            "error",
          )
        : null,
      el(
        "div",
        { class: "row" },
        ...(payout.status === "approval_required"
          ? [decidePayoutButton(payout.id, "approved", "Approve"), decidePayoutButton(payout.id, "rejected", "Refuse")]
          : []),
        ...(payout.status === "sending"
          ? [resolvePayoutSentButton(payout.id), resolvePayoutFailedButton(payout.id)]
          : []),
      ),
    );
  }

  function decidePayoutButton(id: string, decision: string, label: string): HTMLElement {
    const button = el("button", { type: "button", class: decision === "approved" ? "primary" : "danger" }, label);
    button.addEventListener("click", () => {
      act(api(`/api/moderation/withdrawals/${id}/decide`, { method: "POST", body: { decision } }));
    });
    return button;
  }

  /** Marking a payout sent requires its transaction id: the receipt, not the operator's word. */
  function resolvePayoutSentButton(id: string): HTMLElement {
    const button = el("button", { type: "button" }, "It was sent");
    button.addEventListener("click", () => {
      void formDialog({
        title: "Mark this payout sent",
        body: "Only if you have found the transfer in the payout wallet. The transaction id becomes the payee's receipt.",
        fields: [
          { name: "txid", label: "Transaction id", kind: "text", required: true, maxlength: 64 },
          { name: "networkFeeXmr", label: "Network fee in XMR (optional)", kind: "text" },
        ],
        confirmLabel: "Mark sent",
      }).then((answer) => {
        if (!answer) return;
        act(
          api(`/api/moderation/withdrawals/${id}/resolve`, {
            method: "POST",
            body: {
              outcome: "sent",
              txid: (answer.txid ?? "").trim(),
              networkFeeXmr: (answer.networkFeeXmr ?? "").trim() || "0",
            },
          }),
        );
      });
    });
    return button;
  }

  function resolvePayoutFailedButton(id: string): HTMLElement {
    const button = el("button", { type: "button", class: "danger" }, "It never left");
    button.addEventListener("click", () => {
      void formDialog({
        title: "Mark this payout failed",
        body: "The money goes back to the owner's spendable balance. Only if you are sure no transfer left the wallet — this is the decision that pays twice if it is wrong.",
        fields: [],
        confirmLabel: "Return the money",
        danger: true,
      }).then((answer) => {
        if (answer) act(api(`/api/moderation/withdrawals/${id}/resolve`, { method: "POST", body: { outcome: "failed" } }));
      });
    });
    return button;
  }

  /** The one order transition staff can make: settle a dispute either way. Audited server-side. */
  function settleButton(orderId: string, status: "cancelled" | "completed", label: string): HTMLElement {
    const button = el("button", { type: "button", class: status === "cancelled" ? "danger" : "" }, label);
    button.addEventListener("click", () => {
      void formDialog({
        title: label,
        body: status === "cancelled" ? "The order ends without completion; the buyer's side of the dispute is upheld." : "The order is completed; the seller's side is upheld and the buyer may still review it.",
        fields: [],
        confirmLabel: "Settle",
        danger: status === "cancelled",
      }).then((answer) => {
        if (answer) act(api(`/api/market/orders/${orderId}/status`, { method: "POST", body: { status } }));
      });
    });
    return button;
  }

  function act(promise: Promise<unknown>) {
    promise.then(() => void load()).catch((error: Error) => body.append(notice(error.message, "error")));
  }

  /** One dialog for every moderator action that takes a note; the note is optional everywhere. */
  function withNote(title: string, label: string, danger: boolean, then: (note: string) => void) {
    void formDialog({
      title,
      fields: [{ name: "note", label, kind: "textarea", maxlength: 1000 }],
      confirmLabel: "Confirm",
      danger,
    }).then((answer) => {
      if (answer) then(answer.note ?? "");
    });
  }

  function decideButton(id: string, decision: string, label: string): HTMLElement {
    const button = el("button", { type: "button", class: decision === "approved" ? "primary" : "" }, label);
    button.addEventListener("click", () => {
      withNote(`${label} application`, "Note for the applicant (optional)", decision === "rejected", (note) =>
        act(api(`/api/moderation/seller-applications/${id}/decide`, { method: "POST", body: { decision, note } })),
      );
    });
    return button;
  }

  function resolveButton(id: string, outcome: string, label: string): HTMLElement {
    const button = el("button", { type: "button" }, label);
    button.addEventListener("click", () => {
      act(api(`/api/moderation/reports/${id}/resolve`, { method: "POST", body: { outcome, note: "" } }));
    });
    return button;
  }

  function removeListingButton(listingId: string): HTMLElement {
    const button = el("button", { type: "button", class: "danger" }, "Remove listing");
    button.addEventListener("click", () => {
      withNote("Remove listing", "Reason (optional, kept in the audit log)", true, (note) =>
        act(api(`/api/moderation/listings/${listingId}/remove`, { method: "POST", body: { note } })),
      );
    });
    return button;
  }

  function suspendButton(username: string): HTMLElement {
    const button = el("button", { type: "button", class: "danger" }, "Suspend account");
    button.addEventListener("click", () => {
      withNote(`Suspend @${username}`, "Reason (optional, shown to the account)", true, (reason) =>
        act(api(`/api/moderation/users/${encodeURIComponent(username)}/status`, { method: "POST", body: { status: "suspended", reason } })),
      );
    });
    return button;
  }
}
