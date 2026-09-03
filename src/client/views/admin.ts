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
    try {
      // Two independent reads: in parallel, because a moderator waiting twice for one
      // screen is a latency bug that nobody reports and everybody feels.
      [queue, audit] = await Promise.all([
        api<Queue>("/api/moderation/queue"),
        api<{
          entries: Array<{ actor: string | null; action: string; subjectId: string; note: string; at: string }>;
        }>("/api/moderation/audit"),
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
