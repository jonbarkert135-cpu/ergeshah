import { api } from "../api.ts";
import { clear, el, emptyState, errorState, notice, skeleton } from "../ui.ts";

interface Queue {
  reports: Array<{
    id: string;
    targetType: string;
    targetId: string;
    reason: string;
    details: string;
    reporter: string;
    reportedOn: string;
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
      body.append(
        el(
          "div",
          { class: "card" },
          el("strong", {}, `${report.reason} — ${report.targetType}`),
          el("div", { class: "mono muted" }, report.targetId),
          report.details ? el("p", {}, report.details) : null,
          el("div", { class: "muted mono" }, `by ${report.reporter} on ${report.reportedOn}`),
          el(
            "div",
            { class: "row" },
            resolveButton(report.id, "actioned", "Mark actioned"),
            resolveButton(report.id, "dismissed", "Dismiss"),
            report.targetType === "listing"
              ? removeListingButton(report.targetId)
              : suspendButton(report.targetId),
          ),
        ),
      );
    }

    body.append(el("h2", {}, "Audit log"));
    const table = el(
      "table",
      {},
      el("tr", {}, el("th", {}, "When"), el("th", {}, "Actor"), el("th", {}, "Action"), el("th", {}, "Subject"), el("th", {}, "Note")),
    );
    for (const entry of audit.entries) {
      table.append(
        el(
          "tr",
          {},
          el("td", { class: "mono" }, new Date(entry.at).toLocaleString()),
          el("td", { class: "mono" }, entry.actor ?? "—"),
          el("td", {}, entry.action),
          el("td", { class: "mono" }, entry.subjectId.slice(0, 12)),
          el("td", {}, entry.note),
        ),
      );
    }
    body.append(table);
  }

  function act(promise: Promise<unknown>) {
    promise.then(() => void load()).catch((error: Error) => body.append(notice(error.message, "error")));
  }

  function decideButton(id: string, decision: string, label: string): HTMLElement {
    const button = el("button", decision === "approved" ? { class: "primary" } : {}, label);
    button.addEventListener("click", () => {
      const note = window.prompt(`Note for the applicant (${decision})`) ?? "";
      act(
        api(`/api/moderation/seller-applications/${id}/decide`, {
          method: "POST",
          body: { decision, note },
        }),
      );
    });
    return button;
  }

  function resolveButton(id: string, outcome: string, label: string): HTMLElement {
    const button = el("button", {}, label);
    button.addEventListener("click", () => {
      act(api(`/api/moderation/reports/${id}/resolve`, { method: "POST", body: { outcome, note: "" } }));
    });
    return button;
  }

  function removeListingButton(listingId: string): HTMLElement {
    const button = el("button", { class: "danger" }, "Remove listing");
    button.addEventListener("click", () => {
      const note = window.prompt("Reason for removal") ?? "";
      act(api(`/api/moderation/listings/${listingId}/remove`, { method: "POST", body: { note } }));
    });
    return button;
  }

  function suspendButton(username: string): HTMLElement {
    const button = el("button", { class: "danger" }, "Suspend account");
    button.addEventListener("click", () => {
      const reason = window.prompt(`Reason for suspending ${username}`) ?? "";
      act(
        api(`/api/moderation/users/${encodeURIComponent(username)}/status`, {
          method: "POST",
          body: { status: "suspended", reason },
        }),
      );
    });
    return button;
  }
}
