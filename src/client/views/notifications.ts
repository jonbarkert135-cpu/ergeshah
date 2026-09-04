import { api } from "../api.ts";
import { clear, el, emptyState, errorState, focusAnchor, say, skeleton, statusRegion, toast, withBusy } from "../ui.ts";

interface Notification {
  id: string;
  kind: string;
  subjectType: string | null;
  subjectId: string | null;
  detail: string | null;
  at: number;
  read: boolean;
}

interface Inbox {
  notifications: Notification[];
  unread: number;
  nextCursor: string | null;
}

/**
 * What each kind means in words. The server sends a kind and a status word, never a
 * sentence: the prose lives here, in the client, where it can be translated and where it
 * cannot become a place the server stores text about a message.
 */
function describe(item: Notification): string {
  switch (item.kind) {
    case "message":
      return "New encrypted messages are waiting. Open Messages to read them.";
    case "order":
      return `An order of yours is now ${item.detail ?? "updated"}.`;
    case "dispute":
      return "An order of yours has been disputed. A moderator can see the reason.";
    case "review":
      return "One of your listings received a review.";
    case "seller_application":
      return `Your seller application was ${item.detail ?? "decided"}.`;
    case "moderation":
      return `A moderator ${item.detail ?? "acted on"} your ${item.subjectType ?? "account"}.`;
    default:
      return "Something concerning your account changed.";
  }
}

function target(item: Notification): string | null {
  if (item.kind === "message") return "#/chat";
  if (item.subjectType === "order") return "#/orders";
  if (item.subjectType === "listing") return "#/market";
  return null;
}

export function renderNotifications(root: HTMLElement): void {
  clear(root);
  const list = el("div", { class: "stack" });
  const status = statusRegion();
  const markAll = el("button", { type: "button", class: "ghost" }, "Mark all as read");
  const more = el("button", { type: "button", class: "ghost" }, "Show more");
  const moreRow = el("div", { class: "row center" }, more);
  moreRow.hidden = true;
  let cursor: string | null = null;

  markAll.addEventListener("click", () => {
    void withBusy(markAll, async () => {
      await api("/api/notifications/read", { method: "POST", body: { all: true } });
      toast("Inbox marked as read");
      await load();
    });
  });
  more.addEventListener("click", () => {
    void withBusy(more, () => load(cursor));
  });

  root.append(
    el("h1", {}, "Notifications"),
    el(
      "p",
      { class: "lede" },
      "What happened while you were away. A notification about a message says only that something arrived — never who sent it or what it says; that stays end-to-end encrypted.",
    ),
    el("div", { class: "row toolbar" }, markAll),
    status,
    list,
    moreRow,
  );
  void load();

  async function load(after: string | null = null): Promise<void> {
    const restore = focusAnchor(list);
    clear(status);
    moreRow.hidden = true;
    if (!after) clear(list).append(skeleton("line", 4));
    try {
      const query = after ? `?cursor=${encodeURIComponent(after)}` : "";
      const inbox = await api<Inbox>(`/api/notifications${query}`);
      cursor = inbox.nextCursor;
      moreRow.hidden = inbox.nextCursor === null;
      if (!after) clear(list);
      if (inbox.notifications.length === 0 && !after) {
        status.append(
          emptyState("Nothing to report", "Orders, reviews and moderation decisions show up here."),
        );
        return;
      }
      for (const item of inbox.notifications) list.append(row(item));
      say(after ? `${inbox.notifications.length} more` : `${inbox.notifications.length} notifications, ${inbox.unread} unread`);
      restore();
    } catch {
      clear(list).append(errorState("The inbox did not load.", () => void load(after)));
    }
  }

  function row(item: Notification): HTMLElement {
    const where = target(item);
    return el(
      "div",
      { class: item.read ? "card" : "card unread" },
      el("p", {}, describe(item)),
      el(
        "p",
        { class: "meta" },
        new Date(item.at).toLocaleString(),
        where ? " · " : null,
        where ? el("a", { href: where }, "Open") : null,
      ),
    );
  }
}

/** The unread count for the navigation. Failures are silent: a badge is not worth an error. */
export async function unreadCount(): Promise<number> {
  try {
    const inbox = await api<Inbox>("/api/notifications?limit=1");
    return inbox.unread;
  } catch {
    return 0;
  }
}
