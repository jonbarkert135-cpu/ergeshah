import { api } from "../api.ts";
import { clear, el, money, notice } from "../ui.ts";

interface Order {
  id: string;
  listingId: string;
  title: string;
  status: string;
  priceMinor: number;
  currency: string;
  counterparty: string;
  placedOn: string;
}

const NEXT_STEPS: Record<string, Array<{ status: string; label: string; role: "buyer" | "seller" }>> = {
  placed: [
    { status: "accepted", label: "Accept", role: "seller" },
    { status: "cancelled", label: "Cancel", role: "buyer" },
    { status: "cancelled", label: "Cancel", role: "seller" },
  ],
  accepted: [
    { status: "delivered", label: "Mark delivered", role: "seller" },
    { status: "disputed", label: "Open dispute", role: "buyer" },
  ],
  delivered: [
    { status: "completed", label: "Confirm & complete", role: "buyer" },
    { status: "disputed", label: "Open dispute", role: "buyer" },
  ],
};

export function renderOrders(root: HTMLElement): void {
  clear(root);
  let role: "buyer" | "seller" = "buyer";
  const body = el("div", {});
  const toggle = el(
    "div",
    { class: "row" },
    el("button", { onclick: () => switchRole("buyer"), "aria-current": "page" }, "As buyer"),
    el("button", { onclick: () => switchRole("seller") }, "As seller"),
  );
  root.append(el("h1", {}, "Orders"), toggle, body);
  void load();

  function switchRole(next: "buyer" | "seller") {
    role = next;
    const [buyerButton, sellerButton] = Array.from(toggle.children) as HTMLElement[];
    buyerButton?.toggleAttribute("aria-current", next === "buyer");
    sellerButton?.toggleAttribute("aria-current", next === "seller");
    void load();
  }

  async function load() {
    clear(body).append(el("p", { class: "muted" }, "Loading…"));
    const { orders } = await api<{ orders: Order[] }>(`/api/market/orders?role=${role}`);
    clear(body);
    if (orders.length === 0) {
      body.append(el("p", { class: "muted" }, "No orders yet."));
      return;
    }
    const table = el(
      "table",
      {},
      el(
        "tr",
        {},
        el("th", {}, "Listing"),
        el("th", {}, role === "buyer" ? "Seller" : "Buyer"),
        el("th", {}, "Price"),
        el("th", {}, "Placed"),
        el("th", {}, "Status"),
        el("th", {}, "Actions"),
      ),
    );
    for (const order of orders) {
      const actions = el("div", { class: "row" });
      for (const step of NEXT_STEPS[order.status] ?? []) {
        if (step.role !== role) continue;
        const button = el("button", {}, step.label);
        button.addEventListener("click", () => {
          button.disabled = true;
          void api(`/api/market/orders/${order.id}/status`, {
            method: "POST",
            body: { status: step.status },
          })
            .then(() => void load())
            .catch((error: Error) => body.append(notice(error.message, "error")));
        });
        actions.append(button);
      }
      if (order.status === "completed" && role === "buyer") actions.append(reviewButton(order));
      table.append(
        el(
          "tr",
          {},
          el("td", {}, order.title),
          el("td", { class: "mono" }, order.counterparty),
          el("td", { class: "price" }, money(order.priceMinor, order.currency)),
          el("td", { class: "mono" }, order.placedOn),
          el("td", {}, el("span", { class: "tag" }, order.status)),
          el("td", {}, actions),
        ),
      );
    }
    body.append(table);
  }

  function reviewButton(order: Order): HTMLElement {
    const button = el("button", { class: "ghost" }, "Leave review");
    button.addEventListener("click", () => {
      const rating = Number(window.prompt("Rating 1–5")?.trim());
      if (!Number.isInteger(rating) || rating < 1 || rating > 5) return;
      const text = window.prompt("Review (optional)") ?? "";
      void api(`/api/market/orders/${order.id}/review`, {
        method: "POST",
        body: { rating, body: text },
      })
        .then(() => void load())
        .catch((error: Error) => body.append(notice(error.message, "error")));
    });
    return button;
  }
}
