import { api } from "../api.ts";
import { clear, el, money, notice } from "../ui.ts";
import { receiveMessages, sendDeliveryKey } from "../messaging.ts";
import { persistVault, state } from "../state.ts";
import { decryptFile, encryptFile, MAX_FILE_BYTES } from "../../shared/crypto/file.ts";
import { fromBase64Url, toBase64Url } from "../../shared/encoding.ts";

interface Order {
  id: string;
  listingId: string;
  title: string;
  status: string;
  priceMinor: number;
  currency: string;
  channel: string;
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
    // "Delivered" is not a button here: for the seller it is the upload below, which sets
    // the status itself, so an order can never claim a delivery that does not exist.
    { status: "disputed", label: "Open dispute", role: "buyer" },
  ],
  delivered: [
    { status: "completed", label: "Confirm & complete", role: "buyer" },
    { status: "disputed", label: "Open dispute", role: "buyer" },
  ],
};

/** Hands bytes to the browser's own download machinery: no library, no server round-trip. */
function save(bytes: Uint8Array, name: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  const link = el("a", { href: url, download: name });
  link.click();
  URL.revokeObjectURL(url);
}

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
  root.append(
    el("h1", {}, "Orders"),
    el(
      "p",
      { class: "lede" },
      "Files are encrypted in the browser before upload and the key travels through the order's encrypted channel. Save a delivery before you complete the order: completing it deletes the copy on the server.",
    ),
    toggle,
    body,
  );
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
    // Delivery keys arrive as ordinary encrypted messages, so collect any waiting ones
    // before drawing: otherwise a buyer would see "delivered" with no way to open it.
    await receiveMessages().catch(() => 0);
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
      if (order.status === "accepted" && role === "seller") actions.append(uploadControl(order));
      if (role === "seller") {
        const shipment = state.vault?.shipments?.[order.id];
        if (shipment) actions.append(shippingControl(shipment.text));
      }
      if (order.status === "delivered" && role === "buyer") actions.append(downloadControl(order));
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

  /** Seller side: pick a file, encrypt it here, upload ciphertext, send the key. */
  function uploadControl(order: Order): HTMLElement {
    const picker = el("input", { type: "file", style: "display:none" }) as HTMLInputElement;
    const button = el("button", { class: "primary" }, "Encrypt & deliver");
    button.addEventListener("click", () => picker.click());
    picker.addEventListener("change", () => {
      const file = picker.files?.[0];
      if (!file) return;
      if (file.size > MAX_FILE_BYTES) {
        body.append(notice(`File is larger than ${MAX_FILE_BYTES / (1024 * 1024)} MB.`, "error"));
        return;
      }
      button.disabled = true;
      button.textContent = "Encrypting…";
      void deliver(order, file)
        .then(() => void load())
        .catch((error: Error) => {
          button.disabled = false;
          button.textContent = "Encrypt & deliver";
          body.append(notice(error.message, "error"));
        });
    });
    return el("div", { class: "row" }, button, picker);
  }

  async function deliver(order: Order, file: File): Promise<void> {
    const plaintext = new Uint8Array(await file.arrayBuffer());
    const { key, nonce, ciphertext } = encryptFile(order.id, plaintext);
    await api(`/api/market/orders/${order.id}/delivery`, {
      method: "POST",
      body: { ciphertext: toBase64Url(ciphertext) },
    });
    // Upload first, key second: a key without a file is a confusing message, a file
    // without a key is an unopenable blob that expires on its own.
    await sendDeliveryKey(order.counterparty, order.channel, order.id, {
      key: toBase64Url(key),
      nonce: toBase64Url(nonce),
      name: file.name.slice(0, 120),
      at: Date.now(),
    });
  }

  /**
   * Seller side: the buyer's address, which exists only here and in the buyer's browser.
   * It is shown on demand rather than printed into the table, because a delivery address
   * on screen is a delivery address someone can read over your shoulder.
   */
  function shippingControl(details: string): HTMLElement {
    const button = el("button", { class: "ghost" }, "Delivery details");
    const shown = el("div", { class: "mono" });
    button.addEventListener("click", () => {
      if (shown.textContent) clear(shown);
      else shown.append(document.createTextNode(details));
    });
    return el("div", {}, button, shown);
  }

  /** Buyer side: fetch ciphertext, decrypt in the page, save, then have the server forget it. */
  function downloadControl(order: Order): HTMLElement {
    const held = state.vault?.deliveries?.[order.id];
    if (!held) return el("span", { class: "muted mono" }, "waiting for key…");
    const button = el("button", { class: "primary" }, `Download ${held.name}`);
    button.addEventListener("click", () => {
      button.disabled = true;
      void download(order)
        .catch((error: Error) => body.append(notice(error.message, "error")))
        .finally(() => {
          button.disabled = false;
        });
    });
    return button;
  }

  async function download(order: Order): Promise<void> {
    const held = state.vault!.deliveries![order.id]!;
    const { ciphertext } = await api<{ ciphertext: string }>(
      `/api/market/orders/${order.id}/delivery`,
    );
    const plaintext = decryptFile(
      order.id,
      fromBase64Url(held.key),
      fromBase64Url(held.nonce),
      fromBase64Url(ciphertext),
    );
    save(plaintext, held.name);
    // The buyer has the file; the server has no reason to keep a copy of the ciphertext.
    await api(`/api/market/orders/${order.id}/delivery`, { method: "DELETE" });
    await persistVault();
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
