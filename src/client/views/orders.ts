import { api } from "../api.ts";
import { clear, el, emptyState, errorState, formDialog, notice, price as formatPrice, skeleton, table, toast } from "../ui.ts";
import { receiveMessages, sendDeliveryKey } from "../messaging.ts";
import { persistVault, state } from "../state.ts";
import { decryptFile, encryptFile, MAX_FILE_BYTES } from "../../shared/crypto/file.ts";
import { stripImageMetadata } from "../../shared/media.ts";
import { fromBase64Url, toBase64Url } from "../../shared/encoding.ts";
import { safeFileName } from "../../shared/uploads.ts";

interface Order {
  id: string;
  listingId: string;
  title: string;
  kind: string;
  status: string;
  priceXmr: string;
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
    // "Delivered" is not a button here: for the seller it is the delivery control below,
    // which sets the status itself, so an order can never claim a delivery that does not exist.
    { status: "disputed", label: "Open dispute", role: "buyer" },
  ],
  delivered: [
    { status: "completed", label: "Confirm & complete", role: "buyer" },
    { status: "disputed", label: "Open dispute", role: "buyer" },
  ],
};

interface Evidence {
  id: string;
  by: "buyer" | "seller";
  kind: string;
  digest: string;
  on: string;
  beforeDispute: boolean;
}

const EVIDENCE_KINDS: Array<[value: string, label: string]> = [
  ["delivery", "The delivered file"],
  ["attachment", "A file sent in the chat"],
  ["screenshot", "A screenshot"],
  ["other", "Something else"],
];

/**
 * The digest this platform commits to: `HMAC-SHA256(order id, file bytes)`, computed here and
 * never anywhere else (ADR-0074).
 *
 * Keyed with the order id rather than a bare SHA-256 on purpose. A bare hash of a file that
 * exists elsewhere is recognisable to anybody holding that file, so a table of bare hashes
 * would say "these two people exchanged this known file" to any stranger who guessed right.
 * The order id is unguessable and known to exactly the people who are allowed to check: the
 * two parties and, in a dispute, the moderator.
 */
async function orderDigest(orderId: string, bytes: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(orderId),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, bytes as BufferSource);
  return [...new Uint8Array(mac)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Hands bytes to the browser's own download machinery: no library, no server round-trip. */
function save(bytes: Uint8Array, name: string): void {
  // `application/octet-stream` and a sanitised name: the bytes came from a seller, so they
  // are never given a type the browser would render, and never a name that could be a path
  // (point 49). The blob is only ever downloaded, never navigated to.
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
  const link = el("a", { href: url, download: safeFileName(name) });
  link.click();
  URL.revokeObjectURL(url);
}

export function renderOrders(root: HTMLElement): void {
  clear(root);
  let role: "buyer" | "seller" = "buyer";
  const body = el("div", {});
  const buyerButton = el("button", { type: "button", "aria-pressed": "true", onclick: () => switchRole("buyer") }, "As buyer");
  const sellerButton = el("button", { type: "button", "aria-pressed": "false", onclick: () => switchRole("seller") }, "As seller");
  root.append(
    el("h1", {}, "Orders"),
    el(
      "p",
      { class: "lede" },
      "Files are encrypted in the browser before upload and the key travels through the order's encrypted channel. Save a delivery before you complete the order: completing it deletes the copy on the server.",
    ),
    el("div", { class: "row", role: "group", "aria-label": "Show orders" }, buyerButton, sellerButton),
    body,
  );
  void load();

  function switchRole(next: "buyer" | "seller") {
    role = next;
    buyerButton.setAttribute("aria-pressed", String(next === "buyer"));
    sellerButton.setAttribute("aria-pressed", String(next === "seller"));
    void load();
  }

  async function load() {
    clear(body).append(skeleton("line", 4));
    // Delivery keys arrive as ordinary encrypted messages, so collect any waiting ones
    // before drawing: otherwise a buyer would see "delivered" with no way to open it.
    await receiveMessages().catch(() => 0);
    let orders: Order[];
    try {
      ({ orders } = await api<{ orders: Order[] }>(`/api/market/orders?role=${role}`));
    } catch {
      clear(body).append(errorState("Your orders did not load.", () => void load()));
      return;
    }
    clear(body);
    if (orders.length === 0) {
      body.append(
        role === "buyer"
          ? emptyState("No orders yet", "Anything you order from the marketplace appears here, with its encrypted channel.")
          : emptyState("Nothing sold yet", "Orders placed against your listings appear here, newest first."),
      );
      return;
    }
    body.append(
      table(
        ["Listing", role === "buyer" ? "Seller" : "Buyer", "Price", "Placed", "Status", "Actions"],
        orders.map((order) => [
          order.title,
          el("span", { class: "mono" }, order.counterparty),
          el("span", { class: "price" }, formatPrice(order.priceXmr)),
          el("span", { class: "mono" }, order.placedOn),
          el("span", { class: "tag" }, order.status),
          actionsFor(order),
        ]),
        { caption: `Orders as ${role}` },
      ),
    );
  }

  function actionsFor(order: Order): HTMLElement {
    const actions = el("div", { class: "row" });
    for (const step of NEXT_STEPS[order.status] ?? []) {
      if (step.role !== role) continue;
      const button = el("button", { type: "button" }, step.label);
      button.addEventListener("click", () => void transition(order, step.status, button));
      actions.append(button);
    }
    if (order.status === "completed" && role === "buyer") actions.append(reviewButton(order));
    if (order.status === "accepted" && role === "seller") actions.append(deliveryControls(order));
    if (role === "seller") {
      const shipment = state.vault?.shipments?.[order.id];
      if (shipment) actions.append(shippingControl(shipment.text));
    }
    if (order.status === "delivered" && role === "buyer") actions.append(collectControl(order));
    // Evidence is worth committing while there is still something to argue about, and it is
    // worth most *before* an argument starts — so it is offered on a live order, to both
    // sides, and not only once a dispute is open.
    if (["accepted", "delivered", "disputed"].includes(order.status)) {
      actions.append(evidenceControls(order));
    }
    return actions;
  }

  /**
   * Committing to a file without uploading it, and checking a file against what the other
   * side committed to (ADR-0074).
   *
   * Nothing here sends bytes anywhere: the file is read in this browser, reduced to a keyed
   * digest, and the digest is what travels. The server cannot reconstruct the file from it,
   * and a stranger who does not know the order id cannot recognise the file either.
   */
  function evidenceControls(order: Order): HTMLElement {
    const commitPicker = el("input", { type: "file", class: "hidden", "aria-label": "File to commit" }) as HTMLInputElement;
    const checkPicker = el("input", { type: "file", class: "hidden", "aria-label": "File to check" }) as HTMLInputElement;
    const commit = el("button", { type: "button" }, "Commit a file digest");
    const check = el("button", { type: "button" }, "Check a file");

    commit.addEventListener("click", () => commitPicker.click());
    commitPicker.addEventListener("change", () => {
      const chosen = commitPicker.files?.[0];
      if (!chosen) return;
      void formDialog({
        title: "Commit to this file",
        body: `Nothing is uploaded. ${chosen.name} is reduced to a digest in this browser, and the digest is recorded with today's date — so neither side can later claim a different file was the one exchanged. The other party has the file and can check it themselves.`,
        fields: [{ name: "kind", label: "What is it?", kind: "select", options: EVIDENCE_KINDS }],
        confirmLabel: "Commit digest",
      }).then((answer) => {
        if (!answer) return;
        void run(commit, "Hashing…", async () => {
          const digest = await orderDigest(order.id, new Uint8Array(await chosen.arrayBuffer()));
          await api(`/api/market/orders/${order.id}/evidence`, {
            method: "POST",
            body: { digest, kind: answer.kind ?? "other" },
          });
          toast("Digest committed");
        });
      });
    });

    check.addEventListener("click", () => checkPicker.click());
    checkPicker.addEventListener("change", () => {
      const chosen = checkPicker.files?.[0];
      if (!chosen) return;
      void run(check, "Hashing…", async () => {
        const digest = await orderDigest(order.id, new Uint8Array(await chosen.arrayBuffer()));
        const committed = await api<{ evidence: Evidence[] }>(`/api/market/orders/${order.id}/evidence`);
        const match = committed.evidence.find((entry) => entry.digest === digest);
        body.append(
          match
            ? notice(
                `This file is the one the ${match.by} committed to on ${match.on}${match.beforeDispute ? ", before the dispute" : ", after the dispute was opened"}.`,
                "info",
              )
            : notice(
                committed.evidence.length === 0
                  ? "Nobody has committed a digest on this order yet, so there is nothing to compare this file with."
                  : "This file matches none of the digests committed on this order. Either it is not the file they meant, or it has been changed since.",
                "error",
              ),
        );
      });
    });
    return el("span", { class: "row" }, commit, commitPicker, check, checkPicker);
  }

  async function transition(order: Order, status: string, button: HTMLButtonElement) {
    let reason: string | undefined;
    if (status === "disputed") {
      const answer = await formDialog({
        title: "Open a dispute",
        body: "A moderator will read this, together with the order's public facts. They cannot read your conversation, so say here what went wrong.",
        fields: [{ name: "reason", label: "What happened?", kind: "textarea", required: true, maxlength: 2000, hint: "At least 10 characters." }],
        confirmLabel: "Open dispute",
        danger: true,
      });
      if (!answer) return;
      reason = answer.reason;
    }
    button.disabled = true;
    try {
      await api(`/api/market/orders/${order.id}/status`, { method: "POST", body: { status, reason } });
      await load();
    } catch (error) {
      button.disabled = false;
      body.append(notice((error as Error).message, "error"));
    }
  }

  /**
   * Seller side. Goods are not all files (point 45): a file is encrypted and uploaded; a
   * licence key, credentials or a link are typed here and take the same encrypted path, as
   * text; a service or a parcel is marked delivered with nothing stored at all. The server
   * cannot tell the first two apart, and learns nothing about any of them.
   */
  function deliveryControls(order: Order): HTMLElement {
    const picker = el("input", { type: "file", class: "hidden", "aria-label": "File to deliver" }) as HTMLInputElement;
    const file = el("button", { type: "button" }, "Encrypt & deliver file");
    const text = el("button", { type: "button" }, "Deliver text");
    const manual = el("button", { type: "button" }, "Mark delivered");

    file.addEventListener("click", () => picker.click());
    picker.addEventListener("change", () => {
      const chosen = picker.files?.[0];
      if (!chosen) return;
      if (chosen.size > MAX_FILE_BYTES) {
        body.append(notice(`File is larger than ${MAX_FILE_BYTES / (1024 * 1024)} MB.`, "error"));
        return;
      }
      void run(file, "Encrypting…", async () => {
        await deliver(order, new Uint8Array(await chosen.arrayBuffer()), chosen.name.slice(0, 120), "file");
      });
    });
    text.addEventListener("click", () => {
      void formDialog({
        title: "Deliver as text",
        body: "A licence key, credentials, a download link, instructions. Encrypted in this browser like a file; the server stores ciphertext it cannot read.",
        fields: [{ name: "content", label: "Content", kind: "textarea", required: true, maxlength: 20_000 }],
        confirmLabel: "Encrypt & deliver",
      }).then((answer) => {
        if (!answer) return;
        void run(text, "Encrypting…", () =>
          deliver(order, new TextEncoder().encode(answer.content), "delivery.txt", "text"),
        );
      });
    });
    manual.addEventListener("click", () => {
      void formDialog({
        title: "Mark as delivered",
        body: "For a service performed or goods handed over outside the platform. Nothing is stored; the buyer is asked to confirm.",
        fields: [],
        confirmLabel: "Mark delivered",
      }).then((answer) => {
        if (!answer) return;
        void run(manual, "Saving…", () =>
          api(`/api/market/orders/${order.id}/delivery`, { method: "POST", body: { manual: true } }),
        );
      });
    });
    // Lead with the control that fits the listing; every kind can still use every path.
    const controls = order.kind === "digital_good" ? [file, text, manual] : [manual, text, file];
    controls[0]!.classList.add("primary");
    controls[2]!.classList.add("ghost");
    return el("div", { class: "row" }, ...controls, picker);
  }

  async function run(button: HTMLButtonElement, busyLabel: string, action: () => Promise<unknown>) {
    const label = button.textContent;
    button.disabled = true;
    button.textContent = busyLabel;
    try {
      await action();
      await load();
    } catch (error) {
      button.disabled = false;
      button.textContent = label;
      body.append(notice((error as Error).message, "error"));
    }
  }

  async function deliver(order: Order, plaintext: Uint8Array, name: string, kind: "file" | "text"): Promise<void> {
    // A delivered photograph reaches the buyer with whatever the camera wrote into it, and
    // encryption does not help there: the buyer holds the key (src/shared/media.ts).
    const { key, nonce, ciphertext } = encryptFile(order.id, stripImageMetadata(plaintext));
    await api(`/api/market/orders/${order.id}/delivery`, {
      method: "POST",
      body: { ciphertext: toBase64Url(ciphertext) },
    });
    // Upload first, key second: a key without a file is a confusing message, a file
    // without a key is an unopenable blob that expires on its own.
    await sendDeliveryKey(order.counterparty, order.channel, order.id, {
      key: toBase64Url(key),
      nonce: toBase64Url(nonce),
      name,
      kind,
      at: Date.now(),
    });
  }

  /**
   * Seller side: the buyer's address, which exists only here and in the buyer's browser.
   * It is shown on demand rather than printed into the table, because a delivery address
   * on screen is a delivery address someone can read over your shoulder.
   */
  function shippingControl(details: string): HTMLElement {
    const shown = el("div", { class: "mono" });
    const button = el("button", { type: "button", class: "ghost", "aria-expanded": "false" }, "Delivery details");
    button.addEventListener("click", () => {
      const open = shown.textContent !== "";
      clear(shown);
      if (!open) shown.append(document.createTextNode(details));
      button.setAttribute("aria-expanded", String(!open));
    });
    return el("div", {}, button, shown);
  }

  /** Buyer side: a file is decrypted and saved; text is decrypted and shown; a manual delivery is a note. */
  function collectControl(order: Order): HTMLElement {
    const held = state.vault?.deliveries?.[order.id];
    if (!held) {
      return el(
        "span",
        { class: "muted" },
        order.kind === "digital_good"
          ? "waiting for the key…"
          : "Delivered outside the platform. Check the order chat, then confirm.",
      );
    }
    const button = el("button", { type: "button", class: "primary" }, held.kind === "text" ? "Show delivery" : `Download ${safeFileName(held.name)}`);
    button.addEventListener("click", () => {
      button.disabled = true;
      void collect(order)
        .catch((error: Error) => body.append(notice(error.message, "error")))
        .finally(() => {
          button.disabled = false;
        });
    });
    return button;
  }

  async function collect(order: Order): Promise<void> {
    const held = state.vault!.deliveries![order.id]!;
    const { ciphertext } = await api<{ ciphertext: string }>(`/api/market/orders/${order.id}/delivery`);
    const plaintext = decryptFile(order.id, fromBase64Url(held.key), fromBase64Url(held.nonce), fromBase64Url(ciphertext));
    if (held.kind === "text") {
      const content = new TextDecoder().decode(plaintext);
      const shown = el("pre", { class: "block" }, content);
      const copy = el("button", { type: "button" }, "Copy");
      copy.addEventListener("click", () => void navigator.clipboard.writeText(content).then(() => toast("Copied")));
      const done = el("button", { type: "button", class: "primary" }, "Done");
      const dialog = el(
        "dialog",
        { "aria-labelledby": "delivery-title" },
        el("h2", { id: "delivery-title" }, `Delivery for ${order.title}`),
        el("p", { class: "muted" }, "Decrypted in this browser. Save it somewhere safe: the server's copy is deleted once you close this."),
        shown,
        el("div", { class: "actions" }, copy, done),
      ) as HTMLDialogElement;
      done.addEventListener("click", () => dialog.close());
      dialog.addEventListener("close", () => dialog.remove());
      document.body.append(dialog);
      dialog.showModal();
    } else {
      save(plaintext, held.name);
      toast(`Saved ${safeFileName(held.name)}`);
    }
    // The buyer has the goods; the server has no reason to keep a copy of the ciphertext.
    await api(`/api/market/orders/${order.id}/delivery`, { method: "DELETE" });
    await persistVault();
  }

  function reviewButton(order: Order): HTMLElement {
    const button = el("button", { type: "button", class: "ghost" }, "Leave review");
    button.addEventListener("click", () => {
      void formDialog({
        title: `Review ${order.title}`,
        body: "Shown publicly with your username. One review per order; your latest review of a seller is the one that counts.",
        fields: [
          {
            name: "rating",
            label: "Rating",
            kind: "select",
            options: [["5", "5 — excellent"], ["4", "4 — good"], ["3", "3 — fair"], ["2", "2 — poor"], ["1", "1 — bad"]],
          },
          { name: "body", label: "Review (optional)", kind: "textarea", maxlength: 2000 },
        ],
        confirmLabel: "Publish review",
      }).then((answer) => {
        if (!answer) return;
        void api(`/api/market/orders/${order.id}/review`, {
          method: "POST",
          body: { rating: Number(answer.rating), body: answer.body },
        })
          .then(() => void load())
          .catch((error: Error) => body.append(notice(error.message, "error")));
      });
    });
    return button;
  }
}
