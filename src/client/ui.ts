/** Tiny DOM helpers. No framework: less code to audit, nothing to fingerprint. */
export type Child = Node | string | null | undefined | false;

/**
 * Attributes that load or navigate. A `javascript:` URL in one of them is script
 * execution, and `data:` in an anchor is a phishing page on our own origin — so the
 * helper that every view goes through refuses anything outside this list rather than
 * trusting each caller to remember. `blob:` is allowed because downloads are built from
 * a Blob the client just created; `data:image/` because the safety-number QR is an inline
 * SVG image the client generated itself.
 */
const URL_ATTRS = new Set(["href", "src", "action", "formaction", "poster", "xlink:href"]);

export function safeUrl(value: string): boolean {
  const url = value.trim();
  // `//host/path` is protocol-relative — same-origin at a glance, off-site in a browser.
  if (url.startsWith("//")) return false;
  if (url.startsWith("/") || url.startsWith("#") || url.startsWith("?")) return true;
  if (url.startsWith("blob:")) return true;
  if (url.startsWith("data:image/svg+xml;base64,") || url.startsWith("data:image/png;base64,")) return true;
  return /^https?:\/\//i.test(url);
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | ((event: Event) => void)> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === "function") node.addEventListener(key.replace(/^on/, ""), value);
    else if (value === true) node.setAttribute(key, "");
    else if (value !== false) {
      const text = String(value);
      if (URL_ATTRS.has(key.toLowerCase()) && !safeUrl(text)) {
        // Loudly, not silently: a rejected URL here means a bug or an injection attempt,
        // and both should be visible in development rather than degrade into a dead link.
        throw new Error(`refused unsafe URL in ${key}: ${text.slice(0, 32)}`);
      }
      node.setAttribute(key, text);
    }
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    // Always appended as text or nodes — never innerHTML, so user content cannot inject markup.
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: HTMLElement): HTMLElement {
  node.replaceChildren();
  return node;
}

export function notice(message: string, kind: "info" | "error" | "ok" = "info"): HTMLElement {
  return el("div", { class: kind === "info" ? "notice" : `notice ${kind}` }, message);
}

/**
 * The three states every asynchronous surface needs. They exist as functions rather than
 * as advice in a style guide because the alternative — each view improvising — is how an
 * interface ends up with a blank rectangle where a list should be, and a raw error string
 * where an explanation should be.
 */

/** Loading: the shape of what is coming, not a spinner over a void. */
export function skeleton(kind: "line" | "card" = "line", count = 1): HTMLElement {
  const wrap = el("div", { "aria-busy": "true", "aria-label": "Loading" });
  for (let i = 0; i < count; i += 1) {
    wrap.append(el("div", { class: `skeleton ${kind}`, style: kind === "line" ? `width: ${90 - i * 12}%` : "" }));
  }
  return wrap;
}

export function skeletonCards(count = 6): HTMLElement {
  const grid = el("div", { class: "grid", "aria-busy": "true", "aria-label": "Loading" });
  for (let i = 0; i < count; i += 1) grid.append(el("div", { class: "skeleton card" }));
  return grid;
}

/** Empty: says what would be here, and offers the one action that changes that. */
export function emptyState(title: string, explanation: string, action?: HTMLElement): HTMLElement {
  return el(
    "div",
    { class: "state" },
    el("h3", {}, title),
    el("p", {}, explanation),
    action ? el("div", { class: "actions" }, action) : null,
  );
}

/** Error: what failed, and what the reader can do — never a stack trace, never a code. */
export function errorState(explanation: string, retry?: () => void): HTMLElement {
  return el(
    "div",
    { class: "state error" },
    el("h3", {}, "That did not load"),
    el("p", {}, explanation),
    retry ? el("div", { class: "actions" }, el("button", { onclick: retry }, "Try again")) : null,
  );
}

/**
 * A transient message. Used for confirmations that do not deserve a place on the page;
 * anything the reader must act on is a `notice` in the flow instead, where it stays.
 */
export function toast(message: string, kind: "info" | "error" = "info"): void {
  let host = document.querySelector(".toasts");
  if (!host) {
    host = el("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.append(host);
  }
  const node = el("div", { class: kind === "error" ? "toast error" : "toast" }, message);
  host.append(node);
  window.setTimeout(() => node.remove(), kind === "error" ? 6000 : 3500);
}

/**
 * A modal question. Native `<dialog>`: focus trapping, Escape and the backdrop are the
 * platform's job, and every line of that we do not write is a line that cannot be wrong.
 */
export function confirmDialog(options: {
  title: string;
  body: string;
  confirmLabel?: string;
  danger?: boolean;
}): Promise<boolean> {
  return new Promise((resolve) => {
    const cancel = el("button", { class: "ghost" }, "Cancel");
    const confirm = el(
      "button",
      { class: options.danger ? "danger" : "primary" },
      options.confirmLabel ?? "Confirm",
    );
    const dialog = el(
      "dialog",
      {},
      el("h2", {}, options.title),
      el("p", { class: "muted" }, options.body),
      el("div", { class: "actions" }, cancel, confirm),
    ) as HTMLDialogElement;

    const close = (answer: boolean) => {
      dialog.close();
      dialog.remove();
      resolve(answer);
    };
    cancel.addEventListener("click", () => close(false));
    confirm.addEventListener("click", () => close(true));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      close(false);
    });
    document.body.append(dialog);
    dialog.showModal();
    confirm.focus();
  });
}

/**
 * Runs an async action with the button showing it: disabled, spinner, restored afterwards.
 * Without this, every handler reinvents it, and half of them forget the `finally`.
 */
export async function withBusy<T>(button: HTMLButtonElement, action: () => Promise<T>): Promise<T> {
  button.disabled = true;
  button.classList.add("loading");
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.classList.remove("loading");
  }
}

export function money(minor: number, currency: string): string {
  const major = (minor / 100).toFixed(2);
  return `${major} ${currency}`;
}

export function field(label: string, input: HTMLElement, hint?: string): HTMLElement {
  return el(
    "div",
    { class: "field" },
    el("label", {}, label),
    input,
    hint ? el("div", { class: "hint" }, hint) : null,
  );
}

export function input(
  name: string,
  attrs: Record<string, string> = {},
): HTMLInputElement {
  return el("input", { name, autocomplete: "off", ...attrs });
}
