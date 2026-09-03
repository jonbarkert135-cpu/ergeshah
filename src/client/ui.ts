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
    // Widths come from CSS (`.skeleton.line:nth-child(n)`): an inline style is dropped by
    // the Content-Security-Policy, silently — the real browser said so, the tests did not.
    wrap.append(el("div", { class: `skeleton ${kind}` }));
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
    const cancel = el("button", { type: "button", class: "ghost" }, "Cancel");
    const confirm = el(
      "button",
      { type: "button", class: options.danger ? "danger" : "primary" },
      options.confirmLabel ?? "Confirm",
    );
    const dialog = el(
      "dialog",
      { "aria-labelledby": "dialog-title", "aria-describedby": "dialog-body" },
      el("h2", { id: "dialog-title" }, options.title),
      el("p", { class: "muted", id: "dialog-body" }, options.body),
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

/**
 * A price, as the API sends it: an exact decimal string of XMR. The unit is appended and
 * nothing is rounded — a marketplace that quietly displayed 0.0450 as 0.05 would be telling
 * the buyer a number the payment will not match.
 */
export function price(xmr: string): string {
  return `${xmr} XMR`;
}

let fieldCounter = 0;

/**
 * A labelled control. The label is *associated* (`for`/`id`), not merely adjacent: that is
 * what lets a screen reader name the field, and what makes the label a click target for
 * the control. The hint is wired with `aria-describedby` for the same reason.
 */
export function field(label: string, input: HTMLElement, hint?: string): HTMLElement {
  const id = input.id || `f${(fieldCounter += 1)}`;
  input.id = id;
  const help = hint ? el("div", { class: "hint", id: `${id}-hint` }) : null;
  if (help) {
    help.textContent = hint!;
    input.setAttribute("aria-describedby", help.id);
  }
  return el("div", { class: "field" }, el("label", { for: id }, label), input, help);
}

export interface DialogField {
  name: string;
  label: string;
  kind?: "text" | "textarea" | "select" | "number";
  options?: Array<[value: string, label: string]>;
  hint?: string;
  required?: boolean;
  min?: number;
  max?: number;
  maxlength?: number;
  autocomplete?: string;
}

/**
 * A question with fields — what `window.prompt` was for, without its problems: prompt has no
 * label, no hint, no validation, takes one line, and is styled by the browser rather than by
 * the system. Native `<dialog>` with `<form method="dialog">`: Escape cancels, Enter submits,
 * focus is trapped and returned by the platform. Resolves to the values, or `null`.
 */
export function formDialog(options: {
  title: string;
  body?: string;
  fields: DialogField[];
  confirmLabel?: string;
  danger?: boolean;
}): Promise<Record<string, string> | null> {
  return new Promise((resolve) => {
    const controls = options.fields.map((spec) => {
      const control =
        spec.kind === "textarea"
          ? el("textarea", { name: spec.name, rows: "4" })
          : spec.kind === "select"
            ? el("select", { name: spec.name }, ...(spec.options ?? []).map(([value, label]) => el("option", { value }, label)))
            : el("input", { name: spec.name, type: spec.kind === "number" ? "number" : "text", autocomplete: spec.autocomplete ?? "off" });
      if (spec.required) control.setAttribute("required", "");
      if (spec.maxlength) control.setAttribute("maxlength", String(spec.maxlength));
      if (spec.min !== undefined) control.setAttribute("min", String(spec.min));
      if (spec.max !== undefined) control.setAttribute("max", String(spec.max));
      return [spec, control] as const;
    });
    const cancel = el("button", { class: "ghost", type: "button" }, "Cancel");
    const confirm = el("button", { class: options.danger ? "danger" : "primary", type: "submit" }, options.confirmLabel ?? "Continue");
    const form = el(
      "form",
      { method: "dialog" },
      el("h2", { id: "dialog-title" }, options.title),
      options.body ? el("p", { class: "muted" }, options.body) : null,
      ...controls.map(([spec, control]) => field(spec.label, control, spec.hint)),
      el("div", { class: "actions" }, cancel, confirm),
    );
    const dialog = el("dialog", { "aria-labelledby": "dialog-title" }, form) as HTMLDialogElement;
    const close = (answer: Record<string, string> | null) => {
      dialog.close();
      dialog.remove();
      resolve(answer);
    };
    cancel.addEventListener("click", () => close(null));
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const values: Record<string, string> = {};
      for (const [spec, control] of controls) values[spec.name] = (control as HTMLInputElement).value.trim();
      close(values);
    });
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      close(null);
    });
    document.body.append(dialog);
    dialog.showModal();
    (controls[0]?.[1] as HTMLElement | undefined)?.focus();
  });
}

/**
 * A data table with the structure assistive technology needs (`<thead>`, `scope`) and the
 * one thing a phone needs: each cell knows its column, so below 640px the rows stack into
 * labelled blocks instead of forcing a sideways scroll through six columns.
 */
export function table(headers: string[], rows: Child[][], options: { caption?: string } = {}): HTMLElement {
  const head = el("thead", {}, el("tr", {}, ...headers.map((text) => el("th", { scope: "col" }, text))));
  const body = el("tbody", {});
  for (const cells of rows) {
    body.append(
      el(
        "tr",
        {},
        ...cells.map((cell, index) =>
          el("td", headers[index] ? { "data-label": headers[index]! } : {}, cell),
        ),
      ),
    );
  }
  return el(
    "div",
    { class: "table-wrap" },
    el("table", { class: "stack" }, options.caption ? el("caption", { class: "sr-only" }, options.caption) : null, head, body),
  );
}

/**
 * After a view renders, move focus to its heading. A hash router swaps the page under a
 * screen reader without telling it; focusing the new `<h1>` announces where the reader is
 * and puts the keyboard at the top of the content rather than wherever it was.
 */
export function announce(container: HTMLElement): void {
  const heading = container.querySelector("h1");
  if (!heading) return;
  heading.setAttribute("tabindex", "-1");
  heading.focus({ preventScroll: false });
}

export function input(
  name: string,
  attrs: Record<string, string> = {},
): HTMLInputElement {
  return el("input", { name, autocomplete: "off", ...attrs });
}
