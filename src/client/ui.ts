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

export function notice(message: string, kind: "info" | "error" = "info"): HTMLElement {
  return el("div", { class: kind === "error" ? "notice error" : "notice" }, message);
}

export function money(minor: number, currency: string): string {
  const major = (minor / 100).toFixed(2);
  return `${major} ${currency}`;
}

export function field(
  label: string,
  input: HTMLElement,
  hint?: string,
): HTMLElement {
  return el("div", {}, el("label", {}, label), input, hint ? el("div", { class: "muted mono" }, hint) : null);
}

export function input(
  name: string,
  attrs: Record<string, string> = {},
): HTMLInputElement {
  return el("input", { name, autocomplete: "off", ...attrs });
}
