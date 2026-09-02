/** Tiny DOM helpers. No framework: less code to audit, nothing to fingerprint. */
export type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | ((event: Event) => void)> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === "function") node.addEventListener(key.replace(/^on/, ""), value);
    else if (value === true) node.setAttribute(key, "");
    else if (value !== false) node.setAttribute(key, String(value));
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
