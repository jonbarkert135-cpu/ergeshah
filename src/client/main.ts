/**
 * Application shell and router.
 *
 * The client is a plain ES module bundle: no framework, no telemetry, no remote
 * resources of any kind. Everything it loads comes from this origin, which is what makes
 * the `default-src 'self'` Content-Security-Policy possible.
 */
import { clear, el } from "./ui.ts";
import { lock, ready, state } from "./state.ts";
import { renderAuth } from "./views/auth.ts";
import { renderChat } from "./views/chat.ts";
import { renderMarket, renderSell } from "./views/market.ts";
import { renderOrders } from "./views/orders.ts";
import { renderModeration } from "./views/admin.ts";
import { renderAccount } from "./views/account.ts";
import { receiveMessages } from "./messaging.ts";

const root = document.getElementById("app") as HTMLElement;

const ROUTES = [
  { hash: "#/market", label: "Market" },
  { hash: "#/chat", label: "Messages" },
  { hash: "#/orders", label: "Orders" },
  { hash: "#/sell", label: "Sell" },
  { hash: "#/account", label: "Account" },
  { hash: "#/moderation", label: "Moderation", staffOnly: true },
];

async function main(): Promise<void> {
  await ready();
  window.addEventListener("hashchange", () => render());
  render();
  // Background delivery poll: the tab pulls, the server never pushes and never holds
  // an open association between an account and a socket.
  window.setInterval(() => {
    if (!state.vault || document.hidden) return;
    void receiveMessages().catch(() => undefined);
  }, 10_000);
}

function render(): void {
  clear(root);
  if (!state.account || !state.vault) {
    root.append(header(false), main_(renderAuthView), footer());
    return;
  }
  root.append(header(true), main_(renderRoute), footer());
}

function renderAuthView(container: HTMLElement): void {
  renderAuth(container, () => {
    if (!location.hash || location.hash === "#/") location.hash = "#/market";
    render();
  });
}

function renderRoute(container: HTMLElement): void {
  const hash = location.hash || "#/market";
  const navigate = (route: string) => {
    location.hash = route;
  };
  if (hash.startsWith("#/chat")) return renderChat(container);
  if (hash.startsWith("#/orders")) return renderOrders(container);
  if (hash.startsWith("#/sell")) return renderSell(container);
  if (hash.startsWith("#/account")) {
    return renderAccount(container, () => {
      lock();
      location.hash = "#/";
      render();
    });
  }
  if (hash.startsWith("#/moderation")) return renderModeration(container);
  return renderMarket(container, navigate);
}

function header(signedIn: boolean): HTMLElement {
  const nav = el("nav", {});
  if (signedIn) {
    const staff = state.account?.role === "moderator" || state.account?.role === "admin";
    for (const route of ROUTES) {
      if (route.staffOnly && !staff) continue;
      const button = el("button", { class: "ghost" }, route.label);
      if ((location.hash || "#/market").startsWith(route.hash)) button.setAttribute("aria-current", "page");
      button.addEventListener("click", () => {
        location.hash = route.hash;
      });
      nav.append(button);
    }
  }
  return el(
    "header",
    { class: "top" },
    el("span", { class: "brand" }, "Symvolon"),
    nav,
    el("span", { class: "spacer" }),
    signedIn ? el("span", { class: "who" }, `@${state.account?.username}`) : null,
  );
}

function main_(draw: (container: HTMLElement) => void): HTMLElement {
  const container = el("main", {});
  draw(container);
  return container;
}

function footer(): HTMLElement {
  return el(
    "footer",
    { class: "legal" },
    "Encryption happens in this browser. The server sees ciphertext, not messages — but it does see when you connect. Read docs/THREAT_MODEL.md before trusting it with anything that matters.",
  );
}

void main();
