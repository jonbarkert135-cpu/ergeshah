/**
 * Application shell and router.
 *
 * The client is a plain ES module bundle: no framework, no telemetry, no remote
 * resources of any kind. Everything it loads comes from this origin, which is what makes
 * the `default-src 'self'` Content-Security-Policy possible.
 */
import { announce, clear, el, skeleton } from "./ui.ts";
import { lock, ready, state } from "./state.ts";
import { applyTheme, currentTheme, nextTheme, setTheme, themeLabel } from "./theme.ts";
import { sodiumReady } from "../shared/crypto/sodium.ts";
import { renderAuth } from "./views/auth.ts";
import { renderChat } from "./views/chat.ts";
import { renderMarket, renderSell } from "./views/market.ts";
import { renderOrders } from "./views/orders.ts";
import { renderWallet } from "./views/wallet.ts";
import { renderModeration } from "./views/admin.ts";
import { renderAccount } from "./views/account.ts";
import { renderNotifications, unreadCount } from "./views/notifications.ts";
import { receiveMessages } from "./messaging.ts";

const root = document.getElementById("app") as HTMLElement;

const ROUTES = [
  { hash: "#/market", label: "Market" },
  { hash: "#/chat", label: "Messages" },
  { hash: "#/orders", label: "Orders" },
  { hash: "#/wallet", label: "Balance" },
  { hash: "#/notifications", label: "Notifications" },
  { hash: "#/sell", label: "Sell" },
  { hash: "#/account", label: "Account" },
  { hash: "#/moderation", label: "Moderation", staffOnly: true },
];

async function main(): Promise<void> {
  applyTheme();
  // Paint before the cryptography arrives. libsodium is a megabyte of WebAssembly that a
  // visitor reading the sign-in page does not need until they submit, so it downloads in
  // the background while the shell is already on screen (ADR-0027). Every flow that
  // touches a key awaits `sodiumReady()` first, and the promise is memoised.
  const crypto = sodiumReady();
  // A hash change is a page change. Focus goes to the new heading so a keyboard or screen
  // reader user lands on the content, not on a detached button from the previous view.
  window.addEventListener("hashchange", () => render(true));
  renderShell();
  await ready(crypto);
  render();
  // Background delivery poll: the tab pulls, the server never pushes and never holds
  // an open association between an account and a socket.
  window.setInterval(() => {
    if (!state.vault || document.hidden) return;
    void receiveMessages().catch(() => undefined);
    void paintUnread();
  }, 10_000);
  void paintUnread();
}

/** The frame, immediately: header, a placeholder, footer. No blank page, ever. */
function renderShell(): void {
  clear(root);
  root.append(
    header(false),
    main_((container) => {
      container.append(skeleton("line", 3), el("div", { class: "gap" }), skeleton("card", 1));
    }),
    footer(),
  );
}

function render(navigated = false): void {
  clear(root);
  const signedIn = Boolean(state.account && state.vault);
  const content = main_(signedIn ? renderRoute : renderAuthView);
  root.append(skipLink(), header(signedIn), content, footer());
  if (navigated) announce(content);
}

/** First in the tab order, visible only when focused: past the header in one keystroke. */
function skipLink(): HTMLElement {
  return el("a", { class: "skip", href: "#main" }, "Skip to content");
}

function renderAuthView(container: HTMLElement): void {
  renderAuth(container, () => {
    if (!location.hash || location.hash === "#/") location.hash = "#/market";
    render(true);
  });
}

function renderRoute(container: HTMLElement): void {
  const hash = location.hash || "#/market";
  const navigate = (route: string) => {
    location.hash = route;
  };
  if (hash.startsWith("#/chat")) return renderChat(container);
  if (hash.startsWith("#/orders")) return renderOrders(container);
  if (hash.startsWith("#/wallet")) return renderWallet(container);
  if (hash.startsWith("#/sell")) return renderSell(container);
  if (hash.startsWith("#/account")) {
    return renderAccount(container, () => {
      lock();
      location.hash = "#/";
      render();
    });
  }
  if (hash.startsWith("#/notifications")) return renderNotifications(container);
  if (hash.startsWith("#/moderation")) return renderModeration(container);
  return renderMarket(container, navigate);
}

/** The brand mark, inline: one request fewer, and it inherits the theme's ink colour. */
function mark(): SVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 512 512");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "currentColor");
  const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
  group.setAttribute("transform", "rotate(-38,256,256)");
  for (const [d, shift] of [
    ["M 56,256 A 200,200 0 0 1 456,256 Z", "translate(-28,-9)"],
    ["M 456,256 A 200,200 0 0 1 56,256 Z", "translate(28,9)"],
  ] as const) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    path.setAttribute("transform", shift);
    group.append(path);
  }
  svg.append(group);
  return svg;
}

/** Sun, moon, half-disc: drawn, not typed, because a glyph is a font's opinion. */
function themeIcon(theme: string): SVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  const add = (tag: string, attrs: Record<string, string>) => {
    const node = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    svg.append(node);
  };
  if (theme === "light") {
    add("circle", { cx: "12", cy: "12", r: "4.2" });
    for (let i = 0; i < 8; i += 1) {
      const angle = (i * Math.PI) / 4;
      const inner = 7,
        outer = 9.4;
      add("line", {
        x1: String(12 + Math.cos(angle) * inner),
        y1: String(12 + Math.sin(angle) * inner),
        x2: String(12 + Math.cos(angle) * outer),
        y2: String(12 + Math.sin(angle) * outer),
      });
    }
  } else if (theme === "dark") {
    add("path", { d: "M20 14.4A8.5 8.5 0 1 1 9.6 4a6.8 6.8 0 0 0 10.4 10.4Z" });
  } else {
    add("circle", { cx: "12", cy: "12", r: "8.4" });
    add("path", { d: "M12 3.6a8.4 8.4 0 0 1 0 16.8Z", fill: "currentColor", stroke: "none" });
  }
  return svg;
}

function themeButton(): HTMLElement {
  const button = el("button", {
    class: "ghost icon",
    type: "button",
    title: themeLabel(currentTheme()),
    "aria-label": themeLabel(currentTheme()),
  });
  const paint = () => {
    const theme = currentTheme();
    clear(button).append(themeIcon(theme));
    button.setAttribute("title", themeLabel(theme));
    button.setAttribute("aria-label", themeLabel(theme));
  };
  paint();
  button.addEventListener("click", () => {
    setTheme(nextTheme());
    paint();
  });
  return button;
}

function header(signedIn: boolean): HTMLElement {
  // Navigation is links, not buttons: a link is what "go to a page" is, it works with the
  // middle mouse button, the keyboard's link list and the browser's history, for free.
  const nav = el("nav", { "aria-label": "Primary" });
  if (signedIn) {
    const staff = state.account?.role === "moderator" || state.account?.role === "admin";
    for (const route of ROUTES) {
      if (route.staffOnly && !staff) continue;
      const link = el("a", { class: "ghost", href: route.hash }, route.label);
      if (route.hash === "#/notifications") link.dataset.unread = "";
      if ((location.hash || "#/market").startsWith(route.hash)) link.setAttribute("aria-current", "page");
      nav.append(link);
    }
  }
  return el(
    "header",
    { class: "top" },
    el("span", { class: "brand" }, mark(), "Symvolon"),
    nav,
    el("span", { class: "spacer" }),
    signedIn ? el("span", { class: "who" }, `@${state.account?.username}`) : null,
    themeButton(),
  );
}

/**
 * The unread badge. Written into the existing navigation link rather than kept in a state
 * object: there is one place it can be wrong, and it disappears when the count is zero.
 */
async function paintUnread(): Promise<void> {
  const link = document.querySelector<HTMLAnchorElement>("nav a[data-unread]");
  if (!link) return;
  const count = await unreadCount();
  clear(link).append("Notifications");
  if (count > 0) {
    link.append(el("span", { class: "badge", "aria-label": `${count} unread` }, String(count)));
  }
}

function main_(draw: (container: HTMLElement) => void): HTMLElement {
  const container = el("main", { id: "main", tabindex: "-1" });
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
