import { api } from "../api.ts";
import { clear, el, notice } from "../ui.ts";
import { forgetLocalVault, lock } from "../state.ts";

export function renderAccount(root: HTMLElement, onSignedOut: () => void): void {
  clear(root);
  const body = el("div", {});
  root.append(el("h1", {}, "Account & devices"), body);
  void load();

  async function load() {
    clear(body).append(el("p", { class: "muted" }, "Loading…"));
    const me = await api<{ username: string; role: string; memberSince: string | null }>("/api/auth/me");
    const keys = await api<{
      devices: Array<{
        deviceId: string;
        label: string | null;
        signedPreKeyAgeDays: number;
        oneTimePreKeysAvailable: number;
      }>;
    }>("/api/keys/status");
    const sessions = await api<{
      sessions: Array<{ id: string; label: string | null; current: boolean; lastSeenOn: string; expiresOn: string }>;
    }>("/api/auth/sessions");
    clear(body);

    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", { style: "margin-top:0" }, `@${me.username}`),
        el("div", { class: "muted mono" }, `role: ${me.role} · member since ${me.memberSince ?? "—"}`),
        el(
          "p",
          { class: "muted" },
          "The server knows your username, a double-hashed derivative of your password, your public keys, and nothing else about you.",
        ),
      ),
    );

    body.append(el("h2", {}, "Devices"));
    for (const device of keys.devices) {
      body.append(
        el(
          "div",
          { class: "card" },
          el("strong", {}, device.label ?? "unnamed device"),
          el("div", { class: "mono muted" }, device.deviceId),
          el(
            "div",
            { class: "muted" },
            `signed prekey age: ${device.signedPreKeyAgeDays}d · one-time prekeys left: ${device.oneTimePreKeysAvailable}`,
          ),
          revokeButton(device.deviceId),
        ),
      );
    }

    body.append(el("h2", {}, "Sessions"));
    const table = el(
      "table",
      {},
      el("tr", {}, el("th", {}, "Label"), el("th", {}, "Last seen"), el("th", {}, "Expires"), el("th", {}, "")),
    );
    for (const session of sessions.sessions) {
      const revoke = el("button", { class: "ghost" }, session.current ? "current" : "Revoke");
      if (session.current) revoke.setAttribute("disabled", "");
      else
        revoke.addEventListener("click", () => {
          void api(`/api/auth/sessions/${session.id}`, { method: "DELETE" }).then(() => void load());
        });
      table.append(
        el(
          "tr",
          {},
          el("td", {}, session.label ?? "—"),
          el("td", { class: "mono" }, session.lastSeenOn),
          el("td", { class: "mono" }, session.expiresOn),
          el("td", {}, revoke),
        ),
      );
    }
    body.append(table);

    body.append(
      el(
        "div",
        { class: "row", style: "margin-top:20px" },
        el("button", { onclick: () => void signOut(false) }, "Sign out"),
        el("button", { class: "danger", onclick: () => void signOut(true) }, "Sign out and wipe this device"),
      ),
      notice(
        "Wiping removes the encrypted vault from this browser. Your messages exist nowhere else, so they are gone unless you can restore the sealed backup with your password.",
      ),
    );
  }

  function revokeButton(deviceId: string): HTMLElement {
    const button = el("button", { class: "danger" }, "Revoke device");
    button.addEventListener("click", () => {
      if (!window.confirm("Revoke this device? Undelivered messages to it are deleted.")) return;
      void api("/api/keys/revoke", { method: "POST", body: { deviceId } }).then(() => void load());
    });
    return button;
  }

  async function signOut(wipe: boolean) {
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    if (wipe) forgetLocalVault();
    lock();
    onSignedOut();
  }
}

