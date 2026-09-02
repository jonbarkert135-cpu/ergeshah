import { api } from "../api.ts";
import { clear, el, notice } from "../ui.ts";
import { changePassword, deleteAccount, forgetLocalVault, lock } from "../state.ts";

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

    body.append(el("h2", {}, "Password"), passwordCard());
    body.append(el("h2", {}, "Delete account"), deleteCard());
  }

  function passwordCard(): HTMLElement {
    const current = el("input", { type: "password", placeholder: "Current password" });
    const next = el("input", { type: "password", placeholder: "New password" });
    const again = el("input", { type: "password", placeholder: "New password again" });
    const message = el("div", { class: "muted" });
    const button = el("button", {}, "Change password");

    button.addEventListener("click", () => {
      const values = [current, next, again].map((field) => (field as HTMLInputElement).value);
      if (values[1] !== values[2]) {
        message.textContent = "The two new passwords do not match.";
        return;
      }
      if (values[1]!.length < 12) {
        message.textContent = "Use at least 12 characters — this password protects your keys.";
        return;
      }
      button.setAttribute("disabled", "");
      message.textContent = "Re-sealing your vault…";
      void changePassword(values[0]!, values[1]!)
        .then(() => {
          message.textContent = "Password changed. Other sessions were signed out.";
          for (const field of [current, next, again]) (field as HTMLInputElement).value = "";
        })
        .catch((error: Error) => {
          message.textContent = error.message;
        })
        .finally(() => button.removeAttribute("disabled"));
    });

    return el(
      "div",
      { class: "card" },
      el("p", { class: "muted", style: "margin-top:0" },
        "Your password unlocks the vault holding your private keys, so changing it re-encrypts the vault in this browser and replaces the sealed backup. Every other session is signed out."),
      el("div", { class: "row" }, current, next, again),
      el("div", { class: "row", style: "margin-top:12px" }, button, message),
    );
  }

  function deleteCard(): HTMLElement {
    const password = el("input", { type: "password", placeholder: "Password" });
    const message = el("div", { class: "muted" });
    const button = el("button", { class: "danger" }, "Delete my account");

    button.addEventListener("click", () => {
      if (!window.confirm("Delete the account for good? Messages, listings, orders and reviews go with it, and the username becomes available to someone else.")) return;
      button.setAttribute("disabled", "");
      void deleteAccount((password as HTMLInputElement).value)
        .then(() => onSignedOut())
        .catch((error: Error) => {
          message.textContent = error.message;
          button.removeAttribute("disabled");
        });
    });

    return el(
      "div",
      { class: "card" },
      el("p", { class: "muted", style: "margin-top:0" },
        "This removes the account, the sealed vault, every device and prekey, undelivered messages, listings, orders and reviews. Moderation records stay, without your identity attached. Nothing here is recoverable."),
      el("div", { class: "row" }, password, button),
      message,
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

