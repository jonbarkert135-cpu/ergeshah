import { api, ApiError } from "../api.ts";
import { clear, el, field, input, notice } from "../ui.ts";
import {
  adoptLinkedIdentity,
  deriveKeys,
  forgetLocalVault,
  localSealedVault,
  newVault,
  persistVault,
  publishDevice,
  state,
  unlockVault,
} from "../state.ts";
import { claimDeviceLink, newDeviceCode } from "../linking.ts";
import type { SealedVault } from "../../shared/crypto/vault.ts";

export function renderAuth(root: HTMLElement, onReady: () => void): void {
  clear(root);
  let mode: "login" | "register" | "link" = localSealedVault() ? "login" : "register";
  const container = el("div", {});
  root.append(container);
  draw();

  function draw(message?: HTMLElement) {
    clear(container);
    if (mode === "link") {
      drawLink(message);
      return;
    }
    const username = input("username", { autocomplete: "username", minlength: "3", maxlength: "32" });
    const password = input("password", { type: "password", autocomplete: "current-password", minlength: "12" });
    const submit = el("button", { class: "primary", type: "submit" }, mode === "login" ? "Unlock" : "Create account");
    const status = el("div", {});

    const form = el(
      "form",
      { class: "card" },
      el("h1", {}, mode === "login" ? "Sign in" : "Create an account"),
      el(
        "p",
        { class: "lede" },
        mode === "login"
          ? "Your password unlocks the keys stored on this device. It is never sent to the server."
          : "No email, no phone number, no recovery question. The password is stretched in your browser; the server only ever sees a derived half of it.",
      ),
      field("Username", username, "3–32 characters: a–z, 0–9, dot, dash, underscore"),
      field("Password", password, "At least 12 characters. There is no reset: forgetting it destroys your keys."),
      el("div", { class: "row", style: "margin-top:16px" }, submit,
        el("button", { type: "button", class: "ghost", onclick: () => { mode = mode === "login" ? "register" : "login"; draw(); } },
          mode === "login" ? "Create an account instead" : "I already have an account"),
        el("button", { type: "button", class: "ghost", onclick: () => { mode = "link"; draw(); } },
          "Link this browser to an account"),
      ),
      status,
    );
    if (message) status.append(message);

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      submit.disabled = true;
      status.replaceChildren(notice("Deriving keys — this is deliberately slow…"));
      // Yield first so the browser can paint before the Argon2id pass blocks the thread.
      setTimeout(() => {
        void run(username.value.trim().toLowerCase(), password.value)
          .catch((error: unknown) => {
            submit.disabled = false;
            const text = error instanceof ApiError ? error.message : (error as Error).message;
            draw(notice(text, "error"));
          });
      }, 30);
    });
    container.append(form);
  }

  /**
   * Linking screen. This browser makes its own keys and shows a code; a device that is
   * already signed in reads the code and vouches for the keys. We poll until it does.
   */
  function drawLink(message?: HTMLElement) {
    const { code, fingerprint, secret, identity } = newDeviceCode();
    const password = input("device password", { type: "password", minlength: "12" });
    const status = el("div", {});
    let polling = false;

    const codeBox = el("textarea", { readonly: "", rows: "4", class: "mono", style: "width:100%" });
    (codeBox as HTMLTextAreaElement).value = code;

    const start = el("button", { class: "primary" }, "Waiting for the other device…");
    start.addEventListener("click", () => {
      if (polling) return;
      if (password.value.length < 12) {
        status.replaceChildren(notice("Use at least 12 characters for this device.", "error"));
        return;
      }
      polling = true;
      start.disabled = true;
      status.replaceChildren(notice("Watching for the authorisation…"));
      void poll(password.value);
    });

    async function poll(devicePassword: string): Promise<void> {
      const deadline = Date.now() + 5 * 60 * 1000;
      while (Date.now() < deadline) {
        const account = await claimDeviceLink(secret);
        if (account) {
          await adoptLinkedIdentity(account, identity, devicePassword);
          onReady();
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
      polling = false;
      start.disabled = false;
      status.replaceChildren(notice("The code expired. Reload to get a new one.", "error"));
    }

    const card = el(
      "div",
      { class: "card" },
      el("h1", {}, "Link this browser"),
      el(
        "p",
        { class: "lede" },
        "This browser will get its own keys. Read the code below into an already signed-in device (Account → Link a device), then start waiting here.",
      ),
      field("Device code", codeBox, "Copy all of it."),
      el("p", { class: "mono" }, `Fingerprint: ${fingerprint}`),
      notice(
        "Check that the other device shows the same fingerprint before you authorise it. Linking does not copy your message history — this browser starts empty and receives what arrives from now on.",
      ),
      field("Password for this device", password, "Protects this browser's keys. Never sent anywhere; it does not have to match your account password."),
      el("div", { class: "row", style: "margin-top:16px" }, start,
        el("button", { type: "button", class: "ghost", onclick: () => { mode = localSealedVault() ? "login" : "register"; draw(); } }, "Back"),
      ),
      status,
    );
    if (message) status.append(message);
    container.append(card);
  }

  async function run(username: string, password: string): Promise<void> {
    if (password.length < 12) throw new Error("password must be at least 12 characters");
    const keys = deriveKeys(username, password);
    const authSecret = btoa(String.fromCharCode(...keys.authSecret))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    if (mode === "register") {
      state.vault = newVault();
      state.vaultKey = keys.vaultKey;
      const account = await api<{ id: string; username: string; role: string }>(
        "/api/auth/register",
        { method: "POST", body: { username, authSecret } },
      );
      state.account = { id: account.id, username: account.username, role: account.role as never };
      await persistVault();
      await publishDevice("browser");
      onReady();
      return;
    }

    const account = await api<{
      id: string;
      username: string;
      role: string;
      sealedVault: SealedVault | null;
    }>("/api/auth/login", { method: "POST", body: { username, authSecret } });
    const sealed = localSealedVault() ?? account.sealedVault;
    state.vaultKey = keys.vaultKey;
    if (sealed) {
      try {
        state.vault = unlockVault(keys.vaultKey, sealed);
      } catch {
        throw new Error("could not decrypt the local key vault with that password");
      }
    } else {
      // No vault anywhere: this account's old keys are unrecoverable, start a new device.
      forgetLocalVault();
      state.vault = newVault();
    }
    state.account = { id: account.id, username: account.username, role: account.role as never };
    await publishDevice("browser");
    onReady();
  }
}
