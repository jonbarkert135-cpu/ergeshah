import { api, ApiError } from "../api.ts";
import { clear, el, field, input, notice } from "../ui.ts";
import {
  deriveKeys,
  forgetLocalVault,
  localSealedVault,
  newVault,
  persistVault,
  publishDevice,
  state,
  unlockVault,
} from "../state.ts";
import type { SealedVault } from "../../shared/crypto/vault.ts";

export function renderAuth(root: HTMLElement, onReady: () => void): void {
  clear(root);
  let mode: "login" | "register" = localSealedVault() ? "login" : "register";
  const container = el("div", {});
  root.append(container);
  draw();

  function draw(message?: HTMLElement) {
    clear(container);
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
