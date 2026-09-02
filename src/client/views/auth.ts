import { api, ApiError } from "../api.ts";
import { clear, el, field, input, notice } from "../ui.ts";
import {
  adoptLinkedIdentity,
  deriveKeys,
  forgetLocalVault,
  initialiseVault,
  localSealedVault,
  newVault,
  persistVault,
  publishDevice,
  state,
  unlockBackup,
} from "../state.ts";
import { claimDeviceLink, newDeviceCode } from "../linking.ts";
import { recoverAccount, recoveryMaterial } from "../recovery.ts";
import { generatePhrase, type PhraseLength } from "../../shared/crypto/mnemonic.ts";
import { toBase64Url } from "../../shared/encoding.ts";
import type { VaultBackup } from "../../shared/crypto/vault.ts";

export function renderAuth(root: HTMLElement, onReady: () => void): void {
  clear(root);
  let mode: "login" | "register" | "link" | "recover" = localSealedVault() ? "login" : "register";
  const container = el("div", {});
  root.append(container);
  draw();

  function draw(message?: HTMLElement) {
    clear(container);
    if (mode === "link") {
      drawLink(message);
      return;
    }
    if (mode === "recover") {
      drawRecover(message);
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
        el("button", { type: "button", class: "ghost", onclick: () => { mode = "recover"; draw(); } },
          "Use a recovery phrase"),
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

    if (mode === "register") {
      // The phrase is generated before the account exists, shown once, and checked here.
      // Nothing about it reaches the server except a public key derived from it.
      drawPhrase(username, password);
      return;
    }

    const keys = deriveKeys(username, password);
    const authSecret = toBase64Url(keys.authSecret);
    const account = await api<{
      id: string;
      username: string;
      role: string;
      sealedVault: VaultBackup | null;
    }>("/api/auth/login", { method: "POST", body: { username, authSecret } });
    const backup = localSealedVault() ?? account.sealedVault;
    if (backup) {
      try {
        const opened = unlockBackup(keys.wrapKey, backup);
        state.vault = opened.vault;
        state.masterKey = opened.masterKey;
        state.envelopes = { password: backup.password, recovery: backup.recovery ?? null };
      } catch {
        throw new Error("could not decrypt the local key vault with that password");
      }
    } else {
      // No vault anywhere: this account's old keys are unrecoverable, start a new device.
      forgetLocalVault();
      initialiseVault(newVault(), { password: keys.wrapKey });
    }
    state.account = { id: account.id, username: account.username, role: account.role as never };
    await publishDevice("browser");
    onReady();
  }

  /** Step two of registration: the phrase, its one-time display, and the confirmation. */
  function drawPhrase(username: string, password: string): void {
    let length: PhraseLength = 24;
    let phrase = generatePhrase(length);
    render();

    function render(message?: HTMLElement) {
      clear(container);
      const words = phrase.split(" ");
      const grid = el("div", { class: "phrase" });
      words.forEach((word, index) =>
        grid.append(el("div", { class: "phrase-word" },
          el("span", { class: "phrase-index" }, String(index + 1)),
          el("span", { class: "mono" }, word)),
        ),
      );

      const positions = pickPositions(words.length);
      const answers = positions.map(() => input("word", { autocomplete: "off", spellcheck: "false" }));
      const status = el("div", {});
      const finish = el("button", { class: "primary" }, "I have written it down — create the account");

      finish.addEventListener("click", () => {
        const wrong = positions.filter(
          (position, index) => answers[index]!.value.trim().toLowerCase() !== words[position - 1],
        );
        if (wrong.length > 0) {
          status.replaceChildren(notice(`Words ${wrong.join(", ")} do not match. Check the list above.`, "error"));
          return;
        }
        finish.disabled = true;
        status.replaceChildren(notice("Deriving keys — this is deliberately slow…"));
        setTimeout(() => {
          void createAccount(username, password, phrase)
            .catch((error: unknown) => {
              finish.disabled = false;
              const text = error instanceof ApiError ? error.message : (error as Error).message;
              render(notice(text, "error"));
            });
        }, 30);
      });

      const swap = el("button", { class: "ghost", type: "button" },
        length === 24 ? "Use 12 words instead" : "Use 24 words (recommended)");
      swap.addEventListener("click", () => {
        length = length === 24 ? 12 : 24;
        phrase = generatePhrase(length);
        render();
      });

      const download = el("button", { class: "ghost", type: "button" }, "Download as a text file");
      download.addEventListener("click", () => {
        const blob = new Blob([`Symvolon recovery phrase for @${username}\n\n${phrase}\n`], {
          type: "text/plain",
        });
        const url = URL.createObjectURL(blob);
        const anchor = el("a", { href: url, download: `symvolon-recovery-${username}.txt` });
        anchor.click();
        URL.revokeObjectURL(url);
      });

      const copy = el("button", { class: "ghost", type: "button" }, "Copy");
      copy.addEventListener("click", () => void navigator.clipboard?.writeText(phrase));

      container.append(
        el(
          "div",
          { class: "card" },
          el("h1", {}, "Your recovery phrase"),
          el("p", { class: "lede" },
            "This is the only way back into your account if you forget your password. It is shown once, here, and never again — not by us, not by anyone."),
          grid,
          el("div", { class: "row", style: "margin-top:12px" }, copy, download, swap),
          notice(
            "Write it on paper and keep it somewhere private. Anyone who has these words can take the account and read its history; if you lose them along with your password, nobody can restore access — there is no email reset and no administrator override.",
          ),
          el("h2", {}, "Confirm you have it"),
          el("p", { class: "muted" }, `Type words ${positions.join(", ")} — they are checked in this browser and never sent anywhere.`),
          el("div", { class: "confirm" },
            ...positions.map((position, index) => field(`Word ${position}`, answers[index]!)),
          ),
          el("div", { class: "row", style: "margin-top:16px" }, finish,
            el("button", { class: "ghost", type: "button", onclick: () => { mode = "register"; draw(); } }, "Back"),
          ),
          status,
        ),
      );
      if (message) status.append(message);
    }
  }

  async function createAccount(username: string, password: string, phrase: string): Promise<void> {
    const keys = deriveKeys(username, password);
    const recovery = recoveryMaterial(username, phrase);
    try {
      initialiseVault(newVault(), { password: keys.wrapKey, recovery: recovery.wrapKey });
      const account = await api<{ id: string; username: string; role: string }>(
        "/api/auth/register",
        {
          method: "POST",
          body: {
            username,
            authSecret: toBase64Url(keys.authSecret),
            recoveryPublicKey: recovery.publicKey,
          },
        },
      );
      state.account = { id: account.id, username: account.username, role: account.role as never };
      await persistVault();
      await publishDevice("browser");
      onReady();
    } finally {
      recovery.forget();
      keys.authSecret.fill(0);
    }
  }

  /** Recovery: phrase in, new password out, every old session gone. */
  function drawRecover(message?: HTMLElement) {
    const username = input("username", { autocomplete: "username" });
    const phrase = el("textarea", { rows: "3", class: "mono", placeholder: "twelve or twenty-four words", style: "width:100%" });
    const password = input("new password", { type: "password", minlength: "12" });
    const status = el("div", {});
    const submit = el("button", { class: "primary" }, "Recover the account");

    submit.addEventListener("click", () => {
      const words = (phrase as HTMLTextAreaElement).value;
      if (password.value.length < 12) {
        status.replaceChildren(notice("The new password needs at least 12 characters.", "error"));
        return;
      }
      submit.disabled = true;
      status.replaceChildren(notice("Deriving keys from the phrase — this is deliberately slow…"));
      setTimeout(() => {
        void recoverAccount(username.value.trim().toLowerCase(), words, password.value)
          .then(async (result) => {
            state.account = result.account;
            if (result.backup && result.masterKey) {
              const opened = unlockBackup(
                deriveKeys(result.account.username, password.value).wrapKey,
                result.backup,
              );
              state.vault = opened.vault;
              state.masterKey = opened.masterKey;
              state.envelopes = { password: result.backup.password, recovery: result.backup.recovery };
              await persistVault(false);
            } else {
              forgetLocalVault();
              initialiseVault(newVault(), {
                password: deriveKeys(result.account.username, password.value).wrapKey,
              });
              await persistVault();
            }
            await publishDevice("recovered browser");
            onReady();
          })
          .catch((error: unknown) => {
            submit.disabled = false;
            const text = error instanceof ApiError ? error.message : (error as Error).message;
            drawRecover(notice(text, "error"));
          });
      }, 30);
    });

    container.append(
      el(
        "div",
        { class: "card" },
        el("h1", {}, "Recover with your phrase"),
        el("p", { class: "lede" },
          "The words are turned into keys in this browser. They are never sent to the server — it only sees a signature that proves you hold them."),
        field("Username", username),
        field("Recovery phrase", phrase, "Order matters. Case and spacing do not."),
        field("New password", password, "At least 12 characters."),
        notice("Recovering signs out every other session, and sets this password everywhere."),
        el("div", { class: "row", style: "margin-top:16px" }, submit,
          el("button", { class: "ghost", type: "button", onclick: () => { mode = "login"; draw(); } }, "Back"),
        ),
        status,
      ),
    );
    if (message) status.append(message);
  }
}

/** Three positions spread across the phrase, so the check is not all from one corner. */
function pickPositions(words: number): number[] {
  const thirds = [
    1 + Math.floor(Math.random() * Math.floor(words / 3)),
    1 + Math.floor(words / 3) + Math.floor(Math.random() * Math.floor(words / 3)),
    1 + Math.floor((2 * words) / 3) + Math.floor(Math.random() * Math.floor(words / 3)),
  ];
  return [...new Set(thirds)].sort((a, b) => a - b);
}
