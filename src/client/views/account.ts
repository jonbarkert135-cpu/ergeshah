import { api } from "../api.ts";
import { clear, confirmDialog, el, field, notice, skeleton, table, toast } from "../ui.ts";
import {
  changePassword,
  deleteAccount,
  deriveKeys,
  forgetLocalVault,
  lock,
  privacySettings,
  sealedVaultNow,
  setPrivacy,
  state,
} from "../state.ts";
import { blockedPeers, setBlocked } from "../messaging.ts";
import { authoriseDevice, parseDeviceCode, type ParsedDeviceCode } from "../linking.ts";
import { setRecoveryPhrase } from "../recovery.ts";
import { generatePhrase } from "../../shared/crypto/mnemonic.ts";
import { toBase64Url } from "../../shared/encoding.ts";

export function renderAccount(root: HTMLElement, onSignedOut: () => void): void {
  clear(root);
  const body = el("div", {});
  root.append(el("h1", {}, "Account & devices"), body);
  void load();

  async function load() {
    clear(body).append(skeleton("line", 5));
    const me = await api<{
      username: string;
      role: string;
      memberSince: string | null;
      recoveryConfigured: boolean;
      pgpFingerprint: string | null;
    }>("/api/auth/me");
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
        el("h2", { class: "tight" }, `@${me.username}`),
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
    const rows = sessions.sessions.map((session) => {
      const revoke = el("button", { type: "button", class: "ghost" }, session.current ? "current" : "Revoke");
      if (session.current) revoke.setAttribute("disabled", "");
      else
        revoke.addEventListener("click", () => {
          void api(`/api/auth/sessions/${session.id}`, { method: "DELETE" }).then(() => void load());
        });
      return [session.label ?? "—", el("span", { class: "mono" }, session.lastSeenOn), el("span", { class: "mono" }, session.expiresOn), revoke];
    });
    const table_ = table(["Label", "Last seen", "Expires", "Actions"], rows, { caption: "Signed-in sessions" });
    body.append(table_);

    body.append(
      el(
        "div",
        { class: "row spaced" },
        el("button", { onclick: () => void signOut(false) }, "Sign out"),
        el("button", { class: "danger", onclick: () => void signOutEverywhere() }, "Sign out everywhere"),
        el("button", { class: "danger", onclick: () => void signOut(true) }, "Sign out and wipe this device"),
      ),
      notice(
        "Wiping removes the encrypted vault from this browser. Your messages exist nowhere else, so they are gone unless you can restore the sealed backup with your password.",
      ),
      notice(
        "Lost a device? Revoking it stops messages reaching it, but a session it left signed in keeps working until it is revoked here — or sign out everywhere, which ends all of them at once.",
      ),
    );

    body.append(el("h2", {}, "Metadata you emit"), privacyCard());
    body.append(el("h2", {}, "Recovery phrase"), recoveryCard(me.recoveryConfigured));
    body.append(el("h2", {}, "PGP key"), pgpCard(me.username, me.pgpFingerprint));
    body.append(el("h2", {}, "Link a device"), linkCard());
    body.append(el("h2", {}, "Password"), passwordCard());
    body.append(el("h2", {}, "Delete account"), deleteCard());
  }

  /**
   * A PGP key as a second factor. The private half never comes near this code: the server
   * issues a challenge, the user signs it with their own `gpg`, and only the signature and
   * the public key travel back.
   */
  function pgpCard(username: string, fingerprint: string | null): HTMLElement {
    const holder = el("div", {});
    const message = el("div", {});
    const action = el("button", {}, fingerprint ? "Replace this key" : "Add a PGP key");
    const password = () => el("input", { type: "password", placeholder: "Your password" });

    action.addEventListener("click", () => {
      const publicKey = el("textarea", {
        rows: "7",
        class: "mono",
        placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
        spellcheck: "false",
      });
      const next = el("button", { class: "primary" }, "Continue");
      clear(holder).append(
        field("Your public key", publicKey),
        notice("Only the public key. If you paste a private key it will be refused, not stored."),
        el("div", { class: "row" }, next),
      );

      next.addEventListener("click", () => {
        next.setAttribute("disabled", "");
        clear(message);
        void api<{ challengeId: string; challenge: string }>("/api/auth/pgp/challenge", {
          method: "POST",
          body: {},
        })
          .then((challenge) => {
            const signature = el("textarea", {
              rows: "7",
              class: "mono",
              placeholder: "-----BEGIN PGP SIGNATURE-----",
              spellcheck: "false",
            });
            const pw = password();
            const confirm = el("button", { class: "primary" }, "Enable PGP sign-in");
            clear(holder).append(
              el("p", { class: "muted" }, "Sign these bytes with that key:"),
              el("pre", { class: "mono block" }, challenge.challenge),
              el("pre", { class: "mono block" },
                `printf %s '${challenge.challenge}' | gpg --detach-sign --armor`),
              field("Signature", signature),
              el("div", { class: "row" }, pw, confirm),
            );
            confirm.addEventListener("click", () => {
              confirm.setAttribute("disabled", "");
              clear(message);
              void api<{ fingerprint: string }>("/api/auth/pgp/key", {
                method: "POST",
                body: {
                  authSecret: toBase64Url(
                    deriveKeys(username, (pw as HTMLInputElement).value).authSecret,
                  ),
                  publicKey: (publicKey as HTMLTextAreaElement).value,
                  challengeId: challenge.challengeId,
                  signature: (signature as HTMLTextAreaElement).value,
                },
              })
                .then(() => {
                  clear(holder);
                  void load();
                })
                .catch((error: Error) => {
                  message.append(notice(error.message, "error"));
                  confirm.removeAttribute("disabled");
                });
            });
          })
          .catch((error: Error) => {
            message.append(notice(error.message, "error"));
            next.removeAttribute("disabled");
          });
      });
    });

    const off = el("button", { class: "danger" }, "Turn off PGP sign-in");
    off.addEventListener("click", () => {
      const pw = password();
      const confirm = el("button", { class: "danger" }, "Confirm");
      clear(holder).append(el("div", { class: "row" }, pw, confirm));
      confirm.addEventListener("click", () => {
        confirm.setAttribute("disabled", "");
        void api("/api/auth/pgp/remove", {
          method: "POST",
          body: {
            authSecret: toBase64Url(
              deriveKeys(username, (pw as HTMLInputElement).value).authSecret,
            ),
          },
        })
          .then(() => {
            clear(holder);
            void load();
          })
          .catch((error: Error) => {
            message.append(notice(error.message, "error"));
            confirm.removeAttribute("disabled");
          });
      });
    });

    return el(
      "div",
      { class: "card" },
      el("p", { class: "muted tight" },
        fingerprint
          ? "Signing in to this account needs your password and a signature from this key."
          : "Add a PGP key to require a signature as well as a password when signing in. The key never leaves your machine — the server sends a challenge and checks the signature."),
      fingerprint ? el("p", { class: "mono" }, fingerprint) : el("span", {}),
      el("div", { class: "row" }, action, ...(fingerprint ? [off] : [])),
      holder,
      message,
    );
  }

  /**
   * Recovery status, and a way to attach a phrase to an account that has none. The phrase
   * is generated here, shown once, confirmed here, and never sent to the server — only a
   * public key derived from it, plus a copy of the master key wrapped with it.
   */
  /**
   * The three signals this product can emit about you, and the switch for each (points
   * 75-77). All three are off until turned on, all three are messages between two clients
   * rather than server state, and the settings themselves are kept in the encrypted vault —
   * a preference stored server-side would be one more fact about you on the server.
   */
  function privacyCard(): HTMLElement {
    const settings = privacySettings();
    const card = el(
      "div",
      { class: "card" },
      el(
        "p",
        { class: "muted" },
        "Nothing here is on by default. Each one is an ordinary encrypted message to the person you are talking to — the server cannot read it, and cannot tell it apart from anything else you send. That is also the cost: every signal is one more envelope the operator sees you send.",
      ),
    );

    const toggle = (
      label: string,
      hint: string,
      on: boolean,
      apply: (value: boolean) => Promise<void>,
    ) => {
      const button = el(
        "button",
        { type: "button", class: on ? "primary" : "ghost", "aria-pressed": on ? "true" : "false" },
        on ? "On" : "Off",
      );
      button.addEventListener("click", () => {
        button.disabled = true;
        void apply(!on)
          .then(() => load())
          .catch((error: Error) => toast(error.message, "error"));
      });
      return el("div", { class: "row spaced" }, el("div", {}, el("strong", {}, label), el("div", { class: "muted" }, hint)), button);
    };

    card.append(
      toggle(
        "Read receipts",
        "Tell people when you have read what they wrote.",
        settings.readReceipts,
        (value) => setPrivacy({ readReceipts: value }),
      ),
      toggle(
        "Typing indicators",
        "Tell the person you are writing to that you are typing. Sends an envelope every few seconds while you type.",
        settings.typingIndicators,
        (value) => setPrivacy({ typingIndicators: value }),
      ),
    );

    const choices: Array<[string, number | null]> = [
      ["Keep until deleted", null],
      ["1 hour", 1],
      ["24 hours", 24],
      ["7 days", 168],
      ["30 days", 720],
    ];
    const select = el(
      "select",
      { name: "disappear", "aria-label": "Default disappearing-message lifetime" },
      ...choices.map(([label, value]) =>
        el("option", { value: String(value), ...(value === settings.disappearHours ? { selected: true } : {}) }, label),
      ),
    ) as HTMLSelectElement;
    select.addEventListener("change", () => {
      const value = select.value === "null" ? null : Number(select.value);
      void setPrivacy({ disappearHours: value })
        .then(() => toast("Saved. New conversations use this; existing ones keep their own setting."))
        .catch((error: Error) => toast(error.message, "error"));
    });
    card.append(
      field(
        "Disappearing messages, by default",
        select,
        "Both sides delete the message when the time is up, and the server is asked to drop an undelivered copy at the same hour. It cannot stop someone copying what they can already read.",
      ),
    );

    const blocked = blockedPeers();
    card.append(
      el("h3", { class: "tight" }, "Blocked"),
      blocked.length === 0
        ? el("p", { class: "muted" }, "Nobody. Blocking happens in a conversation, and stays in this browser — the server is never told.")
        : el(
            "div",
            { class: "row" },
            ...blocked.map((peer) => {
              const button = el("button", { type: "button", class: "ghost" }, `${peer} · unblock`);
              button.addEventListener("click", () => {
                button.disabled = true;
                void setBlocked(peer, false)
                  .then(() => load())
                  .catch((error: Error) => toast(error.message, "error"));
              });
              return button;
            }),
          ),
    );
    return card;
  }

  function recoveryCard(configured: boolean): HTMLElement {
    const message = el("div", { class: "muted" });
    const holder = el("div", {});
    const add = el("button", {}, configured ? "Replace the recovery phrase" : "Create a recovery phrase");

    add.addEventListener("click", () => {
      const phrase = generatePhrase(24);
      const words = phrase.split(" ");
      const grid = el("div", { class: "phrase" });
      words.forEach((word, index) =>
        grid.append(el("div", { class: "phrase-word" },
          el("span", { class: "phrase-index" }, String(index + 1)),
          el("span", { class: "mono" }, word)),
        ),
      );
      const password = el("input", { type: "password", placeholder: "Your password" });
      const confirm = el("button", { class: "primary" }, "I have written it down");

      confirm.addEventListener("click", () => {
        if (!state.account || !state.masterKey || !state.envelopes) {
          message.textContent = "Unlock the vault first.";
          return;
        }
        confirm.setAttribute("disabled", "");
        message.textContent = "Deriving keys from the phrase…";
        const backup = {
          v: 3 as const,
          vault: sealedVaultNow(),
          password: state.envelopes.password,
          recovery: state.envelopes.recovery ?? null,
        };
        void setRecoveryPhrase(
          state.account.username,
          (password as HTMLInputElement).value,
          phrase,
          state.masterKey,
          backup,
        )
          .then((updated) => {
            state.envelopes = { password: updated.password, recovery: updated.recovery };
            clear(holder);
            message.textContent = "Recovery phrase active. It will not be shown again.";
            void load();
          })
          .catch((error: Error) => {
            message.textContent = error.message;
            confirm.removeAttribute("disabled");
          });
      });

      clear(holder).append(
        grid,
        notice(
          "Written on paper, kept private. Anyone with these words can take this account and read its history; if you lose them together with your password, nobody can restore access.",
        ),
        el("div", { class: "row" }, password, confirm),
      );
    });

    return el(
      "div",
      { class: "card" },
      el("p", { class: "muted tight" },
        configured
          ? "A recovery phrase is active on this account. The words themselves were shown once and are not stored anywhere — replacing them invalidates the old phrase."
          : "This account has no recovery phrase. Without one, a forgotten password cannot be recovered: there is no email reset and no administrator override."),
      el("div", { class: "row" }, add),
      holder,
      message,
    );
  }

  /** Read a code from a new device, check its fingerprint, then vouch for its keys. */
  function linkCard(): HTMLElement {
    const codeBox = el("textarea", { rows: "4", class: "mono", placeholder: "symvolon-link.v1…" });
    const label = el("input", { placeholder: "Label, e.g. laptop", maxlength: "40" });
    const message = el("div", { class: "muted" });
    const authorise = el("button", {}, "Authorise this device");
    let parsed: ParsedDeviceCode | null = null;

    codeBox.addEventListener("input", () => {
      const value = (codeBox as HTMLTextAreaElement).value.trim();
      if (!value) {
        parsed = null;
        message.textContent = "";
        return;
      }
      try {
        parsed = parseDeviceCode(value);
        message.textContent = `Fingerprint: ${parsed.fingerprint} — it must match the other screen exactly.`;
      } catch (error) {
        parsed = null;
        message.textContent = (error as Error).message;
      }
    });

    authorise.addEventListener("click", () => {
      if (!parsed) {
        message.textContent = "Paste the code from the new device first.";
        return;
      }
      const fingerprint = parsed.fingerprint;
      void confirmDialog({
        title: "Authorise this device?",
        body: `Fingerprint ${fingerprint}. From now on it receives every message sent to you. Compare the fingerprint on the other screen before you agree.`,
        confirmLabel: "Authorise",
      }).then((agreed) => {
        if (agreed) authoriseNow();
      });
    });

    function authoriseNow(): void {
      if (!parsed) return;
      authorise.setAttribute("disabled", "");
      void authoriseDevice(parsed, (label as HTMLInputElement).value.trim() || "linked device")
        .then(() => {
          message.textContent = "Authorised. The other device has five minutes to finish.";
          (codeBox as HTMLTextAreaElement).value = "";
          parsed = null;
          void load();
        })
        .catch((error: Error) => {
          message.textContent = error.message;
        })
        .finally(() => authorise.removeAttribute("disabled"));
    }

    return el(
      "div",
      { class: "card" },
      el("p", { class: "muted tight" },
        "A second browser gets its own keys rather than a copy of these — two devices sharing one identity would break your conversations. On the new device choose \"Link this browser\", then paste its code here."),
      codeBox,
      el("div", { class: "row spaced" }, label, authorise),
      message,
    );
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
      el("p", { class: "muted tight" },
        "Your password unlocks the vault holding your private keys, so changing it re-encrypts the vault in this browser and replaces the sealed backup. Every other session is signed out."),
      el("div", { class: "row" }, current, next, again),
      el("div", { class: "row spaced" }, button, message),
    );
  }

  function deleteCard(): HTMLElement {
    const password = el("input", { type: "password", placeholder: "Password" });
    const message = el("div", { class: "muted" });
    const button = el("button", { class: "danger" }, "Delete my account");

    button.addEventListener("click", () => {
      void confirmDialog({
        title: "Delete this account for good?",
        body: "Messages, listings, orders and reviews go with it, the username becomes available to someone else, and none of it is recoverable.",
        confirmLabel: "Delete everything",
        danger: true,
      }).then((agreed) => {
        if (agreed) remove();
      });
    });

    function remove(): void {
      button.setAttribute("disabled", "");
      void deleteAccount((password as HTMLInputElement).value)
        .then(() => onSignedOut())
        .catch((error: Error) => {
          message.textContent = error.message;
          button.removeAttribute("disabled");
        });
    }

    return el(
      "div",
      { class: "card" },
      el("p", { class: "muted tight" },
        "This removes the account, the sealed vault, every device and prekey, undelivered messages, listings, orders and reviews. Moderation records stay, without your identity attached. Nothing here is recoverable."),
      el("div", { class: "row" }, password, button),
      message,
    );
  }

  function revokeButton(deviceId: string): HTMLElement {
    const button = el("button", { class: "danger" }, "Revoke device");
    button.addEventListener("click", () => {
      void confirmDialog({
        title: "Revoke this device?",
        body:
          "It stops receiving messages immediately, anything already waiting for it is deleted, " +
          "and that device identity can never be published again. Sessions signed in on it are " +
          "separate: end those under Sessions, or with \u201CSign out everywhere\u201D.",
        confirmLabel: "Revoke",
        danger: true,
      }).then(async (agreed) => {
        if (!agreed) return;
        await api("/api/keys/revoke", { method: "POST", body: { deviceId } });
        toast("Device revoked");
        void load();
      });
    });
    return button;
  }

  /** Ends every session of the account, including this one — the stolen-device button. */
  async function signOutEverywhere() {
    const agreed = await confirmDialog({
      title: "Sign out everywhere?",
      body: "Every signed-in session ends, on this device and on all the others. The encrypted vault stays in this browser.",
      confirmLabel: "Sign out everywhere",
      danger: true,
    });
    if (!agreed) return;
    await api("/api/auth/logout-everywhere", { method: "POST" }).catch(() => undefined);
    lock();
    onSignedOut();
  }

  async function signOut(wipe: boolean) {
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    if (wipe) forgetLocalVault();
    lock();
    onSignedOut();
  }
}

