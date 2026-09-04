/**
 * The account screen: who you are here, which devices hold your keys, what this product
 * can emit about you, and the door out. Anything that changes a credential — the password,
 * the PGP key, the recovery phrase, the sessions — lives in the security centre
 * (`views/security.ts`) instead, so there is one screen to check rather than two.
 */
import { api } from "../api.ts";
import { clear, confirmDialog, el, field, skeleton, toast } from "../ui.ts";
import { deleteAccount, privacySettings, setPrivacy } from "../state.ts";
import { blockedPeers, setBlocked } from "../messaging.ts";
import { authoriseDevice, parseDeviceCode, type ParsedDeviceCode } from "../linking.ts";

export function renderAccount(root: HTMLElement, onSignedOut: () => void): void {
  clear(root);
  const body = el("div", {});
  root.append(el("h1", {}, "Account & devices"), body);
  void load();

  async function load() {
    clear(body).append(skeleton("line", 5));
    const me = await api<{ username: string; role: string; memberSince: string | null }>(
      "/api/auth/me",
    );
    const keys = await api<{
      devices: Array<{
        deviceId: string;
        label: string | null;
        signedPreKeyAgeDays: number;
        signedPreKeyStale: boolean;
        oneTimePreKeysAvailable: number;
      }>;
    }>("/api/keys/status");
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
            `signed prekey age: ${device.signedPreKeyAgeDays}d${device.signedPreKeyStale ? " (rotating on next load)" : ""} · one-time prekeys left: ${device.oneTimePreKeysAvailable}`,
          ),
          revokeButton(device.deviceId),
        ),
      );
    }

    body.append(
      el(
        "div",
        { class: "card" },
        el("h2", { class: "tight" }, "Security centre"),
        el(
          "p",
          { class: "muted" },
          "Your password, PGP key, recovery phrase, signed-in sessions and security history are on their own screen.",
        ),
        el("div", { class: "row" }, el("a", { class: "button", href: "#/security" }, "Open security")),
      ),
    );

    body.append(el("h2", {}, "Metadata you emit"), privacyCard());
    body.append(el("h2", {}, "Link a device"), linkCard());
    body.append(el("h2", {}, "Delete account"), deleteCard());
  }

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
      toggle(
        "Delay delivery",
        "Hold each message on the server for a random 15 seconds to 2 minutes before it can be collected, " +
          "so a send and the fetch that follows it cannot be matched by their timing. Your messages arrive later.",
        settings.delayDelivery,
        (value) => setPrivacy({ delayDelivery: value }),
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

}

