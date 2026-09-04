/**
 * The security centre.
 *
 * One screen for the five things a person needs to be able to check without reading a
 * manual: what protects this account, which key it trusts, whether a way back exists, who
 * is signed in, and what has happened lately. Everything here is either public material
 * (a fingerprint) or a fact about state (a phrase exists) — no secret is ever shown twice,
 * and the words that would let someone back in are shown exactly once, at the moment they
 * are created, on another screen.
 */
import { api } from "../api.ts";
import { clear, confirmDialog, el, field, notice, skeleton, table, toast } from "../ui.ts";
import {
  changePassword,
  deriveKeys,
  forgetLocalVault,
  lock,
  sealedVaultNow,
  state,
} from "../state.ts";
import { setRecoveryPhrase } from "../recovery.ts";
import { generatePhrase } from "../../shared/crypto/mnemonic.ts";
import { toBase64Url } from "../../shared/encoding.ts";

interface Me {
  username: string;
  recoveryConfigured: boolean;
  pgpFingerprint: string | null;
}

interface SessionRow {
  id: string;
  label: string | null;
  current: boolean;
  lastSeenOn: string;
  expiresOn: string;
}

interface Challenge {
  challengeId: string;
  challenge: string;
  purpose: string;
  currentKeySignatureRequired: boolean;
  expiresInSeconds: number;
}

/** What each recorded event means, in the words a person would use about themselves. */
const EVENT_LABELS: Record<string, string> = {
  "login.password": "Signed in with a password",
  "login.pgp": "Signed in with a password and a PGP signature",
  "login.failed": "A sign-in was refused: wrong password",
  "login.device": "A linked device signed in",
  "password.changed": "Password changed",
  "pgp.enrolled": "PGP key added",
  "pgp.rotated": "PGP key replaced",
  "pgp.removed": "PGP key removed",
  "recovery.key_set": "Recovery phrase set or replaced",
  "recovery.completed": "Account recovered with the recovery phrase",
  "session.revoked": "A session was revoked",
  "sessions.revoked_all": "Signed out everywhere",
  "device.revoked": "A device was revoked",
};

export function renderSecurity(root: HTMLElement, onSignedOut: () => void): void {
  clear(root);
  const body = el("div", {});
  root.append(el("h1", {}, "Security"), body);
  void load();

  async function load(): Promise<void> {
    clear(body).append(skeleton("line", 5));
    const me = await api<Me>("/api/auth/me");
    const sessions = await api<{ sessions: SessionRow[] }>("/api/auth/sessions");
    const history = await api<{
      retentionDays: number;
      events: Array<{ kind: string; on: string; count: number }>;
    }>("/api/auth/security-events");
    clear(body);

    body.append(
      statusCard(me, sessions.sessions.length),
      el("h2", {}, "Sign-in key (PGP)"),
      pgpCard(me),
      el("h2", {}, "Recovery phrase"),
      recoveryCard(me.recoveryConfigured),
      el("h2", {}, "Password"),
      passwordCard(),
      el("h2", {}, "Sessions"),
      sessionsCard(sessions.sessions),
      el("h2", {}, "Recent security events"),
      eventsCard(history),
    );
  }

  /** The whole account, in five lines: what is on, what is off, what that costs. */
  function statusCard(me: Me, sessionCount: number): HTMLElement {
    const row = (label: string, value: string, good: boolean) =>
      el(
        "div",
        { class: "row spaced" },
        el("div", {}, el("strong", {}, label)),
        el("div", { class: good ? "muted" : "muted" }, value),
      );
    return el(
      "div",
      { class: "card" },
      el("h2", { class: "tight" }, `@${me.username}`),
      el(
        "p",
        { class: "muted" },
        "No email address, no phone number, no recovery question. What protects this account is what is listed here, and nothing else — there is no support desk that can override any of it.",
      ),
      row("Password", "set — stretched in this browser, never sent", true),
      row(
        "PGP second factor",
        me.pgpFingerprint ? "on — a signature is required to sign in" : "off",
        Boolean(me.pgpFingerprint),
      ),
      row(
        "Recovery phrase",
        me.recoveryConfigured ? "set — the only way back if you forget the password" : "not set",
        me.recoveryConfigured,
      ),
      row("Signed-in sessions", String(sessionCount), true),
    );
  }

  /**
   * A PGP key as a second factor. The private half never comes near this code: the server
   * issues a challenge naming itself, this purpose and an expiry, the user signs those bytes
   * with their own `gpg`, and only the signature and the public key travel back.
   *
   * Replacing a key needs a signature from the key being replaced, and removing one needs a
   * signature from the key being removed — so a stolen session and a stolen password cannot
   * quietly take the factor off. Lost the key itself? The recovery phrase clears it.
   */
  function pgpCard(me: Me): HTMLElement {
    const holder = el("div", {});
    const message = el("div", {});
    const action = el("button", {}, me.pgpFingerprint ? "Replace this key" : "Add a PGP key");
    const password = () => el("input", { type: "password", placeholder: "Your password" });

    const signingInstructions = (challenge: Challenge, who: string) =>
      el(
        "div",
        {},
        el("p", { class: "muted" }, `Sign these exact bytes with ${who}:`),
        el("pre", { class: "mono block" }, challenge.challenge),
        el(
          "pre",
          { class: "mono block" },
          `printf %s '${challenge.challenge}' | gpg --detach-sign --armor`,
        ),
        el(
          "p",
          { class: "muted" },
          "The line names this service, what the signature authorises and when it stops being valid, so it cannot be reused for anything else. It expires in five minutes.",
        ),
      );

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
        void api<Challenge>("/api/auth/pgp/challenge", { method: "POST", body: { intent: "key" } })
          .then((challenge) => {
            const signature = armourBox("-----BEGIN PGP SIGNATURE----- (new key)");
            const currentSignature = armourBox("-----BEGIN PGP SIGNATURE----- (current key)");
            const pw = password();
            const confirm = el(
              "button",
              { class: "primary" },
              challenge.currentKeySignatureRequired ? "Replace the key" : "Enable PGP sign-in",
            );
            clear(holder).append(
              signingInstructions(
                challenge,
                challenge.currentKeySignatureRequired
                  ? "the new key — and then again with the key it replaces"
                  : "that key",
              ),
              field("Signature from the new key", signature),
              challenge.currentKeySignatureRequired
                ? field(
                    "Signature from the key you are replacing",
                    currentSignature,
                    "Proof that you still hold the key on this account. Without it, anyone with your password could swap the factor out.",
                  )
                : el("span", {}),
              el("div", { class: "row" }, pw, confirm),
            );
            confirm.addEventListener("click", () => {
              confirm.setAttribute("disabled", "");
              clear(message);
              void api<{ fingerprint: string }>("/api/auth/pgp/key", {
                method: "POST",
                body: {
                  authSecret: toBase64Url(
                    deriveKeys(me.username, (pw as HTMLInputElement).value).authSecret,
                  ),
                  publicKey: (publicKey as HTMLTextAreaElement).value,
                  challengeId: challenge.challengeId,
                  signature: (signature as HTMLTextAreaElement).value,
                  ...(challenge.currentKeySignatureRequired
                    ? { currentSignature: (currentSignature as HTMLTextAreaElement).value }
                    : {}),
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
      clear(message);
      void api<Challenge>("/api/auth/pgp/challenge", {
        method: "POST",
        body: { intent: "remove" },
      })
        .then((challenge) => {
          const signature = armourBox("-----BEGIN PGP SIGNATURE-----");
          const pw = password();
          const confirm = el("button", { class: "danger" }, "Remove the key");
          clear(holder).append(
            signingInstructions(challenge, "the key you are removing"),
            field("Signature", signature),
            el("div", { class: "row" }, pw, confirm),
          );
          confirm.addEventListener("click", () => {
            confirm.setAttribute("disabled", "");
            void api("/api/auth/pgp/remove", {
              method: "POST",
              body: {
                authSecret: toBase64Url(
                  deriveKeys(me.username, (pw as HTMLInputElement).value).authSecret,
                ),
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
        .catch((error: Error) => message.append(notice(error.message, "error")));
    });

    return el(
      "div",
      { class: "card" },
      el(
        "p",
        { class: "muted tight" },
        me.pgpFingerprint
          ? "Signing in to this account needs your password and a signature from this key."
          : "Add a PGP key to require a signature as well as a password when signing in. The key never leaves your machine — the server sends a challenge and checks the signature.",
      ),
      me.pgpFingerprint
        ? el(
            "div",
            {},
            el("div", { class: "muted" }, "Fingerprint, in full — compare it with `gpg --fingerprint`:"),
            el("p", { class: "mono" }, me.pgpFingerprint),
          )
        : el("span", {}),
      el("div", { class: "row" }, action, ...(me.pgpFingerprint ? [off] : [])),
      me.pgpFingerprint
        ? notice(
            "A signature proves you hold the private key. It does not prove you are on the right site: check the address bar, and keep the key on a machine you trust.",
          )
        : el("span", {}),
      holder,
      message,
    );
  }

  function armourBox(placeholder: string): HTMLElement {
    return el("textarea", { rows: "7", class: "mono", placeholder, spellcheck: "false" });
  }

  /**
   * Recovery status, and a way to attach a phrase to an account that has none. The phrase
   * is generated here, shown once, confirmed here, and never sent to the server — only a
   * public key derived from it, plus a copy of the master key wrapped with it.
   */
  function recoveryCard(configured: boolean): HTMLElement {
    const message = el("div", { class: "muted" });
    const holder = el("div", {});
    const add = el("button", {}, configured ? "Replace the recovery phrase" : "Create a recovery phrase");

    add.addEventListener("click", () => {
      const phrase = generatePhrase(24);
      const words = phrase.split(" ");
      const grid = el("div", { class: "phrase" });
      words.forEach((word, index) =>
        grid.append(
          el(
            "div",
            { class: "phrase-word" },
            el("span", { class: "phrase-index" }, String(index + 1)),
            el("span", { class: "mono" }, word),
          ),
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
      el(
        "p",
        { class: "muted tight" },
        configured
          ? "A recovery phrase is active on this account. The words themselves were shown once and are not stored anywhere — replacing them invalidates the old phrase. It is also the way back if you lose your PGP key: recovering clears the second factor and ends every session."
          : "This account has no recovery phrase. Without one, a forgotten password cannot be recovered: there is no email reset and no administrator override.",
      ),
      el("div", { class: "row" }, add),
      holder,
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
      const values = [current, next, again].map((entry) => (entry as HTMLInputElement).value);
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
          for (const entry of [current, next, again]) (entry as HTMLInputElement).value = "";
          void load();
        })
        .catch((error: Error) => {
          message.textContent = error.message;
        })
        .finally(() => button.removeAttribute("disabled"));
    });

    return el(
      "div",
      { class: "card" },
      el(
        "p",
        { class: "muted tight" },
        "Your password unlocks the vault holding your private keys, so changing it re-encrypts the vault in this browser and replaces the sealed backup. Every other session, every pending challenge and every unused device code is invalidated.",
      ),
      el("div", { class: "row" }, current, next, again),
      el("div", { class: "row spaced" }, button, message),
    );
  }

  function sessionsCard(sessions: SessionRow[]): HTMLElement {
    const rows = sessions.map((session) => {
      const revoke = el(
        "button",
        { type: "button", class: "ghost" },
        session.current ? "current" : "Revoke",
      );
      if (session.current) revoke.setAttribute("disabled", "");
      else
        revoke.addEventListener("click", () => {
          void api(`/api/auth/sessions/${session.id}`, { method: "DELETE" }).then(() => void load());
        });
      return [
        session.label ?? "—",
        el("span", { class: "mono" }, session.lastSeenOn),
        el("span", { class: "mono" }, session.expiresOn),
        revoke,
      ];
    });

    return el(
      "div",
      { class: "card" },
      el(
        "p",
        { class: "muted tight" },
        "A label you chose, the day it was last used and the day it expires. No addresses, no locations, no device fingerprints — the server does not keep them.",
      ),
      table(["Label", "Last seen", "Expires", "Actions"], rows, { caption: "Signed-in sessions" }),
      el(
        "div",
        { class: "row spaced" },
        el("button", { onclick: () => void signOut(false) }, "Sign out"),
        el("button", { class: "danger", onclick: () => void signOutEverywhere() }, "Sign out everywhere"),
        el("button", { class: "danger", onclick: () => void signOut(true) }, "Sign out and wipe this device"),
      ),
      notice(
        "Lost a device? Revoking its session stops it acting as you. Stopping it receiving messages is a separate step, under Account → Devices.",
      ),
    );
  }

  function eventsCard(history: {
    retentionDays: number;
    events: Array<{ kind: string; on: string; count: number }>;
  }): HTMLElement {
    if (history.events.length === 0) {
      return el(
        "div",
        { class: "card" },
        el("p", { class: "muted tight" }, "Nothing recorded yet."),
      );
    }
    const rows = history.events.map((event) => [
      el("span", { class: "mono" }, event.on),
      EVENT_LABELS[event.kind] ?? event.kind,
      el("span", { class: "mono" }, String(event.count)),
    ]);
    return el(
      "div",
      { class: "card" },
      table(["Day", "Event", "Times"], rows, { caption: "Your account's security history" }),
      el(
        "p",
        { class: "muted" },
        `Counted by day, kept for ${history.retentionDays} days, and visible to you alone. No addresses, no devices, no times of day: enough to notice something you did not do, not enough to reconstruct what you did.`,
      ),
    );
  }

  /** Ends every session of the account, including this one — the stolen-device button. */
  async function signOutEverywhere(): Promise<void> {
    const agreed = await confirmDialog({
      title: "Sign out everywhere?",
      body: "Every signed-in session ends, on this device and on all the others, along with any pending challenge or unused device code. The encrypted vault stays in this browser.",
      confirmLabel: "Sign out everywhere",
      danger: true,
    });
    if (!agreed) return;
    await api("/api/auth/logout-everywhere", { method: "POST" }).catch(() => undefined);
    lock();
    onSignedOut();
  }

  async function signOut(wipe: boolean): Promise<void> {
    if (wipe) {
      const agreed = await confirmDialog({
        title: "Wipe this browser?",
        body: "The encrypted vault is removed from this device. Your messages exist nowhere else, so they are gone unless you can restore the sealed backup with your password.",
        confirmLabel: "Sign out and wipe",
        danger: true,
      });
      if (!agreed) return;
    }
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    if (wipe) forgetLocalVault();
    lock();
    onSignedOut();
    toast("Signed out");
  }
}
