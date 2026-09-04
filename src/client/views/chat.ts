import { clear, confirmDialog, el, emptyState, formDialog, notice, toast } from "../ui.ts";
import {
  conversations,
  deleteConversation,
  deleteMessage,
  disappearHours,
  isBlocked,
  openAttachment,
  peerIsTyping,
  pruneExpired,
  receiveMessages,
  searchMessages,
  sendAttachment,
  sendMessage,
  sendReadReceipt,
  sendTyping,
  setBlocked,
  signalRevision,
  setDisappearing,
  startConversation,
} from "../messaging.ts";
import { persistVault, state } from "../state.ts";
import type { AttachmentRef, ChatMessage, Conversation } from "../state.ts";
import { MAX_FILE_BYTES } from "../../shared/crypto/file.ts";
import { safeFileName } from "../../shared/uploads.ts";
import {
  acknowledgeKeyChange,
  markVerified,
  peerDevices,
  verificationState,
} from "../verification.ts";
import { qrSvg } from "../../shared/qr.ts";

let selectedChannel: string | null = null;

/** Disappearing-message choices, in hours. Anything finer is a false sense of precision. */
const DISAPPEAR_CHOICES: Array<[string, number | null]> = [
  ["Keep until deleted", null],
  ["1 hour", 1],
  ["24 hours", 24],
  ["7 days", 168],
  ["30 days", 720],
];

function hoursLabel(hours: number): string {
  return DISAPPEAR_CHOICES.find(([, value]) => value === hours)?.[0] ?? `${hours} hours`;
}

/** Hands decrypted bytes to the browser's download machinery. Never rendered in the page. */
function save(bytes: Uint8Array, name: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
  const link = el("a", { href: url, download: safeFileName(name) });
  link.click();
  URL.revokeObjectURL(url);
}

export function renderChat(root: HTMLElement): void {
  clear(root);
  let query = "";
  const list = el("nav", { class: "list", "aria-label": "Conversations" });
  const panel = el("section", { "aria-label": "Conversation" });
  root.append(
    el("h1", {}, "Messages"),
    el(
      "p",
      { class: "lede" },
      "Everything here is encrypted in your browser. The server stores ciphertext addressed to a device, deletes it on delivery, and is never told who sent it.",
    ),
    el("div", { class: "chat" }, list, panel),
  );
  drawList();
  drawPanel();

  function drawList() {
    clear(list);
    // Search runs here, in the browser, over messages this device has already decrypted
    // (point 79). There is no server-side search of private messages and no route that
    // could offer one.
    const search = el("input", {
      type: "search",
      name: "q",
      placeholder: "Search your messages…",
      "aria-label": "Search your messages (this device only)",
      maxlength: "80",
      autocomplete: "off",
      value: query,
    }) as HTMLInputElement;
    search.addEventListener("input", () => {
      query = search.value;
      drawList();
      // Focus survives the redraw: retyping into a box that lost the cursor is not search.
      search.focus();
      search.setSelectionRange(search.value.length, search.value.length);
    });
    list.append(
      el(
        "button",
        { type: "button", class: "primary", onclick: () => void newConversation() },
        "New conversation",
      ),
      search,
    );

    if (query.trim()) {
      const hits = searchMessages(query);
      list.append(
        el(
          "p",
          { class: "muted" },
          hits.length === 0
            ? "Nothing on this device matches."
            : `${hits.length} on this device${hits.length === 50 ? " (first 50)" : ""}`,
        ),
      );
      for (const hit of hits) {
        list.append(
          el(
            "button",
            {
              onclick: () => {
                selectedChannel = hit.channel;
                drawPanel();
              },
            },
            el("strong", {}, hit.peer),
            el("span", { class: "muted mono" }, ` ${hit.message.text.slice(0, 40)}`),
          ),
        );
      }
      return;
    }

    const items = conversations();
    if (items.length === 0) {
      list.append(el("p", { class: "muted" }, "No conversations yet."));
    }
    for (const conversation of items) {
      const last = conversation.messages.at(-1);
      list.append(
        el(
          "button",
          {
            onclick: () => {
              selectedChannel = conversation.channel;
              drawList();
              drawPanel();
            },
            ...(selectedChannel === conversation.channel ? { "aria-current": "page" } : {}),
          },
          el("strong", {}, conversation.peer),
          isBlocked(conversation.peer) ? el("span", { class: "tag" }, "blocked") : null,
          el("span", { class: "muted mono" }, last ? ` ${last.text.slice(0, 22)}` : " —"),
        ),
      );
    }
  }

  function drawPanel() {
    clear(panel);
    const conversation = conversations().find((item) => item.channel === selectedChannel);
    if (!conversation) {
      panel.append(
        emptyState(
          "No conversation selected",
          "Pick a conversation, or start one by username. Nothing here is stored in readable form on the server.",
        ),
      );
      return;
    }
    if (conversation.messages.length === 0) {
      panel.append(
        emptyState(
          `Nothing said yet with ${conversation.peer}`,
          "The first message establishes the encrypted session. Until then there is nothing for the server to hold.",
        ),
      );
    }
    // role="log": new messages are announced as they arrive, without moving focus.
    const messages = el("div", { class: "messages", role: "log", "aria-live": "polite", "aria-label": "Messages" });
    for (const message of conversation.messages) {
      messages.append(drawMessage(conversation, message));
    }
    const box = el("input", {
      name: "message",
      placeholder: `Message ${conversation.peer}…`,
      "aria-label": `Message ${conversation.peer}`,
      maxlength: "4000",
      autocomplete: "off",
    });
    const send = el("button", { type: "submit", class: "primary" }, "Send");
    const status = el("div", { role: "status" });
    // Typing indicators are off unless the account turned them on, and `sendTyping` is
    // what enforces that — this listener does not know or decide.
    box.addEventListener("input", () => void sendTyping(conversation).catch(() => {}));

    const picker = el("input", {
      type: "file",
      class: "hidden",
      "aria-label": "Attach a file",
    }) as HTMLInputElement;
    const attach = el("button", { type: "button", class: "ghost" }, "Attach");
    attach.addEventListener("click", () => picker.click());
    picker.addEventListener("change", () => {
      const chosen = picker.files?.[0];
      if (!chosen) return;
      if (chosen.size > MAX_FILE_BYTES) {
        status.replaceChildren(
          notice(`That file is larger than ${MAX_FILE_BYTES / (1024 * 1024)} MB.`, "error"),
        );
        return;
      }
      attach.disabled = true;
      status.replaceChildren(notice("Encrypting in this browser…"));
      void chosen
        .arrayBuffer()
        .then((buffer) => sendAttachment(conversation, new Uint8Array(buffer), chosen.name))
        .then(() => {
          status.replaceChildren();
          drawPanel();
        })
        .catch((error: Error) => status.replaceChildren(notice(error.message, "error")))
        .finally(() => {
          attach.disabled = false;
          picker.value = "";
        });
    });

    // A form: Enter submits, and so does the phone keyboard's action key.
    const composer = el("form", { class: "composer" }, box, attach, send, picker);
    composer.addEventListener("submit", (event) => {
      event.preventDefault();
      const text = box.value.trim();
      if (!text) return;
      box.value = "";
      send.disabled = true;
      void sendMessage(conversation, text)
        .then(() => {
          status.replaceChildren();
          drawPanel();
          box.focus();
        })
        .catch((error: Error) => status.replaceChildren(notice(error.message, "error")))
        .finally(() => {
          send.disabled = false;
        });
    });

    const verification = verificationState(conversation);
    const hours = disappearHours(conversation);
    // A reader whose own setting is "keep" can still be in a disappearing conversation,
    // because the sender chose one. Saying so is the difference between a message that
    // vanishes and a message that vanished without warning.
    const incomingExpiry = conversation.messages.some((message) => message.expiresAt !== undefined);
    panel.append(
      el(
        "div",
        { class: "row" },
        el("h2", { class: "flush" }, conversation.peer),
        el("span", { class: "tag" }, "end-to-end encrypted"),
        verification === "verified" ? el("span", { class: "tag" }, "verified ✓") : null,
        hours === null
          ? incomingExpiry
            ? el("span", { class: "tag" }, "messages here disappear")
            : null
          : el("span", { class: "tag" }, `disappears after ${hoursLabel(hours)}`),
        // The controls travel as one group, so a narrow window wraps them together
        // instead of stranding "Delete" alone on the next line.
        el(
          "div",
          { class: "row" },
          el("button", { class: "ghost", onclick: () => drawVerification(conversation) }, "Safety number"),
          el("button", { class: "ghost", onclick: () => void chooseDisappearing(conversation) }, "Disappearing"),
          el(
            "button",
            { class: "ghost", onclick: () => void toggleBlock(conversation) },
            isBlocked(conversation.peer) ? "Unblock" : "Block",
          ),
          el("button", { class: "danger", onclick: () => void removeConversation(conversation) }, "Delete"),
        ),
      ),
      el(
        "div",
        {},
        keyChangeBanner(conversation),
        verification === "changed"
          ? notice(
              `A device in this conversation is not one you verified. That is either ${conversation.peer} adding a device, or someone else's key in its place — check the safety number before sending anything sensitive.`,
              "error",
            )
          : null,
      ),
      messages,
      el(
        "div",
        { role: "status" },
        peerIsTyping(conversation.channel) ? el("p", { class: "muted" }, `${conversation.peer} is typing…`) : null,
      ),
      composer,
      status,
    );
    messages.scrollTop = messages.scrollHeight;
    // A read receipt is sent only if this account turned them on; `sendReadReceipt`
    // decides, and it sends at most one per batch of new messages.
    void sendReadReceipt(conversation).catch(() => {});
    // Re-drawn after a send: the writer's cursor belongs back in the box.
    if (document.activeElement === document.body) box.focus();
  }

  /**
   * One message. Three things live here that are easy to get wrong: an attachment is
   * fetched and decrypted on demand rather than rendered in the page, "Read" appears only
   * because the peer chose to say so, and "Delete" removes it from *this* device — the
   * label says so, because promising anything else would be a lie (docs/DELETION.md).
   */
  function drawMessage(conversation: Conversation, message: ChatMessage): HTMLElement {
    const remove = el(
      "button",
      {
        class: "ghost small",
        "aria-label": `Delete this message from this device (${new Date(message.at).toLocaleString()})`,
      },
      "Delete",
    );
    remove.addEventListener("click", () => {
      void deleteMessage(conversation, message.id ?? "").then(() => drawPanel());
    });
    return el(
      "div",
      { class: message.mine ? "msg mine" : "msg" },
      el("span", { class: "sr-only" }, message.mine ? "You: " : `${message.from}: `),
      message.attachment ? attachmentControl(message.attachment) : message.text,
      el(
        "span",
        { class: "meta" },
        new Date(message.at).toLocaleString(),
        message.expiresAt ? ` · disappears ${new Date(message.expiresAt).toLocaleString()}` : "",
        message.mine && message.readAt ? " · read" : "",
      ),
      remove,
    );
  }

  function attachmentControl(reference: AttachmentRef): HTMLElement {
    const button = el(
      "button",
      { class: "ghost", "aria-label": `Decrypt and save ${reference.name}` },
      `${reference.name} · ${Math.max(1, Math.round(reference.bytes / 1024))} kB`,
    );
    button.addEventListener("click", () => {
      button.disabled = true;
      void openAttachment(reference)
        .then((bytes) => save(bytes, reference.name))
        .catch((error: Error) => toast(error.message, "error"))
        .finally(() => {
          button.disabled = false;
        });
    });
    return button;
  }

  async function chooseDisappearing(conversation: Conversation) {
    const answer = await formDialog({
      title: "Disappearing messages",
      body: "Both sides delete the message when the time is up, and the server is asked to drop an undelivered copy at the same hour. It is not a guarantee: a recipient can copy or screenshot anything they can read, and a device that never comes back online keeps what it already has.",
      fields: [
        {
          name: "hours",
          label: "Delete messages after",
          kind: "select",
          // The current setting first: the dialog has no "selected" concept, and a browser
          // selects the first option — so the order is what shows the current answer.
          options: [...DISAPPEAR_CHOICES]
            .sort(
              (a, b) =>
                Number(b[1] === disappearHours(conversation)) -
                Number(a[1] === disappearHours(conversation)),
            )
            .map(([label, value]) => [String(value), label] as [string, string]),
        },
      ],
      confirmLabel: "Save",
    });
    if (!answer) return;
    const chosen = answer.hours === "null" ? null : Number(answer.hours);
    await setDisappearing(conversation, chosen);
    drawPanel();
  }

  async function toggleBlock(conversation: Conversation) {
    const blocked = isBlocked(conversation.peer);
    if (
      !blocked &&
      !(await confirmDialog({
        title: `Block ${conversation.peer}?`,
        body: "Their messages are discarded by this device as they arrive, and you cannot write to them until you unblock. The server is not told: it never knew who was writing to you, and a block it could see would tell it.",
        confirmLabel: "Block",
        danger: true,
      }))
    ) {
      return;
    }
    await setBlocked(conversation.peer, !blocked);
    drawList();
    drawPanel();
  }

  async function removeConversation(conversation: Conversation) {
    const agreed = await confirmDialog({
      title: `Delete this conversation?`,
      body: "The history and the session keys are removed from this browser. Copies on your other devices, and on theirs, stay where they are — nothing here can reach them.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!agreed) return;
    await deleteConversation(conversation.channel);
    selectedChannel = null;
    drawList();
    drawPanel();
  }

  /**
   * AUTH-6: the peer's identity keys changed, and this says so until someone acknowledges
   * it. Two texts, because the two events are not equally alarming — a key added beside
   * the old ones is usually a second device, while every old key gone is what an account
   * taken over, reinstalled, or registered again by a stranger looks like from here. The
   * banner explains the innocent reading first and still asks for the comparison, since a
   * warning that only cries attack is one people learn to dismiss.
   */
  function keyChangeBanner(conversation: Conversation): HTMLElement | null {
    const change = conversation.keyChange;
    if (!change) return null;
    const dismiss = el("button", { class: "ghost" }, "Dismiss");
    dismiss.addEventListener("click", () => {
      void acknowledgeKeyChange(conversation).then(() => drawPanel());
    });
    return el(
      "div",
      { class: change.kind === "replaced" ? "notice error" : "notice", role: "alert" },
      change.kind === "replaced"
        ? `Every device ${conversation.peer} was using has been replaced since your last message. That is what a reinstall or an account recovery looks like — and also what someone else registering this username would look like. Compare the safety number before you send anything sensitive.`
        : `${conversation.peer} is using a device this conversation has not seen before. That is usually a new device of theirs; it is also what a substituted key looks like. Compare its safety number.`,
      el(
        "div",
        { class: "row" },
        el(
          "button",
          { class: "ghost", onclick: () => drawVerification(conversation) },
          "Safety number",
        ),
        dismiss,
      ),
    );
  }

  /**
   * The comparison screen: one safety number per device the peer is using, each with a
   * scannable code. Both sides must see the same digits — that is the entire protocol,
   * and it is why the code encodes exactly those digits and nothing clickable.
   */
  function drawVerification(conversation: Conversation) {
    const devices = peerDevices(conversation);
    clear(panel);
    panel.append(
      el(
        "div",
        { class: "row" },
        el("h2", { class: "flush" }, `Verify ${conversation.peer}`),
        el("button", { class: "ghost", onclick: () => drawPanel() }, "Back to messages"),
      ),
      el(
        "p",
        { class: "lede" },
        "Compare these characters with the ones on their screen, in person or over a channel this server does not carry. Scanning the code shows the same characters — it does not verify anything by itself.",
      ),
    );
    if (devices.length === 0) {
      panel.append(el("p", { class: "muted" }, "No session yet — send a message first."));
      return;
    }
    for (const device of devices) {
      const image = el("img", {
        // A data URL, so the page still loads nothing from anywhere (CSP: img-src 'self' data:).
        src: `data:image/svg+xml;base64,${btoa(qrSvg(device.safetyNumber.replace(/ /g, "")))}`,
        alt: "Safety number as a scannable code",
        width: "222",
        height: "222",
      });
      const button = el("button", { class: "primary" }, "They match — mark verified");
      button.addEventListener("click", () => {
        void markVerified(conversation, device.key).then(() => drawVerification(conversation));
      });
      panel.append(
        el(
          "div",
          { class: "verify" },
          image,
          el("div", { class: "safety-number" }, device.safetyNumber),
          device.verifiedAt
            ? el(
                "p",
                { class: "muted" },
                `Verified on ${new Date(device.verifiedAt).toLocaleDateString()}.`,
              )
            : button,
        ),
      );
    }
  }

  async function newConversation() {
    const answer = await formDialog({
      title: "New conversation",
      fields: [{ name: "peer", label: "Username", required: true, maxlength: 32, autocomplete: "off", hint: "The first message establishes the encrypted session." }],
      confirmLabel: "Start",
    });
    const peer = answer?.peer?.toLowerCase();
    if (!peer) return;
    if (peer === state.account?.username) return;
    const conversation = await startConversation(peer);
    selectedChannel = conversation.channel;
    drawList();
    drawPanel();
  }

  /** Poll while this view is mounted. */
  let typingShown = false;
  let seenRevision = signalRevision();
  const timer = window.setInterval(() => {
    if (document.hidden) return;
    // Messages that reached their hour go while the view is open, not only on reload.
    if (pruneExpired()) {
      void persistVault();
      drawList();
      drawPanel();
    }
    void receiveMessages().then((count) => {
      const typing = selectedChannel !== null && peerIsTyping(selectedChannel);
      // A read receipt decrypts to no message at all, so `count` stays 0 — without the
      // revision check the receipt would sit in the vault unseen until something else
      // redrew the panel.
      const signalled = signalRevision() !== seenRevision;
      if (count === 0 && !signalled && typing === typingShown) return;
      seenRevision = signalRevision();
      typingShown = typing;
      drawList();
      drawPanel();
    });
  }, 4000);
  const observer = new MutationObserver(() => {
    if (!root.isConnected) {
      window.clearInterval(timer);
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

