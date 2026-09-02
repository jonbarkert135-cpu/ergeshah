import { clear, el, notice } from "../ui.ts";
import { conversations, receiveMessages, sendMessage, startConversation } from "../messaging.ts";
import { state } from "../state.ts";
import type { Conversation } from "../state.ts";
import { markVerified, peerDevices, verificationState } from "../verification.ts";
import { qrSvg } from "../../shared/qr.ts";

let selectedChannel: string | null = null;

export function renderChat(root: HTMLElement): void {
  clear(root);
  const list = el("div", { class: "list" });
  const panel = el("div", {});
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
    list.append(
      el(
        "button",
        { class: "primary", onclick: () => void newConversation() },
        "New conversation",
      ),
    );
    const items = conversations();
    if (items.length === 0) list.append(el("p", { class: "muted" }, "No conversations yet."));
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
          el("span", { class: "muted mono" }, last ? ` ${last.text.slice(0, 22)}` : " —"),
        ),
      );
    }
  }

  function drawPanel() {
    clear(panel);
    const conversation = conversations().find((item) => item.channel === selectedChannel);
    if (!conversation) {
      panel.append(el("p", { class: "muted" }, "Select or start a conversation."));
      return;
    }
    const messages = el("div", { class: "messages" });
    for (const message of conversation.messages) {
      messages.append(
        el(
          "div",
          { class: message.mine ? "msg mine" : "msg" },
          message.text,
          el("span", { class: "meta" }, new Date(message.at).toLocaleString()),
        ),
      );
    }
    const box = el("input", { placeholder: `Message ${conversation.peer}…`, maxlength: "4000" });
    const send = el("button", { class: "primary" }, "Send");
    const status = el("div", {});

    const submit = () => {
      const text = box.value.trim();
      if (!text) return;
      box.value = "";
      send.disabled = true;
      void sendMessage(conversation, text)
        .then(() => {
          status.replaceChildren();
          drawPanel();
        })
        .catch((error: Error) => status.replaceChildren(notice(error.message, "error")))
        .finally(() => {
          send.disabled = false;
        });
    };
    box.addEventListener("keydown", (event) => {
      if ((event as KeyboardEvent).key === "Enter") submit();
    });
    send.addEventListener("click", submit);

    const verification = verificationState(conversation);
    panel.append(
      el(
        "div",
        { class: "row" },
        el("h2", { style: "margin:0" }, conversation.peer),
        el("span", { class: "tag" }, "end-to-end encrypted"),
        verification === "verified" ? el("span", { class: "tag" }, "verified ✓") : null,
        el("button", { class: "ghost", onclick: () => drawVerification(conversation) }, "Safety number"),
      ),
      el(
        "div",
        {},
        verification === "changed"
          ? notice(
              `A device in this conversation is not one you verified. That is either ${conversation.peer} adding a device, or someone else's key in its place — check the safety number before sending anything sensitive.`,
              "error",
            )
          : null,
      ),
      messages,
      el("div", { class: "composer" }, box, send),
      status,
    );
    messages.scrollTop = messages.scrollHeight;
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
        el("h2", { style: "margin:0" }, `Verify ${conversation.peer}`),
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
          el("div", { class: "mono", style: "font-size:1.1rem" }, device.safetyNumber),
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
    const peer = window.prompt("Username to message")?.trim().toLowerCase();
    if (!peer) return;
    if (peer === state.account?.username) return;
    const conversation = await startConversation(peer);
    selectedChannel = conversation.channel;
    drawList();
    drawPanel();
  }

  /** Poll while this view is mounted. */
  const timer = window.setInterval(() => {
    if (document.hidden) return;
    void receiveMessages().then((count) => {
      if (count > 0) {
        drawList();
        drawPanel();
      }
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

