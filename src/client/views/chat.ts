import { clear, el, notice } from "../ui.ts";
import { conversations, receiveMessages, sendMessage, startConversation } from "../messaging.ts";
import { state } from "../state.ts";
import type { Conversation } from "../state.ts";
import { safetyNumber } from "../../shared/crypto/identity.ts";
import { decodeIdentity } from "../state.ts";
import { fromBase64Url } from "../../shared/encoding.ts";

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

    panel.append(
      el(
        "div",
        { class: "row" },
        el("h2", { style: "margin:0" }, conversation.peer),
        el("span", { class: "tag" }, "end-to-end encrypted"),
        el(
          "span",
          { class: "muted mono", title: "Compare this with your contact over another channel" },
          safetyFor(conversation),
        ),
      ),
      messages,
      el("div", { class: "composer" }, box, send),
      status,
    );
    messages.scrollTop = messages.scrollHeight;
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

function safetyFor(conversation: Conversation): string {
  const sessionKey = Object.keys(conversation.sessions)[0];
  if (!sessionKey || !state.vault) return "no session yet";
  const mine = decodeIdentity(state.vault.identity).identity.publicKey;
  try {
    return `safety ${safetyNumber(mine, fromBase64Url(sessionKey))}`;
  } catch {
    return "no session yet";
  }
}
