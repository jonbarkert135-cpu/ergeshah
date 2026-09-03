/**
 * Points 75-77 and 80: every metadata feature is opt-in, or privacy-preserving by
 * construction, or absent — and the absences are asserted rather than assumed.
 *
 * The interesting half runs two real client instances against the real server: a typing
 * signal and a read receipt have to be indistinguishable from a message on the wire, must
 * never be stored as one, and must not be sent at all unless the account turned them on.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { startTestServer, type TestServer } from "./helpers.ts";
import { actAs, installBrowserGlobals, installFetch, signUp, type Persona } from "./browser.ts";
import { generatePhrase } from "../src/shared/crypto/mnemonic.ts";
import {
  conversations,
  peerIsTyping,
  pruneExpired,
  receiveMessages,
  searchMessages,
  sendMessage,
  sendReadReceipt,
  sendTyping,
  setDisappearing,
  startConversation,
} from "../src/client/messaging.ts";
import { deleteConversation, deleteMessage } from "../src/client/messaging.ts";
import { lock, privacySettings, ready, setPrivacy, state } from "../src/client/state.ts";
import { listColumns, listTables } from "./database.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;
let recoveryPhrase = "";

beforeEach(async () => {
  await ready();
  recoveryPhrase ||= generatePhrase(24);
  server = await startTestServer();
  installBrowserGlobals();
  installFetch(server);
  lock();
});
afterEach(async () => {
  await server.close();
});

describe("metadata features that do not exist", () => {
  it("has no route that reports presence, typing or read state", async () => {
    const routes = server.app.routeInventory.map((route) => `${route.method} ${route.url}`);
    for (const forbidden of [/presence/i, /typing/i, /online/i, /receipt/i, /last-?seen/i]) {
      expect(routes.filter((route) => forbidden.test(route))).toEqual([]);
    }
  });

  it("has no column anywhere for presence, read state or a delivery state", async () => {
    const columns: string[] = [];
    for (const name of await listTables(server.db)) {
      columns.push(...(await listColumns(server.db, name)).map((column) => `${name}.${column}`));
    }
    // `notifications.read_at` is the inbox's own read flag — a person marking their own
    // notice board, not a receipt sent to anybody.
    const suspicious = columns.filter((column) =>
      /(presence|online|typing|last_seen(?!_day)|delivered_at|seen_at)/.test(column),
    );
    expect(suspicious).toEqual([]);
    expect(columns.filter((column) => /read_at/.test(column))).toEqual(["notifications.read_at"]);
  });

  it("ships no push notification machinery at all (point 80)", () => {
    const sources = [
      ...readdirSync(new URL("../src/server", import.meta.url), { recursive: true }),
    ]
      .map(String)
      .filter((name) => name.endsWith(".ts"))
      .map((name) => read(`src/server/${name}`));
    sources.push(read("src/client/api.ts"), read("src/client/main.ts"), read("src/client/state.ts"));
    for (const source of sources) {
      expect(source).not.toMatch(/PushManager|serviceWorker|pushSubscription|device_token|fcm|apns/i);
    }
    const routes = server.app.routeInventory.map((route) => route.url);
    expect(routes.filter((url) => /push|subscribe/i.test(url))).toEqual([]);
  });

  it("documents each of the eight metadata features point 75 lists", () => {
    const doc = read("docs/METADATA.md");
    for (const feature of [
      "Sender",
      "Recipient",
      "Timestamp",
      "Size",
      "Delivery state",
      "Typing indicator",
      "Read receipt",
      "Online status",
    ]) {
      expect(doc, feature).toContain(`**${feature}**`);
    }
  });
});

describe("signals between two clients", () => {
  let alice: Persona;
  let bob: Persona;

  beforeEach(async () => {
    await fetch("/");
    alice = await signUp("alice", recoveryPhrase);
    lock();
    localStorage.clear();
    await fetch("/");
    bob = await signUp("bob", recoveryPhrase);
  });

  it("sends nothing until the account turns the feature on", async () => {
    await actAs(alice);
    expect(privacySettings().typingIndicators).toBe(false);
    expect(privacySettings().readReceipts).toBe(false);
    expect(privacySettings().disappearHours).toBeNull();

    const conversation = await startConversation("bob");
    await sendTyping(conversation);
    const envelopes = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes");
    expect(envelopes!.n).toBe(0);
  });

  it("carries a typing signal that the server cannot tell from a message", async () => {
    await actAs(alice);
    await setPrivacy({ typingIndicators: true });
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "hello bob");
    await sendTyping(conversation);

    // Two envelopes, indistinguishable in every way the schema can express: same columns,
    // same channel, same expiry, and the *same padding bucket* — a typing signal is the
    // size of a short message, because it is one. What padding never hides is the bucket
    // itself, and that is true of signals exactly as it is of sentences (docs/METADATA.md).
    const rows = await server.db.all<{ payload: string; channel: string; expires_at: number }>(
      "SELECT payload, channel, expires_at FROM envelopes ORDER BY created_at",
    );
    expect(rows).toHaveLength(2);
    expect(rows[0]!.channel).toBe(rows[1]!.channel);
    expect(rows[0]!.payload.length).toBe(rows[1]!.payload.length);
    expect(rows[0]!.expires_at - rows[1]!.expires_at).toBeLessThanOrEqual(1000);

    // And on the receiving side it is applied, not stored.
    await actAs(bob);
    expect(await receiveMessages()).toBe(1);
    const incoming = conversations()[0]!;
    expect(incoming.messages).toHaveLength(1);
    expect(incoming.messages[0]!.text).toBe("hello bob");
    expect(peerIsTyping(incoming.channel)).toBe(true);
    expect(JSON.stringify(state.vault)).not.toContain("typing");
  });

  it("marks a message read only when the reader chose to say so", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "did you see this");

    await actAs(bob);
    await receiveMessages();
    const incoming = conversations()[0]!;
    await sendReadReceipt(incoming); // receipts off: sends nothing
    expect(incoming.readUpTo).toBeUndefined();

    await setPrivacy({ readReceipts: true });
    await sendReadReceipt(incoming);
    expect(incoming.readUpTo).toBe(incoming.messages.at(-1)!.at);
    await sendReadReceipt(incoming); // already sent for this batch: no second envelope

    await actAs(alice);
    expect(await receiveMessages()).toBe(0); // a receipt is not a message
    const mine = conversations()[0]!.messages;
    expect(mine).toHaveLength(1);
    expect(mine[0]!.readAt).toBeTypeOf("number");
  });
});

describe("disappearing messages, deletion and search on the client", () => {
  let alice: Persona;
  let bob: Persona;

  beforeEach(async () => {
    await fetch("/");
    alice = await signUp("alice", recoveryPhrase);
    lock();
    localStorage.clear();
    await fetch("/");
    bob = await signUp("bob", recoveryPhrase);
  });

  it("drops a message on both sides when its hour passes, and asks the server for the same", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await setDisappearing(conversation, 1);
    await sendMessage(conversation, "gone in an hour");

    const envelope = await server.db.get<{ created_at: number; expires_at: number }>(
      "SELECT created_at, expires_at FROM envelopes LIMIT 1",
    );
    expect(envelope!.expires_at - envelope!.created_at).toBe(3_600_000);

    const mine = conversations()[0]!.messages[0]!;
    expect(mine.expiresAt).toBeTypeOf("number");
    expect(pruneExpired(Date.now() + 3_600_001)).toBe(true);
    expect(conversations()[0]!.messages).toHaveLength(0);

    await actAs(bob);
    await receiveMessages();
    const received = conversations()[0]!.messages[0]!;
    expect(received.expiresAt).toBeTypeOf("number");
    expect(pruneExpired(Date.now() + 3_600_001)).toBe(true);
    expect(conversations()[0]!.messages).toHaveLength(0);
  });

  it("takes the sooner of the two lifetimes, never the longer one", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await setDisappearing(conversation, 720); // sender: 30 days
    await sendMessage(conversation, "keep this a while");

    await actAs(bob);
    await receiveMessages();
    const incoming = conversations()[0]!;
    await setDisappearing(incoming, 1); // reader: one hour
    await actAs(alice);
    await sendMessage(conversations()[0]!, "and this one too");
    await actAs(bob);
    await receiveMessages();

    const received = conversations()[0]!.messages.at(-1)!;
    expect(received.expiresAt! - received.at).toBeLessThanOrEqual(3_600_000);
  });

  it("deletes one message, and a whole conversation with its session keys", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "first");
    await sendMessage(conversation, "second");
    expect(Object.keys(conversation.sessions).length).toBeGreaterThan(0);

    await deleteMessage(conversation, conversation.messages[0]!.id!);
    expect(conversation.messages.map((message) => message.text)).toEqual(["second"]);

    const keyMaterial = Object.values(conversation.sessions)[0]!.rootKey;
    await deleteConversation(conversation.channel);
    expect(conversations()).toHaveLength(0);
    // The vault that gets sealed no longer contains that session's key material.
    expect(JSON.stringify(state.vault)).not.toContain(keyMaterial);
  });

  it("searches in the browser, over what this device decrypted", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "the invoice is attached");
    await sendMessage(conversation, "and the receipt");

    expect(searchMessages("INVOICE").map((hit) => hit.message.text)).toEqual([
      "the invoice is attached",
    ]);
    expect(searchMessages("  ")).toEqual([]);
    expect(searchMessages("nothing here")).toEqual([]);
    expect(searchMessages("the")).toHaveLength(2);
  });

  it("has no server-side search over message content", () => {
    const messages = read("src/server/routes/messages.ts");
    expect(messages).not.toMatch(/LIKE/i);
    // The only inverted index in the system is the marketplace's, over public listings.
    expect(read("src/server/lib/search.ts")).not.toContain("envelopes");
  });
});
