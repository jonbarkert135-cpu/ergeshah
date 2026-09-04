/**
 * The browser half, tested against the real server.
 *
 * The browser stubs and the sign-up/login helpers live in `test/browser.ts`, shared with
 * the metadata, attachment and abuse suites. What is exercised here is the real client
 * modules — vault, device publication, send, receive — rather than a re-implementation.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startTestServer, type TestServer } from "./helpers.ts";
import {
  actAs,
  FAST,
  installBrowserGlobals,
  installFetch,
  signUp,
  TEST_PASSWORD,
  type Persona,
} from "./browser.ts";
import { deriveAccountKeys } from "../src/shared/crypto/vault.ts";
import { generatePhrase } from "../src/shared/crypto/mnemonic.ts";
import {
  localSealedVault,
  lock,
  ready,
  state,
  unlockBackup,
} from "../src/client/state.ts";
import { conversations, receiveMessages, sendMessage, startConversation } from "../src/client/messaging.ts";
import { toBase64Url } from "../src/shared/encoding.ts";
import { randomBytes } from "../src/shared/crypto/sodium.ts";

/** Generated once libsodium is up, in `beforeEach`; one phrase for the whole file. */
let recoveryPhrase = "";
let server: TestServer;

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

describe("browser client against the real server", () => {
  it("registers, publishes a device and seals the vault locally and remotely", async () => {
    await fetch("/"); // pick up the CSRF cookie the way a page load does
    await signUp("alice", recoveryPhrase);

    expect(state.vault?.deviceId).toBeTruthy();
    const sealed = localSealedVault();
    expect(sealed?.v).toBe(3);
    // What is on disk is ciphertext, not keys.
    expect(JSON.stringify(sealed)).not.toContain(state.vault!.identity.identity.privateKey);

    const stored = await server.db.get<{ sealed: string }>("SELECT sealed FROM vaults");
    expect(JSON.parse(stored!.sealed).vault.data).toBe(sealed!.vault.data);

    // And it opens again with the password-derived key.
    const keys = deriveAccountKeys("alice", TEST_PASSWORD, FAST);
    expect(unlockBackup(keys.wrapKey, sealed!).vault.deviceId).toBe(state.vault!.deviceId);
  });

  it("carries a two-way conversation between two client instances", async () => {
    await fetch("/");
    const alice: Persona = await signUp("alice", recoveryPhrase);
    lock();
    localStorage.clear();
    await fetch("/");
    const bob: Persona = await signUp("bob", recoveryPhrase);

    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "hello bob");

    await actAs(bob);
    expect(await receiveMessages()).toBe(1);
    const incoming = conversations()[0]!;
    expect(incoming.peer).toBe("alice");
    expect(incoming.messages.at(-1)?.text).toBe("hello bob");
    await sendMessage(incoming, "hello alice");

    await actAs(alice);
    expect(await receiveMessages()).toBe(1);
    expect(conversations()[0]!.messages.at(-1)?.text).toBe("hello alice");
  });

  it("refuses an invite into an existing conversation from a key that is not the peer's (SEC-2026-024)", async () => {
    await fetch("/");
    const alice: Persona = await signUp("alice", recoveryPhrase);
    lock();
    localStorage.clear();
    await fetch("/");
    const bob: Persona = await signUp("bob", recoveryPhrase);
    lock();
    localStorage.clear();
    await fetch("/");
    const mallory: Persona = await signUp("mallory", recoveryPhrase);

    // An order conversation: both parties know the channel id before a word is sent, so bob's
    // side names its peer with no session yet — the state a stranger's invite would exploit.
    const channel = toBase64Url(randomBytes(24));
    await actAs(bob);
    await startConversation("alice", channel);

    // mallory learnt the channel id and posts an invite into it.
    await actAs(mallory);
    await sendMessage(await startConversation("bob", channel), "it is me, alice");
    await actAs(alice);
    await sendMessage(await startConversation("bob", channel), "hello bob");

    await actAs(bob);
    expect(await receiveMessages()).toBe(1);
    const incoming = conversations();
    expect(incoming).toHaveLength(1);
    expect(incoming[0]!.messages.map((message) => message.text)).toEqual(["hello bob"]);
    // alice's key is the one the directory lists, so it is no key change; mallory's never
    // got as far as a session, and the envelope is gone from the server rather than parked.
    expect(incoming[0]!.keyChange).toBeUndefined();
    expect(Object.keys(incoming[0]!.sessions)).toEqual([alice.vault!.identity.identity.publicKey]);
    expect(await server.db.get("SELECT count(*) AS n FROM envelopes")).toEqual({ n: 0 });
  });
});
