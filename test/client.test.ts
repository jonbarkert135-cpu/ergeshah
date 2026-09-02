/**
 * The browser half, tested against the real server.
 *
 * The two browser APIs the client actually needs — `localStorage` and `document.cookie`
 * — are stubbed here, and `fetch` is redirected into Fastify's injector. That exercises
 * the real client modules (vault, device publication, send, receive) rather than a
 * re-implementation of them, without pulling a DOM emulator into the test dependencies.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startTestServer, type TestServer } from "./helpers.ts";
import { toBase64Url } from "../src/shared/encoding.ts";
import { deriveAccountKeys } from "../src/shared/crypto/vault.ts";
import { api } from "../src/client/api.ts";
import {
  localSealedVault,
  lock,
  newVault,
  persistVault,
  publishDevice,
  ready,
  state,
  unlockVault,
} from "../src/client/state.ts";
import { conversations, receiveMessages, sendMessage, startConversation } from "../src/client/messaging.ts";

const FAST = { opsLimit: 1, memLimit: 8192 };
let server: TestServer;

function installBrowserGlobals(): void {
  const store = new Map<string, string>();
  const cookies = new Map<string, string>();
  Object.assign(globalThis, {
    localStorage: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, value),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    },
    document: {
      get cookie(): string {
        return [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");
      },
      set cookie(value: string) {
        const [pair, ...attributes] = value.split(";");
        const [name, cookieValue] = (pair ?? "").split("=");
        if (!name) return;
        if (attributes.some((attribute) => /max-age=0/i.test(attribute)) || !cookieValue) {
          cookies.delete(name.trim());
        } else {
          cookies.set(name.trim(), cookieValue);
        }
      },
    },
  });
}

function installFetch(): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : String(input);
    const headers: Record<string, string> = { ...((init.headers as Record<string, string>) ?? {}) };
    if (document.cookie) headers.cookie = document.cookie;
    headers.host = "localhost";
    if (init.method && init.method !== "GET") headers.origin = "http://localhost";
    const response = await server.app.inject({
      method: (init.method ?? "GET") as "GET",
      url,
      headers,
      payload: init.body as string | undefined,
    });
    for (const raw of [response.headers["set-cookie"] ?? []].flat()) {
      const [pair] = String(raw).split(";");
      const [name, value] = (pair ?? "").split("=");
      if (name) document.cookie = `${name}=${value ?? ""}`;
    }
    return new Response(response.body, {
      status: response.statusCode,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

/** What `renderAuth` does, minus the DOM. */
async function signUp(username: string, password = "a rather long passphrase"): Promise<void> {
  const keys = deriveAccountKeys(username, password, FAST);
  state.vault = newVault();
  state.vaultKey = keys.vaultKey;
  const account = await api<{ id: string; username: string; role: string }>("/api/auth/register", {
    method: "POST",
    body: { username, authSecret: toBase64Url(keys.authSecret) },
  });
  state.account = { id: account.id, username: account.username, role: account.role as never };
  await persistVault();
  await publishDevice("test");
}

beforeEach(async () => {
  await ready();
  server = await startTestServer();
  installBrowserGlobals();
  installFetch();
  lock();
});
afterEach(async () => {
  await server.close();
});

describe("browser client against the real server", () => {
  it("registers, publishes a device and seals the vault locally and remotely", async () => {
    await fetch("/"); // pick up the CSRF cookie the way a page load does
    await signUp("alice");

    expect(state.vault?.deviceId).toBeTruthy();
    const sealed = localSealedVault();
    expect(sealed?.v).toBe(1);
    // What is on disk is ciphertext, not keys.
    expect(JSON.stringify(sealed)).not.toContain(state.vault!.identity.identity.privateKey);

    const stored = await server.db.get<{ sealed: string }>("SELECT sealed FROM vaults");
    expect(JSON.parse(stored!.sealed).data).toBe(sealed!.data);

    // And it opens again with the password-derived key.
    const keys = deriveAccountKeys("alice", "a rather long passphrase", FAST);
    expect(unlockVault(keys.vaultKey, sealed!).deviceId).toBe(state.vault!.deviceId);
  });

  it("carries a two-way conversation between two client instances", async () => {
    await fetch("/");
    await signUp("alice");
    const alice = { account: state.account, vault: state.vault, vaultKey: state.vaultKey };

    await api("/api/auth/logout", { method: "POST" });
    lock();
    localStorage.clear();
    await fetch("/");
    await signUp("bob");
    const bob = { account: state.account, vault: state.vault, vaultKey: state.vaultKey };

    const use = (who: typeof alice) => Object.assign(state, who);

    use(alice);
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    await login("alice");
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "hello bob");

    use(bob);
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    await login("bob");
    expect(await receiveMessages()).toBe(1);
    const incoming = conversations()[0]!;
    expect(incoming.peer).toBe("alice");
    expect(incoming.messages.at(-1)?.text).toBe("hello bob");
    await sendMessage(incoming, "hello alice");

    use(alice);
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    await login("alice");
    expect(await receiveMessages()).toBe(1);
    expect(conversations()[0]!.messages.at(-1)?.text).toBe("hello alice");
  });

  async function login(username: string, password = "a rather long passphrase") {
    const keys = deriveAccountKeys(username, password, FAST);
    await fetch("/");
    await api("/api/auth/login", {
      method: "POST",
      body: { username, authSecret: toBase64Url(keys.authSecret) },
    });
  }
});
