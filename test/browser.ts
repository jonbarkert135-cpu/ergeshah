/**
 * A browser, minus the DOM.
 *
 * The client modules need exactly three things a browser provides — `localStorage`,
 * `document.cookie` and `fetch` — so these are stubbed, with `fetch` redirected into
 * Fastify's injector. Tests then exercise the real client code (vault, device publication,
 * send, receive, signals, deletion) rather than a re-implementation of it, and without a DOM
 * emulator in the dependency list.
 *
 * Shared by `client.test.ts`, `metadata.test.ts`, `attachments.test.ts` and `abuse.test.ts`.
 */
import type { TestServer } from "./helpers.ts";
import { api } from "../src/client/api.ts";
import {
  initialiseVault,
  newVault,
  persistVault,
  publishDevice,
  state,
} from "../src/client/state.ts";
import { deriveAccountKeys, deriveRecoveryKeys } from "../src/shared/crypto/vault.ts";
import { toBase64Url } from "../src/shared/encoding.ts";

/** Argon2id parameters are the product; in tests we only care that the plumbing works. */
export const FAST = { opsLimit: 1, memLimit: 8192 };
export const TEST_PASSWORD = "a rather long passphrase";

/** One client instance's whole identity, so a test can switch between two of them. */
export type Persona = Pick<typeof state, "account" | "vault" | "masterKey" | "envelopes">;

export function installBrowserGlobals(): void {
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

export function installFetch(server: TestServer): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : String(input);
    const headers: Record<string, string> = { ...((init.headers as Record<string, string>) ?? {}) };
    // A real browser sends no cookie jar when a request asks for `credentials: "omit"`,
    // and the sealed-sender path (ADR-0084) depends on exactly that: a session cookie
    // riding along would defeat the token. The stub has to honour it or the tests would
    // be testing a browser that does not exist.
    if (init.credentials !== "omit" && document.cookie) headers.cookie = document.cookie;
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

/** What `renderAuth` does, minus the DOM. Returns the persona it just created. */
export async function signUp(
  username: string,
  recoveryPhrase: string,
  password = TEST_PASSWORD,
): Promise<Persona> {
  const keys = deriveAccountKeys(username, password, FAST);
  const recovery = deriveRecoveryKeys(username, recoveryPhrase, FAST);
  initialiseVault(newVault(), { password: keys.wrapKey, recovery: recovery.wrapKey });
  const account = await api<{ id: string; username: string; role: string }>("/api/auth/register", {
    method: "POST",
    body: {
      username,
      authSecret: toBase64Url(keys.authSecret),
      recoveryPublicKey: toBase64Url(recovery.signPublicKey),
    },
  });
  state.account = { id: account.id, username: account.username, role: account.role as never };
  await persistVault();
  await publishDevice("test");
  return {
    account: state.account,
    vault: state.vault,
    masterKey: state.masterKey,
    envelopes: state.envelopes,
  };
}

export async function login(username: string, password = TEST_PASSWORD): Promise<void> {
  const keys = deriveAccountKeys(username, password, FAST);
  await fetch("/");
  await api("/api/auth/login", {
    method: "POST",
    body: { username, authSecret: toBase64Url(keys.authSecret) },
  });
}

/**
 * Switch the module-level client state to a persona and take over its session. Two browsers
 * in one process share one `state`, so a test that plays both sides swaps deliberately.
 */
export async function actAs(persona: Persona): Promise<void> {
  Object.assign(state, persona);
  await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
  await login(persona.account!.username);
}
