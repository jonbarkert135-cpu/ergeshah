/**
 * Serving the same instance over a clearnet domain and a v3 onion address.
 *
 * The interesting part is not Tor — it is that three browser-level defences are *right*
 * for HTTPS and *wrong* for an onion service (which is plain HTTP inside an authenticated
 * circuit), and getting them wrong means either a site nobody can log into or a security
 * header quietly dropped on the clearnet.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/server/config.ts";
import { authSecretFor, startTestServer, type TestServer } from "./helpers.ts";

const ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

let server: TestServer;

beforeEach(async () => {
  // This suite drives the API with raw `inject` calls rather than the test client, so the
  // proof-of-work gate is turned off here (`powBits: 0`, the supported way to disable it):
  // what is under test is which headers and cookie flags the onion host changes.
  server = await startTestServer({ behindTls: true, onionHostname: ONION, powBits: 0 });
});
afterEach(async () => {
  await server.close();
});

function cookiesOf(headers: Record<string, unknown>): string[] {
  return [headers["set-cookie"] ?? []].flat().map(String);
}

function cookieValue(cookies: string[], name: string): string {
  const match = cookies.find((cookie) => cookie.startsWith(`${name}=`));
  return decodeURIComponent((match ?? "").split(";")[0]!.split("=")[1] ?? "");
}

describe("onion service", () => {
  it("keeps Secure cookies on the clearnet and drops them on the onion address", async () => {
    const clearnet = await server.app.inject({ method: "GET", url: "/", headers: { host: "example.com" } });
    expect(cookiesOf(clearnet.headers).join()).toContain("Secure");

    const onion = await server.app.inject({ method: "GET", url: "/", headers: { host: ONION } });
    const cookies = cookiesOf(onion.headers);
    expect(cookies).not.toHaveLength(0);
    // Secure would mean "HTTPS only", and the onion service is HTTP: nobody could log in.
    expect(cookies.join()).not.toContain("Secure");
    expect(cookies.join()).toContain("SameSite=Strict");
  });

  it("lets someone register and stay signed in over the onion address", async () => {
    // The whole round trip with `Host: …onion` and a matching Origin, because "the cookie
    // has no Secure flag" is only interesting if the session it carries actually works.
    const first = await server.app.inject({ method: "GET", url: "/", headers: { host: ONION } });
    const csrf = cookieValue(cookiesOf(first.headers), "csrf");

    const registered = await server.app.inject({
      method: "POST",
      url: "/api/auth/register",
      headers: {
        host: ONION,
        origin: `http://${ONION}`,
        cookie: `csrf=${csrf}`,
        "x-csrf-token": csrf,
        "content-type": "application/json",
      },
      payload: JSON.stringify({
        username: "onionuser",
        authSecret: authSecretFor("onionuser", "correct horse battery staple"),
      }),
    });
    expect(registered.statusCode).toBe(200);
    const session = cookieValue(cookiesOf(registered.headers), "session");

    const me = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { host: ONION, cookie: `session=${session}` },
    });
    expect(me.statusCode).toBe(200);
    expect(me.json().username).toBe("onionuser");
  });

  it("drops HSTS and upgrade-insecure-requests only for the onion host", async () => {
    const clearnet = await server.app.inject({ method: "GET", url: "/", headers: { host: "example.com" } });
    expect(clearnet.headers["strict-transport-security"]).toContain("max-age=");
    expect(clearnet.headers["content-security-policy"]).toContain("upgrade-insecure-requests");

    const onion = await server.app.inject({ method: "GET", url: "/", headers: { host: ONION } });
    expect(onion.headers["strict-transport-security"]).toBeUndefined();
    expect(onion.headers["content-security-policy"]).not.toContain("upgrade-insecure-requests");
    // The rest of the policy is unchanged: this is a subtraction, not a different policy.
    expect(onion.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(onion.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  });

  it("advertises the onion address to Tor Browser, and only where that means anything", async () => {
    const page = await server.app.inject({ method: "GET", url: "/market", headers: { host: "example.com" } });
    expect(page.headers["onion-location"]).toBe(`http://${ONION}/market`);

    // Not on API responses (Tor Browser only acts on documents) …
    const api = await server.app.inject({ method: "GET", url: "/api/auth/me", headers: { host: "example.com" } });
    expect(api.headers["onion-location"]).toBeUndefined();
    // … and not when the visitor is already on the onion address.
    const onion = await server.app.inject({ method: "GET", url: "/", headers: { host: ONION } });
    expect(onion.headers["onion-location"]).toBeUndefined();
  });

  it("says nothing about an onion service when none is configured", async () => {
    const plain = await startTestServer({ behindTls: true });
    try {
      const response = await plain.app.inject({ method: "GET", url: "/", headers: { host: "example.com" } });
      expect(response.headers["onion-location"]).toBeUndefined();
    } finally {
      await plain.close();
    }
  });

  it("refuses a malformed onion address at boot rather than emitting a broken header", () => {
    expect(() => loadConfig()).not.toThrow();
    for (const bad of ["example.com", "short.onion", `${ONION}.evil.com`, "http://x.onion"]) {
      process.env.ONION_HOSTNAME = bad;
      expect(() => loadConfig()).toThrow(/v3 onion address/);
    }
    // Accepted with or without a scheme, case-insensitively.
    process.env.ONION_HOSTNAME = `HTTP://${ONION.toUpperCase()}/`;
    expect(loadConfig().onionHostname).toBe(ONION);
    delete process.env.ONION_HOSTNAME;
  });
});
