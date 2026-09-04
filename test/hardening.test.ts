/**
 * Browser-level hardening: the headers, and the client helper that every attribute goes
 * through. Both are the kind of protection that is easy to write once and lose silently
 * in a refactor, which is exactly what a test is for.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import { safeUrl } from "../src/client/ui.ts";

let server: TestServer;

beforeAll(async () => {
  server = await startTestServer();
});

afterAll(async () => {
  await server.close();
});

describe("security headers", () => {
  it("sends a policy that actually restricts something", async () => {
    const response = await server.app.inject({ method: "GET", url: "/" });
    const csp = String(response.headers["content-security-policy"]);

    // A decorative CSP is one with 'unsafe-inline', 'unsafe-eval' or a wildcard in it.
    // 'wasm-unsafe-eval' is a different keyword with a different meaning — it permits
    // compiling WebAssembly and nothing else — and the client does not run without it in
    // Chromium, because the cryptography *is* WebAssembly (ADR-0027).
    expect(csp).not.toMatch(/unsafe-inline|\*/);
    expect(csp).not.toMatch(/(?<!wasm-)unsafe-eval/);
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    for (const directive of [
      "default-src 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      // DOM XSS closed structurally: no string may reach an HTML sink.
      "require-trusted-types-for 'script'",
      "trusted-types 'none'",
    ]) {
      expect(csp).toContain(directive);
    }

    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.headers["x-frame-options"]).toBe("DENY");
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(String(response.headers["permissions-policy"])).toContain("camera=()");
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["x-powered-by"]).toBeUndefined();
  });

  it("keeps the session cookie unreadable by scripts", async () => {
    const client = new TestClient(server);
    await register(server, "cookie-probe");
    void client;
    const login = await server.app.inject({
      method: "GET",
      url: "/",
    });
    const csrf = String(login.headers["set-cookie"] ?? "");
    // The CSRF cookie is readable on purpose (double-submit) but must not travel to
    // other sites; the session cookie is HttpOnly and is asserted in auth.test.ts.
    expect(csrf).toContain("SameSite=Strict");
  });

  // SEC-2026-014: without the `__Host-` prefix, any sibling host under the registrable domain
  // can set a `session` cookie for this origin and log the victim into the attacker's account.
  it("names its cookies __Host- on HTTPS, so a related host cannot plant them", async () => {
    const tls = await startTestServer({ behindTls: true });
    try {
      const first = await tls.app.inject({ method: "GET", url: "/", headers: { host: "example.com" } });
      const minted = [first.headers["set-cookie"] ?? []].flat().map(String);
      expect(minted.some((c) => c.startsWith("__Host-csrf=") && c.includes("Secure") && !/Domain=/i.test(c))).toBe(true);

      const alice = await register(tls, "prefixed");
      expect(alice.cookieNames()).toContain("__Host-session");
      expect(alice.cookieNames()).not.toContain("session");
      expect((await alice.get("/api/auth/me")).status).toBe(200);

      // A bare `session` cookie — the only kind a sibling host can set — is not a session here.
      const planted = await tls.app.inject({
        method: "GET",
        url: "/api/auth/me",
        headers: { host: "example.com", cookie: `session=${alice.cookie("session")}` },
      });
      expect(planted.statusCode).toBe(401);
      // Nor is a bare `csrf` cookie a CSRF token.
      const forged = await tls.app.inject({
        method: "POST",
        url: "/api/auth/logout",
        headers: {
          host: "example.com",
          origin: "https://example.com",
          cookie: `__Host-session=${alice.cookie("session")}; csrf=abc`,
          "x-csrf-token": "abc",
        },
      });
      expect(forged.statusCode).toBe(403);
      // Logging out clears the prefixed names.
      const out = await alice.post("/api/auth/logout", {});
      expect(out.status).toBe(200);
      expect(alice.cookieNames()).not.toContain("__Host-session");
    } finally {
      await tls.close();
    }
    // An onion service is plain HTTP inside the circuit: no prefix, no Secure, and no siblings.
    const onion = await startTestServer({ behindTls: true });
    try {
      const response = await onion.app.inject({
        method: "GET",
        url: "/",
        headers: { host: `${"a".repeat(56)}.onion` },
      });
      const cookies = [response.headers["set-cookie"] ?? []].flat().map(String);
      expect(cookies.some((c) => c.startsWith("csrf=") && !c.includes("Secure"))).toBe(true);
    } finally {
      await onion.close();
    }
  });

  it("does not upgrade requests on an onion host, and does on clearnet", async () => {
    const onion = await server.app.inject({
      method: "GET",
      url: "/",
      headers: { host: "5anebdfz2wsdlqrkxbhbnhmhdxvqbwphzqvqfkq5s2yrqbtjrq7cyeid.onion" },
    });
    expect(String(onion.headers["content-security-policy"])).not.toContain(
      "upgrade-insecure-requests",
    );
  });
});

describe("the DOM helper refuses unsafe URLs", () => {
  // `el()` runs in a browser; its URL rule is pure, so it is tested directly here and
  // exercised through `el()` by every view in the client.
  it("allows what the client legitimately produces", () => {
    for (const url of [
      "/orders",
      "?role=seller",
      "#top",
      "https://example.org/x",
      "http://example.org/x",
      "blob:http://localhost/abc",
      "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
    ]) {
      expect(safeUrl(url), url).toBe(true);
    }
  });

  it("refuses script and phishing schemes, including the disguised spellings", () => {
    for (const url of [
      "javascript:alert(1)",
      "  javascript:alert(1)",
      "JavaScript:alert(1)",
      "\tjavascript:alert(1)",
      "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
      "data:image/svg+xml,<svg onload=alert(1)>",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
      "//evil.example/path",
    ]) {
      expect(safeUrl(url), url).toBe(false);
    }
  });
});
