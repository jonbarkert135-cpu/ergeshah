/**
 * Transport- and browser-level hardening.
 *
 * The Content-Security-Policy is the important one: the entire client is self-hosted,
 * so `default-src 'self'` with no exceptions is achievable, and it is what makes the
 * "no third-party anything" promise enforceable by the browser instead of by a README.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "./config.ts";
import { forbidden } from "./lib/errors.ts";
import { API_VERSION, cookiesAreSecure, isApiRequest, isOnionHost } from "./app.ts";
import { CSRF_COOKIE, cookieName, parseCookies, serializeCookie, SESSION_COOKIE } from "./lib/cookies.ts";
import { constantTimeEqual, randomToken } from "./lib/ids.ts";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const CSP_DIRECTIVES = [
  "default-src 'self'",
  // 'wasm-unsafe-eval' is required, not optional: the cryptography is libsodium compiled
  // to WebAssembly, and Chromium refuses to instantiate *any* WASM module under a bare
  // `script-src 'self'` — the whole client fails at the first key derivation, which is
  // exactly how this was found (a real browser run, ADR-0027). The keyword permits
  // compiling WebAssembly and nothing else: `eval`, `new Function` and inline scripts stay
  // forbidden, which is the property that matters against injected script.
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'none'",
  "worker-src 'self'",
  "manifest-src 'self'",
  // The client builds every node with createElement/textContent and never assigns to an
  // HTML sink, so the strongest DOM-XSS policy a browser offers costs us nothing: no
  // script may pass a string to innerHTML, document.write or eval-like sinks at all.
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
];

/**
 * `upgrade-insecure-requests` is right for a clearnet deployment and wrong for an onion
 * one: an onion service is plain HTTP by design, and upgrading its own same-origin
 * requests to HTTPS would break the page. Everything else in the policy is identical.
 */
const CSP = CSP_DIRECTIVES.concat("upgrade-insecure-requests").join("; ");
const CSP_ONION = CSP_DIRECTIVES.join("; ");

const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "camera=()",
  "geolocation=()",
  "gyroscope=()",
  "magnetometer=()",
  "microphone=()",
  "payment=()",
  "usb=()",
  "interest-cohort=()",
].join(", ");

export function registerSecurity(app: FastifyInstance, config: Config): void {
  // A visitor needs a CSRF token before they can do anything, including logging in, so
  // any safe request without one mints it. It is not a secret and not an identifier: it
  // is compared only against the header of the same browser.
  app.addHook("onRequest", async (request, reply) => {
    if (!SAFE_METHODS.has(request.method)) return;
    const secure = cookiesAreSecure(config, request);
    if (parseCookies(request.headers.cookie)[cookieName(CSRF_COOKIE, secure)]) return;
    reply.header(
      "set-cookie",
      serializeCookie(cookieName(CSRF_COOKIE, secure), randomToken(24), {
        httpOnly: false,
        secure,
        sameSite: "Strict",
        maxAgeSeconds: 12 * 60 * 60,
      }),
    );
  });

  app.addHook("onSend", async (request, reply, payload) => {
    const onion = isOnionHost(request.headers.host);
    // Which API answered, whether or not the caller asked through the versioned path.
    if (isApiRequest(request)) reply.header("x-api-version", String(API_VERSION));
    reply.header("content-security-policy", onion ? CSP_ONION : CSP);
    reply.header("referrer-policy", "no-referrer");
    reply.header("x-content-type-options", "nosniff");
    reply.header("x-frame-options", "DENY");
    reply.header("permissions-policy", PERMISSIONS_POLICY);
    reply.header("cross-origin-opener-policy", "same-origin");
    reply.header("cross-origin-resource-policy", "same-origin");
    reply.header("origin-agent-cluster", "?1");
    // No caching of anything that could contain user data. The single exception is a
    // content-addressed asset: its URL contains the hash of its bytes, so a cached copy
    // can never be the wrong copy, and the route sets its own header (routes/static.ts).
    if (!request.url.startsWith("/assets/") && request.url !== "/favicon.svg") {
      reply.header("cache-control", "no-store");
    }
    // HSTS on an onion address would pin it to HTTPS, which no onion service speaks.
    if (config.behindTls && !onion) {
      reply.header("strict-transport-security", "max-age=63072000; includeSubDomains");
    }
    // Onion-Location tells Tor Browser that this site has an onion address and offers to
    // switch to it. It is only meaningful on the clearnet document responses, and Tor
    // Browser ignores it unless it arrives over HTTPS.
    if (config.onionHostname && !onion && request.method === "GET" && !isApiRequest(request)) {
      reply.header("onion-location", `http://${config.onionHostname}${request.url}`);
    }
    reply.removeHeader("x-powered-by");
    return payload;
  });
}

/**
 * CSRF defence, three independent layers: SameSite=Strict on the session cookie, an
 * Origin/Host check, and a double-submit token that a cross-origin page cannot read.
 */
export function enforceCsrf(config: Config, request: FastifyRequest, _reply: FastifyReply): void {
  if (SAFE_METHODS.has(request.method)) return;

  const origin = request.headers.origin;
  if (typeof origin === "string" && origin !== "null") {
    const host = request.headers.host;
    let originHost: string;
    try {
      originHost = new URL(origin).host;
    } catch {
      throw forbidden("invalid Origin header");
    }
    if (!host || originHost !== host) throw forbidden("cross-origin request rejected");
  }

  const cookies = parseCookies(request.headers.cookie);
  // Sealed sender (ADR-0084): a send-token request carries no cookies at all, which is the
  // point of it — and a request with no ambient authority is not what CSRF protects
  // against. A cross-site page cannot read the token out of another origin's vault, so
  // there is nothing here for it to ride. The Origin check above still applied.
  const secure = cookiesAreSecure(config, request);
  if (typeof request.headers["x-send-token"] === "string" && !cookies[cookieName(SESSION_COOKIE, secure)]) {
    return;
  }
  const cookieToken = cookies[cookieName(CSRF_COOKIE, secure)];
  const headerToken = request.headers["x-csrf-token"];
  // Constant-time, like every other secret comparison on the server (`lib/ids.ts`). The
  // double-submit token is not a password and the attack is awkward, but a `!==` on a secret
  // is the kind of exception that gets copied into the next handler, and there is no reason
  // to keep one (finding SEC-2026-005).
  if (!cookieToken || typeof headerToken !== "string" || !constantTimeEqual(headerToken, cookieToken)) {
    throw forbidden("missing or mismatched CSRF token");
  }
}
