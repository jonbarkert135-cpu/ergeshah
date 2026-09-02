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
import { parseCookies, serializeCookie } from "./lib/cookies.ts";
import { randomToken } from "./lib/ids.ts";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
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
  "upgrade-insecure-requests",
].join("; ");

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
    if (parseCookies(request.headers.cookie)["csrf"]) return;
    reply.header(
      "set-cookie",
      serializeCookie("csrf", randomToken(24), {
        httpOnly: false,
        secure: config.behindTls,
        sameSite: "Strict",
        maxAgeSeconds: 12 * 60 * 60,
      }),
    );
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("content-security-policy", CSP);
    reply.header("referrer-policy", "no-referrer");
    reply.header("x-content-type-options", "nosniff");
    reply.header("x-frame-options", "DENY");
    reply.header("permissions-policy", PERMISSIONS_POLICY);
    reply.header("cross-origin-opener-policy", "same-origin");
    reply.header("cross-origin-resource-policy", "same-origin");
    reply.header("origin-agent-cluster", "?1");
    // No caching of anything that could contain user data; assets are hashed instead.
    reply.header("cache-control", "no-store");
    if (config.behindTls) {
      reply.header("strict-transport-security", "max-age=63072000; includeSubDomains");
    }
    reply.removeHeader("x-powered-by");
    return payload;
  });
}

/**
 * CSRF defence, three independent layers: SameSite=Strict on the session cookie, an
 * Origin/Host check, and a double-submit token that a cross-origin page cannot read.
 */
export function enforceCsrf(request: FastifyRequest, _reply: FastifyReply): void {
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
  const cookieToken = cookies["csrf"];
  const headerToken = request.headers["x-csrf-token"];
  if (!cookieToken || typeof headerToken !== "string" || headerToken !== cookieToken) {
    throw forbidden("missing or mismatched CSRF token");
  }
}
