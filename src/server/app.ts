import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { Config } from "./config.ts";
import type { Db } from "./db/index.ts";
import { HttpError, unauthorized, forbidden } from "./lib/errors.ts";
import { parseCookies, serializeCookie } from "./lib/cookies.ts";
import { resolveSession, type SessionUser } from "./lib/sessions.ts";
import { consume, type LimitName } from "./lib/rate_limit.ts";
import { enforceCsrf, registerSecurity } from "./security.ts";
import { recordAudit } from "./lib/audit.ts";
import { randomToken } from "./lib/ids.ts";
import { registerAuthRoutes } from "./routes/auth.ts";
import { registerKeyRoutes } from "./routes/keys.ts";
import { registerMessageRoutes } from "./routes/messages.ts";
import { registerMarketRoutes } from "./routes/market.ts";
import { registerDeliveryRoutes } from "./routes/deliveries.ts";
import { registerModerationRoutes } from "./routes/moderation.ts";
import { registerStaticRoutes } from "./routes/static.ts";

const SESSION_COOKIE = "session";
const CSRF_COOKIE = "csrf";

declare module "fastify" {
  interface FastifyRequest {
    /** Set by `authenticate`; used to key rate limits to the account, never logged. */
    sessionUser?: SessionUser;
  }
  interface FastifyInstance {
    db: Db;
    config: Config;
    /** Pre-rendered HTML shell of the single-page app. */
    appShell: string;
    /**
     * Every route this server exposes, collected as they are registered. It exists so
     * that `test/authorization.test.ts` can walk the API and assert that each endpoint
     * refuses an anonymous caller — an inventory nobody has to remember to update.
     */
    routeInventory: Array<{ method: string; url: string }>;
    /** Throws unless the request carries a valid session for an active account. */
    authenticate(request: FastifyRequest): Promise<SessionUser>;
    requireRole(request: FastifyRequest, roles: SessionUser["role"][]): Promise<SessionUser>;
    limit(request: FastifyRequest, scope: LimitName): Promise<void>;
  }
}

export async function buildApp(config: Config, db: Db): Promise<FastifyInstance> {
  const app = Fastify({
    // No request logging: an access log is the single most common privacy leak in a
    // "private" service. Errors are reported without request context.
    logger: false,
    disableRequestLogging: true,
    trustProxy: config.trustProxy,
    // Large enough for one base64url-encoded delivery (4/3 expansion plus JSON framing),
    // which is the biggest body this API accepts by design.
    bodyLimit: Math.max(config.maxEnvelopeBytes * 4, Math.ceil(config.maxDeliveryBytes * 1.4)),
    // A URL parameter is an id or a username here; nothing legitimate is longer.
    routerOptions: { ignoreTrailingSlash: true, maxParamLength: 128 },
    // Slowloris and its friends: a request that never finishes is a connection held for
    // free. Fastify leaves these unset, which means "wait forever".
    requestTimeout: 30_000,
    connectionTimeout: 30_000,
    keepAliveTimeout: 20_000,
  });

  const routeInventory: Array<{ method: string; url: string }> = [];
  app.addHook("onRoute", (route) => {
    for (const method of [route.method].flat()) {
      if (method === "HEAD" || method === "OPTIONS") continue;
      routeInventory.push({ method, url: route.url });
    }
  });
  app.decorate("routeInventory", routeInventory);

  app.decorate("db", db);
  app.decorate("config", config);

  app.decorate("authenticate", async (request: FastifyRequest): Promise<SessionUser> => {
    // The preHandler hook usually resolved it already; this is the same check, once.
    if (request.sessionUser) {
      if (request.sessionUser.status !== "active") throw forbidden("account suspended");
      return request.sessionUser;
    }
    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (!token) throw unauthorized();
    const user = await resolveSession(db, token);
    if (!user) throw unauthorized("session expired");
    if (user.status !== "active") throw forbidden("account suspended");
    // Remembered for the rate limiter, which prefers the account over the address: on an
    // onion service every request comes from 127.0.0.1 (see lib/rate_limit.ts).
    request.sessionUser = user;
    return user;
  });

  app.decorate(
    "requireRole",
    async (request: FastifyRequest, roles: SessionUser["role"][]): Promise<SessionUser> => {
      const user = await app.authenticate(request);
      if (!roles.includes(user.role)) {
        // A refused privileged request is the interesting one — it is what a compromised
        // or curious account leaves behind. The route *pattern* is recorded, never the
        // concrete URL, so this cannot become a log of which order someone poked at.
        await recordAudit(db, {
          actorUserId: user.id,
          action: "privileged.denied",
          subjectType: "route",
          subjectId: request.routeOptions?.url ?? "unknown",
          note: user.role,
          result: "denied",
        });
        throw forbidden("insufficient privileges");
      }
      return user;
    },
  );

  app.decorate("limit", async (request: FastifyRequest, scope: LimitName): Promise<void> => {
    await consume(db, config.bucketPepper, scope, limitSubject(request), config.rateLimits);
  });

  registerSecurity(app, config);

  app.addHook("preHandler", async (request, reply) => {
    if (!request.url.startsWith("/api/")) return;
    enforceCsrf(request, reply);
    // Resolve the session once, before the handler runs, and without deciding anything:
    // routes still call `authenticate`, and public routes still work without a session.
    // The point is that the rate limiter can key on the account even on a public route —
    // otherwise every logged-in user browsing an onion service shares one bucket.
    if (!request.sessionUser) {
      const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
      if (token) {
        const user = await resolveSession(db, token);
        if (user && user.status === "active") request.sessionUser = user;
      }
    }
  });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof HttpError) {
      return reply.status(error.statusCode).send({ error: error.code, message: error.message });
    }
    // Fastify's own client errors (malformed JSON, body too large, unsupported media
    // type) are the client's fault, not an incident: answer them tersely and truthfully
    // instead of turning them into a 500 and a log line.
    const status = (error as { statusCode?: number }).statusCode ?? 500;
    if (status >= 400 && status < 500) {
      const tooLarge = status === 413;
      return reply.status(status).send({
        error: tooLarge ? "too_large" : "bad_request",
        message: tooLarge ? "request body too large" : "malformed request",
      });
    }
    // Two audiences, one incident. The operator gets a structured line with a reference,
    // the route *pattern*, the error name and its message — enough to find the bug, and
    // free of the request body, the user, the query and the stack (a stack in a log is a
    // filesystem path and a dependency inventory). The user gets the reference and
    // nothing else, so a support conversation can start with "error 7f3a…" instead of a
    // screenshot of internals.
    const ref = randomToken(6);
    const failure = error as Error;
    process.stderr.write(
      `${JSON.stringify({
        at: new Date().toISOString(),
        ref,
        level: "error",
        method: request.method,
        route: request.routeOptions?.url ?? "unknown",
        name: failure.name,
        message: failure.message,
      })}\n`,
    );
    return reply.status(500).send({ error: "internal_error", message: "internal error", ref });
  });

  app.setNotFoundHandler(async (request, reply) => {
    if (request.url.startsWith("/api/")) {
      return reply.status(404).send({ error: "not_found", message: "not found" });
    }
    // Single-page app: unknown paths render the shell, never a directory listing.
    return reply.status(404).type("text/html; charset=utf-8").send(app.appShell);
  });

  await registerAuthRoutes(app);
  await registerKeyRoutes(app);
  await registerMessageRoutes(app);
  await registerMarketRoutes(app);
  await registerDeliveryRoutes(app);
  await registerModerationRoutes(app);
  await registerStaticRoutes(app);

  return app;
}

/** Address used only as rate-limit input; it is HMACed and never stored. */
function clientAddress(request: FastifyRequest): string {
  return request.ip ?? "unknown";
}

/**
 * What a rate-limit bucket is counted against. An authenticated caller is counted as an
 * account, so that one abusive user cannot spend everybody else's allowance on a shared
 * address — which is every request on an onion service, and most requests behind a
 * corporate NAT.
 */
function limitSubject(request: FastifyRequest): string {
  const user = request.sessionUser;
  return user ? `user:${user.id}` : `addr:${clientAddress(request)}`;
}

/**
 * `Secure` means "HTTPS only", which is right everywhere except one place: an onion
 * service is reached over plain HTTP *inside* an authenticated, encrypted Tor circuit, so
 * a Secure cookie would simply never be sent and nobody could log in. Tor Browser already
 * treats `.onion` origins as trustworthy for exactly this reason.
 *
 * The Host header is client-controlled, but the only thing a client can do by lying is
 * weaken its own cookie on its own request — the browser sends the real host.
 */
export function isOnionHost(host: string | undefined): boolean {
  return typeof host === "string" && /\.onion(?::\d+)?$/i.test(host.trim());
}

export function cookiesAreSecure(config: Config, request: FastifyRequest): boolean {
  return config.behindTls && !isOnionHost(request.headers.host);
}

export function sessionCookie(
  config: Config,
  request: FastifyRequest,
  token: string,
  maxAgeSeconds: number,
): string {
  return serializeCookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: cookiesAreSecure(config, request),
    sameSite: "Strict",
    maxAgeSeconds,
  });
}

export function csrfCookie(
  config: Config,
  request: FastifyRequest,
  token: string,
  maxAgeSeconds: number,
): string {
  return serializeCookie(CSRF_COOKIE, token, {
    httpOnly: false,
    secure: cookiesAreSecure(config, request),
    sameSite: "Strict",
    maxAgeSeconds,
  });
}
