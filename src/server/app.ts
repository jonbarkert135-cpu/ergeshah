import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { Config } from "./config.ts";
import type { Db } from "./db/index.ts";
import { HttpError, unauthorized, forbidden } from "./lib/errors.ts";
import { parseCookies, serializeCookie } from "./lib/cookies.ts";
import { resolveSession, type SessionUser } from "./lib/sessions.ts";
import { consume, type LimitName } from "./lib/rate_limit.ts";
import { enforceCsrf, registerSecurity } from "./security.ts";
import { registerAuthRoutes } from "./routes/auth.ts";
import { registerKeyRoutes } from "./routes/keys.ts";
import { registerMessageRoutes } from "./routes/messages.ts";
import { registerMarketRoutes } from "./routes/market.ts";
import { registerModerationRoutes } from "./routes/moderation.ts";
import { registerStaticRoutes } from "./routes/static.ts";

const SESSION_COOKIE = "session";
const CSRF_COOKIE = "csrf";

declare module "fastify" {
  interface FastifyInstance {
    db: Db;
    config: Config;
    /** Pre-rendered HTML shell of the single-page app. */
    appShell: string;
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
    bodyLimit: Math.max(config.maxEnvelopeBytes * 4, 512 * 1024),
    routerOptions: { ignoreTrailingSlash: true },
  });

  app.decorate("db", db);
  app.decorate("config", config);

  app.decorate("authenticate", async (request: FastifyRequest): Promise<SessionUser> => {
    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (!token) throw unauthorized();
    const user = await resolveSession(db, token);
    if (!user) throw unauthorized("session expired");
    if (user.status !== "active") throw forbidden("account suspended");
    return user;
  });

  app.decorate(
    "requireRole",
    async (request: FastifyRequest, roles: SessionUser["role"][]): Promise<SessionUser> => {
      const user = await app.authenticate(request);
      if (!roles.includes(user.role)) throw forbidden("insufficient privileges");
      return user;
    },
  );

  app.decorate("limit", async (request: FastifyRequest, scope: LimitName): Promise<void> => {
    await consume(db, config.bucketPepper, scope, clientAddress(request));
  });

  registerSecurity(app, config);

  app.addHook("preHandler", async (request, reply) => {
    if (request.url.startsWith("/api/")) enforceCsrf(request, reply);
  });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof HttpError) {
      return reply.status(error.statusCode).send({ error: error.code, message: error.message });
    }
    if ((error as { statusCode?: number }).statusCode === 400) {
      return reply.status(400).send({ error: "bad_request", message: "malformed request" });
    }
    // Deliberately terse: no stack traces, no request details, nothing user-identifying.
    process.stderr.write(
      `error ${request.method} ${request.routeOptions?.url ?? ""}: ${(error as Error).message}\n`,
    );
    return reply.status(500).send({ error: "internal_error", message: "internal error" });
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
  await registerModerationRoutes(app);
  await registerStaticRoutes(app);

  return app;
}

/** Address used only as rate-limit input; it is HMACed and never stored. */
function clientAddress(request: FastifyRequest): string {
  return request.ip ?? "unknown";
}

export function sessionCookie(config: Config, token: string, maxAgeSeconds: number): string {
  return serializeCookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: config.behindTls,
    sameSite: "Strict",
    maxAgeSeconds,
  });
}

export function csrfCookie(config: Config, token: string, maxAgeSeconds: number): string {
  return serializeCookie(CSRF_COOKIE, token, {
    httpOnly: false,
    secure: config.behindTls,
    sameSite: "Strict",
    maxAgeSeconds,
  });
}
