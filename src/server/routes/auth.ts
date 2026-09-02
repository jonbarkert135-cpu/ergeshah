/**
 * Account identity: registration, login, logout, session management.
 *
 * The server never sees a password — only `authSecret`, the half of the client-side
 * Argon2id output that is meant to be shown to it (see `src/shared/crypto/vault.ts`).
 */
import type { FastifyInstance, FastifyReply } from "fastify";
import { csrfCookie, sessionCookie } from "../app.ts";
import { badRequest, conflict, unauthorized } from "../lib/errors.ts";
import { newId, randomToken } from "../lib/ids.ts";
import { hashAuthSecret, verifyAuthSecret } from "../lib/password.ts";
import {
  createSession,
  destroyAllSessions,
  destroySession,
  pruneSessions,
} from "../lib/sessions.ts";
import { today, dayToIsoDate } from "../lib/time.ts";
import { asBase64Url, asOptionalString, asUsername } from "../lib/validate.ts";

interface Credentials {
  username: unknown;
  authSecret: unknown;
  label?: unknown;
  sealedVault?: unknown;
}

export async function registerAuthRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  app.post("/api/auth/register", async (request, reply) => {
    // Validate before spending a rate-limit token: a malformed request costs the server
    // nothing, and burning the budget on typos would only punish honest clients.
    const body = (request.body ?? {}) as Credentials;
    const username = asUsername(body.username);
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const label = asOptionalString(body.label, "label", 40) || null;
    await app.limit(request, "register");

    const existing = await db.get("SELECT id FROM users WHERE username = ?", [username]);
    if (existing) {
      // Usernames are public identifiers on this platform (you message and buy from a
      // name), so registration necessarily reveals that one is taken. Login does not.
      throw conflict("that username is taken", "username_taken");
    }

    const userId = newId();
    const passwordHash = await hashAuthSecret(authSecret);
    const isFirstUser = !(await db.get("SELECT id FROM users LIMIT 1"));

    await db.transaction(async (tx) => {
      await tx.run(
        `INSERT INTO users (id, username, password_hash, role, status, created_day)
         VALUES (?, ?, ?, ?, 'active', ?)`,
        [userId, username, passwordHash, isFirstUser ? "admin" : "user", today()],
      );
      if (body.sealedVault !== undefined) {
        await tx.run("INSERT INTO vaults (user_id, sealed, updated_day) VALUES (?, ?, ?)", [
          userId,
          JSON.stringify(body.sealedVault),
          today(),
        ]);
      }
    });

    const session = await createSession(db, userId, config.sessionTtlMs, label);
    return replyWithSession(reply, config, {
      id: userId,
      username,
      role: isFirstUser ? "admin" : "user",
      token: session.token,
      expiresAt: session.expiresAt,
    });
  });

  app.post("/api/auth/login", async (request, reply) => {
    const body = (request.body ?? {}) as Credentials;
    const username = asUsername(body.username);
    const authSecret = asBase64Url(body.authSecret, "authSecret", 64);
    const label = asOptionalString(body.label, "label", 40) || null;
    await app.limit(request, "auth");

    const user = await db.get<{
      id: string;
      username: string;
      password_hash: string;
      role: "user" | "moderator" | "admin";
      status: "active" | "suspended";
      status_reason: string | null;
    }>(
      "SELECT id, username, password_hash, role, status, status_reason FROM users WHERE username = ?",
      [username],
    );

    // Constant work whether or not the account exists: no enumeration through timing.
    const ok = await verifyAuthSecret(user?.password_hash ?? null, authSecret);
    if (!user || !ok) throw unauthorized("invalid username or password");
    if (user.status !== "active") {
      throw unauthorized(`account suspended: ${user.status_reason ?? "contact moderation"}`);
    }

    const session = await createSession(db, user.id, config.sessionTtlMs, label);
    await pruneSessions(db);
    const vault = await db.get<{ sealed: string }>(
      "SELECT sealed FROM vaults WHERE user_id = ?",
      [user.id],
    );
    return replyWithSession(reply, config, {
      id: user.id,
      username: user.username,
      role: user.role,
      token: session.token,
      expiresAt: session.expiresAt,
      sealedVault: vault ? JSON.parse(vault.sealed) : null,
    });
  });

  app.post("/api/auth/logout", async (request, reply) => {
    const user = await app.authenticate(request);
    await destroySession(db, user.sessionId);
    reply.header("set-cookie", [
      sessionCookie(config, "", 0),
      csrfCookie(config, "", 0),
    ]);
    return { ok: true };
  });

  app.post("/api/auth/logout-everywhere", async (request, reply) => {
    const user = await app.authenticate(request);
    await destroyAllSessions(db, user.id);
    reply.header("set-cookie", [sessionCookie(config, "", 0), csrfCookie(config, "", 0)]);
    return { ok: true };
  });

  app.get("/api/auth/me", async (request) => {
    const user = await app.authenticate(request);
    const row = await db.get<{ created_day: number }>(
      "SELECT created_day FROM users WHERE id = ?",
      [user.id],
    );
    const seller = await db.get<{ display_name: string; status: string }>(
      "SELECT display_name, status FROM sellers WHERE user_id = ?",
      [user.id],
    );
    return {
      id: user.id,
      username: user.username,
      role: user.role,
      memberSince: row ? dayToIsoDate(row.created_day) : null,
      seller: seller ? { displayName: seller.display_name, status: seller.status } : null,
    };
  });

  app.get("/api/auth/sessions", async (request) => {
    const user = await app.authenticate(request);
    const rows = await db.all<{
      id: string;
      label: string | null;
      created_at: number;
      expires_at: number;
      last_seen_day: number;
    }>(
      "SELECT id, label, created_at, expires_at, last_seen_day FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
      [user.id],
    );
    return {
      sessions: rows.map((row) => ({
        id: row.id,
        label: row.label,
        current: row.id === user.sessionId,
        createdOn: dayToIsoDate(Math.floor(row.created_at / 86_400_000)),
        lastSeenOn: dayToIsoDate(row.last_seen_day),
        expiresOn: dayToIsoDate(Math.floor(row.expires_at / 86_400_000)),
      })),
    };
  });

  app.delete("/api/auth/sessions/:id", async (request) => {
    const user = await app.authenticate(request);
    const { id } = request.params as { id: string };
    const row = await db.get<{ id: string }>(
      "SELECT id FROM sessions WHERE id = ? AND user_id = ?",
      [id, user.id],
    );
    if (!row) throw badRequest("no such session", "not_found");
    await destroySession(db, id);
    return { ok: true };
  });
}

function replyWithSession(
  reply: FastifyReply,
  config: FastifyInstance["config"],
  payload: {
    id: string;
    username: string;
    role: string;
    token: string;
    expiresAt: number;
    sealedVault?: unknown;
  },
) {
  const maxAge = Math.floor((payload.expiresAt - Date.now()) / 1000);
  const csrf = randomToken(24);
  reply.header("set-cookie", [
    sessionCookie(config, payload.token, maxAge),
    csrfCookie(config, csrf, maxAge),
  ]);
  return {
    id: payload.id,
    username: payload.username,
    role: payload.role,
    csrfToken: csrf,
    sealedVault: payload.sealedVault ?? null,
  };
}
