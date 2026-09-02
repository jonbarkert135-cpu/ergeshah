import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/server/app.ts";
import { loadConfig, type Config } from "../src/server/config.ts";
import { createSqliteDb } from "../src/server/db/sqlite.ts";
import { migrate } from "../src/server/db/migrate.ts";
import type { Db } from "../src/server/db/index.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import { deriveAccountKeys } from "../src/shared/crypto/vault.ts";
import { toBase64Url } from "../src/shared/encoding.ts";

/** Argon2id parameters are the product; in tests we only care that the plumbing works. */
export const FAST_KDF = { opsLimit: 1, memLimit: 8192 };

export interface TestServer {
  app: FastifyInstance;
  db: Db;
  config: Config;
  close(): Promise<void>;
}

export async function startTestServer(overrides: Partial<Config> = {}): Promise<TestServer> {
  await sodiumReady();
  const config = loadConfig({
    env: "test",
    dialect: "sqlite",
    behindTls: false,
    bucketPepper: `test-pepper-${Math.random()}-0000000000000000`,
    ...overrides,
  });
  const db = createSqliteDb(":memory:");
  await migrate(db);
  const app = await buildApp(config, db);
  await app.ready();
  return {
    app,
    db,
    config,
    async close() {
      await app.close();
      await db.close();
    },
  };
}

interface Response<T> {
  status: number;
  body: T;
}

/** A browser-shaped client: keeps cookies, sends the CSRF header, uses the same origin. */
export class TestClient {
  private cookies = new Map<string, string>();
  readonly server: TestServer;
  username = "";

  constructor(server: TestServer) {
    this.server = server;
  }

  async request<T = Record<string, unknown>>(
    method: string,
    url: string,
    body?: unknown,
    options: { origin?: string; csrf?: string | null } = {},
  ): Promise<Response<T>> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    const cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    if (cookie) headers.cookie = cookie;
    if (method !== "GET") {
      const csrf = options.csrf === undefined ? this.cookies.get("csrf") : options.csrf;
      if (csrf) headers["x-csrf-token"] = csrf;
      headers.origin = options.origin ?? "http://localhost";
      headers.host = "localhost";
    }
    const response = await this.server.app.inject({
      method: method as "GET",
      url,
      headers,
      payload: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const raw of [response.headers["set-cookie"] ?? []].flat()) {
      const [pair] = String(raw).split(";");
      const [name, value] = (pair ?? "").split("=");
      if (!name) continue;
      if (!value) this.cookies.delete(name);
      else this.cookies.set(name, decodeURIComponent(value));
    }
    let parsed: unknown;
    try {
      parsed = response.json();
    } catch {
      parsed = response.body;
    }
    return { status: response.statusCode, body: parsed as T };
  }

  get<T = Record<string, unknown>>(url: string) {
    return this.request<T>("GET", url);
  }
  post<T = Record<string, unknown>>(url: string, body?: unknown) {
    return this.request<T>("POST", url, body);
  }
  patch<T = Record<string, unknown>>(url: string, body?: unknown) {
    return this.request<T>("PATCH", url, body);
  }
  del<T = Record<string, unknown>>(url: string) {
    return this.request<T>("DELETE", url);
  }

  cookie(name: string): string | undefined {
    return this.cookies.get(name);
  }
}

export function authSecretFor(username: string, password: string): string {
  return toBase64Url(deriveAccountKeys(username, password, FAST_KDF).authSecret);
}

export async function register(
  server: TestServer,
  username: string,
  password = "correct horse battery staple",
): Promise<TestClient> {
  const client = new TestClient(server);
  await client.get("/"); // like a browser: load the app, receive a CSRF cookie

  const response = await client.post("/api/auth/register", {
    username,
    authSecret: authSecretFor(username, password),
  });
  if (response.status !== 200) {
    throw new Error(`registration failed: ${JSON.stringify(response.body)}`);
  }
  client.username = username;
  return client;
}

export async function promote(
  server: TestServer,
  username: string,
  role: "moderator" | "admin",
): Promise<void> {
  await server.db.run("UPDATE users SET role = ? WHERE username = ?", [role, username]);
}

export async function approveSeller(
  server: TestServer,
  client: TestClient,
  displayName: string,
): Promise<void> {
  const application = await client.post<{ id: string }>("/api/market/seller-applications", {
    displayName,
    statement: "I will sell carefully written software and design work.",
  });
  const admin = await register(server, `mod${Math.floor(Math.random() * 1e6)}`);
  await promote(server, admin.username, "moderator");
  const decision = await admin.post(
    `/api/moderation/seller-applications/${application.body.id}/decide`,
    { decision: "approved", note: "welcome" },
  );
  if (decision.status !== 200) throw new Error(`approval failed: ${JSON.stringify(decision.body)}`);
}
