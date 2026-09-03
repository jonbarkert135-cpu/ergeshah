/**
 * Configuration. Everything has a safe default except the secrets, which have no
 * default at all in production — the server refuses to start rather than run with a
 * guessable pepper.
 */
import { readFileSync } from "node:fs";
import { resolveLimits, type Limits } from "./lib/rate_limit.ts";

export type Dialect = "sqlite" | "postgres";

export interface Config {
  env: "development" | "production" | "test";
  host: string;
  port: number;
  dialect: Dialect;
  sqlitePath: string;
  postgresUrl: string | null;
  /** Secret used to derive daily rotating rate-limit bucket keys from client addresses. */
  bucketPepper: string;
  /**
   * `false`, `true`, or the addresses of the proxies to believe (`"10.0.0.1"`,
   * `"127.0.0.1/8, ::1"`). A bare `true` believes `X-Forwarded-For` from whoever connects,
   * which is only safe when nothing but the proxy can reach the port.
   */
  trustProxy: boolean | string;
  sessionTtlMs: number;
  /** Days a session may go unused before it is deleted, independent of `sessionTtlMs`. */
  sessionIdleDays: number;
  /**
   * Leading zero bits a client must find before an unauthenticated account endpoint will
   * look at its request. 0 disables the gate — supported, because an invite-only instance
   * behind a VPN has nothing to defend against, and documented as the trade it is.
   */
  powBits: number;
  envelopeTtlMs: number;
  maxEnvelopeBytes: number;
  /** Ciphertext cap for one order delivery, in bytes before base64url expansion. */
  maxDeliveryBytes: number;
  deliveryTtlMs: number;
  /** How long administrative audit entries are kept before housekeeping deletes them. */
  auditRetentionMs: number;
  /** How long a read or unread notification stays in an inbox. An inbox is not a history. */
  notificationRetentionMs: number;
  /**
   * Sockets this process will hold at once. Beyond it the kernel queues, which is a
   * slow visitor rather than an out-of-memory kill (point 86).
   */
  maxConnections: number;
  /** Server-side ceiling on one SQL statement. PostgreSQL only; SQLite has no equivalent. */
  dbStatementTimeoutMs: number;
  /** Per-operation token buckets, `DEFAULT_LIMITS` overridden by `RATE_LIMITS`. */
  rateLimits: Limits;
  /** Bytes that must stay free before this server accepts another blob. 0 disables the floor. */
  storageFloorBytes: number;
  /** v3 onion address of this service, advertised to Tor Browser. Empty = not published. */
  onionHostname: string;
  behindTls: boolean;
}

/**
 * Reads a secret from the environment, or from a file named by `<NAME>_FILE`. The second
 * form is how Docker and Kubernetes hand secrets to a container: a file mounted from a
 * secret store, never a value in `docker inspect`, a shell history or a crash dump.
 */
function secretFromEnv(name: string): string | undefined {
  const file = process.env[`${name}_FILE`];
  if (file) {
    try {
      return readFileSync(file, "utf8").trim();
    } catch (error) {
      throw new Error(`${name}_FILE is set to ${file}, which cannot be read: ${(error as Error).message}`);
    }
  }
  return process.env[name];
}

/** The prefix that makes a development fallback obviously not a secret, on sight and in code. */
const DEVELOPMENT_SECRET_PREFIX = "development-only-";

function requiredSecret(name: string, env: string): string {
  const value = secretFromEnv(name);
  if (value && value.length >= 32) {
    // A development value that reached production is the failure mode point 91 is about:
    // it is long enough to pass the length check, it is in a `.env` somebody copied, and
    // nothing else would ever notice. The name says what it is, so this can be checked.
    if (env === "production" && value.startsWith(DEVELOPMENT_SECRET_PREFIX)) {
      throw new Error(
        `${name} is a development placeholder and must not be used in production — generate one with 'openssl rand -base64 48'`,
      );
    }
    return value;
  }
  if (env === "production") {
    throw new Error(
      `${name} (or ${name}_FILE) must be set to at least 32 random characters in production (see .env.example)`,
    );
  }
  return `${DEVELOPMENT_SECRET_PREFIX}${name}-not-secret-0000000000`;
}

/**
 * Three environments, and no fourth (point 91). A typo — `NODE_ENV=prod`, `Production` —
 * currently reads as "not production", which silently turns off every strict check the
 * production path adds. That is the wrong direction for a mistake to fail in.
 */
export function parseEnvironment(value: string | undefined): Config["env"] {
  if (value === undefined || value.trim() === "") return "development";
  if (value === "development" || value === "test" || value === "production") return value;
  throw new Error(`NODE_ENV must be development, test or production (got ${JSON.stringify(value)})`);
}

/**
 * Difficulty, in leading zero bits. Each bit doubles the expected work, so this is the one
 * number in the file where a typo of one digit is the difference between a speed bump and
 * a locked door — which is why it is validated at boot rather than discovered in
 * production.
 *
 * The default of 16 costs roughly 65,000 hashes: a fraction of a second in a browser, and
 * a real bill for anyone opening accounts in bulk, because they pay it per attempt. It is
 * a cost that composes with the rate limiter rather than replacing it; raise it while an
 * attack is on and put it back afterwards. Above 20 the tail of the distribution — this
 * is a random search, and 5% of attempts take three times the average — starts producing
 * waits that users experience as a broken sign-in button.
 */
function powBits(value: string | undefined): number {
  if (value === undefined || value.trim() === "") return 16;
  const bits = Number(value);
  if (!Number.isInteger(bits) || bits < 0 || bits > 24) {
    throw new Error("POW_BITS must be a whole number between 0 (off) and 24");
  }
  return bits;
}

/**
 * `TRUST_PROXY` used to be a boolean, and `true` means "believe `X-Forwarded-For` from
 * whoever connected". That is correct behind a proxy on a private network and a rate-limit
 * bypass anywhere else, so the variable also takes the proxy addresses themselves — which
 * is the same setting with the trust narrowed to the machine that earned it.
 */
function trustProxy(value: string | undefined): boolean | string {
  if (value === undefined || value.trim() === "" || value === "false") return false;
  if (value === "true") return true;
  return value.trim();
}

/**
 * A limit that is meant to protect the machine has to be a number the machine can use: a
 * typo that reads as `NaN` would disable the very ceiling it configures, silently. So the
 * parse is strict and boot fails instead.
 */
export function positiveInteger(name: string, value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a whole number of at least 1`);
  }
  return parsed;
}

const ONION_V3 = /^[a-z2-7]{56}\.onion$/;

/**
 * Validated at boot rather than trusted: this string is put into a header that tells Tor
 * Browser where to redirect, so a typo or an injected value is worth catching here.
 */
function onionHostname(value: string | undefined): string {
  if (!value) return "";
  const host = value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (!ONION_V3.test(host)) {
    throw new Error("ONION_HOSTNAME must be a v3 onion address, e.g. abcd…56chars….onion");
  }
  return host;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const env = parseEnvironment(process.env.NODE_ENV);
  return {
    env,
    host: process.env.HOST ?? "127.0.0.1",
    port: Number(process.env.PORT ?? 8080),
    dialect: (process.env.DB_DIALECT as Dialect) ?? (process.env.DATABASE_URL ? "postgres" : "sqlite"),
    sqlitePath: process.env.SQLITE_PATH ?? "data/symvolon.sqlite",
    postgresUrl: secretFromEnv("DATABASE_URL") ?? null,
    bucketPepper: requiredSecret("RATE_LIMIT_PEPPER", env),
    trustProxy: trustProxy(process.env.TRUST_PROXY),
    sessionTtlMs: Number(process.env.SESSION_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
    sessionIdleDays: Number(process.env.SESSION_IDLE_DAYS ?? 14),
    powBits: powBits(process.env.POW_BITS),
    envelopeTtlMs: Number(process.env.ENVELOPE_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
    maxEnvelopeBytes: Number(process.env.MAX_ENVELOPE_BYTES ?? 64 * 1024),
    maxDeliveryBytes: Number(process.env.MAX_DELIVERY_BYTES ?? 5 * 1024 * 1024),
    deliveryTtlMs: Number(process.env.DELIVERY_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
    auditRetentionMs: Number(process.env.AUDIT_RETENTION_MS ?? 365 * 24 * 60 * 60 * 1000),
    notificationRetentionMs: Number(process.env.NOTIFICATION_RETENTION_MS ?? 90 * 24 * 60 * 60 * 1000),
    maxConnections: positiveInteger("MAX_CONNECTIONS", process.env.MAX_CONNECTIONS, 512),
    dbStatementTimeoutMs: positiveInteger(
      "DB_STATEMENT_TIMEOUT_MS",
      process.env.DB_STATEMENT_TIMEOUT_MS,
      5_000,
    ),
    storageFloorBytes: Number(process.env.STORAGE_FLOOR_BYTES ?? 512 * 1024 * 1024),
    rateLimits: resolveLimits(process.env.RATE_LIMITS),
    onionHostname: onionHostname(process.env.ONION_HOSTNAME),
    behindTls: process.env.BEHIND_TLS !== "false",
    ...overrides,
  };
}
