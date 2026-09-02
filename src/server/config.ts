/**
 * Configuration. Everything has a safe default except the secrets, which have no
 * default at all in production — the server refuses to start rather than run with a
 * guessable pepper.
 */
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
  trustProxy: boolean;
  sessionTtlMs: number;
  envelopeTtlMs: number;
  maxEnvelopeBytes: number;
  /** Ciphertext cap for one order delivery, in bytes before base64url expansion. */
  maxDeliveryBytes: number;
  deliveryTtlMs: number;
  /** How long administrative audit entries are kept before housekeeping deletes them. */
  auditRetentionMs: number;
  /** v3 onion address of this service, advertised to Tor Browser. Empty = not published. */
  onionHostname: string;
  behindTls: boolean;
}

function requiredSecret(name: string, env: string): string {
  const value = process.env[name];
  if (value && value.length >= 32) return value;
  if (env === "production") {
    throw new Error(
      `${name} must be set to at least 32 random characters in production (see .env.example)`,
    );
  }
  return `development-only-${name}-not-secret-0000000000`;
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
  const env = (process.env.NODE_ENV as Config["env"]) ?? "development";
  return {
    env,
    host: process.env.HOST ?? "127.0.0.1",
    port: Number(process.env.PORT ?? 8080),
    dialect: (process.env.DB_DIALECT as Dialect) ?? (process.env.DATABASE_URL ? "postgres" : "sqlite"),
    sqlitePath: process.env.SQLITE_PATH ?? "data/symvolon.sqlite",
    postgresUrl: process.env.DATABASE_URL ?? null,
    bucketPepper: requiredSecret("RATE_LIMIT_PEPPER", env),
    trustProxy: process.env.TRUST_PROXY === "true",
    sessionTtlMs: Number(process.env.SESSION_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
    envelopeTtlMs: Number(process.env.ENVELOPE_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
    maxEnvelopeBytes: Number(process.env.MAX_ENVELOPE_BYTES ?? 64 * 1024),
    maxDeliveryBytes: Number(process.env.MAX_DELIVERY_BYTES ?? 5 * 1024 * 1024),
    deliveryTtlMs: Number(process.env.DELIVERY_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
    auditRetentionMs: Number(process.env.AUDIT_RETENTION_MS ?? 365 * 24 * 60 * 60 * 1000),
    onionHostname: onionHostname(process.env.ONION_HOSTNAME),
    behindTls: process.env.BEHIND_TLS !== "false",
    ...overrides,
  };
}
