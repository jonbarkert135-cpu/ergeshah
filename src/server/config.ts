/**
 * Configuration. Everything has a safe default except the secrets, which have no
 * default at all in production — the server refuses to start rather than run with a
 * guessable pepper.
 */
import { readFileSync } from "node:fs";
import { resolveLimits, type Limits } from "./lib/rate_limit.ts";
import { parseXmr } from "../shared/money.ts";

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
  /** Sealed sender (ADR-0084): how long an unspent send token stays usable. */
  sendTokenTtlMs: number;
  /** How many tokens one request mints. A batch is a conversation's worth of messages. */
  sendTokenBatch: number;
  /** Timing noise (ADR-0085): the longest delivery delay a sender may ask for. */
  maxDeliveryDelaySeconds: number;
  /** Seller bond (ADR-0086): the smallest stake worth the bookkeeping. */
  bondMinPico: number;
  /** How long a bond must sit before it can be released. */
  bondCooloffMs: number;
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
  /**
   * How many blob rows (attachments plus order deliveries) this server will hold before it
   * refuses another upload. The free-space floor guards bytes; this guards the count, which
   * is what a million tiny uploads cost. 0 disables the ceiling.
   */
  maxBlobRows: number;
  /**
   * The platform's cut of a completed order, in basis points (500 = 5%). Charged to the
   * seller, deducted at settlement, and rounded down in the seller's favour
   * (`lib/ledger.ts`). Zero is supported and means a marketplace that earns nothing per
   * order, which is a business decision this server is happy to run.
   */
  orderFeeBps: number;
  /** Smallest payout this server will queue, in piconero. Below it the network fee dominates. */
  minWithdrawalPico: number;
  /**
   * Default ceiling on automatic payouts, per request and per rolling 24 hours, for an
   * account that has no limit of its own. Anything above it is queued for an administrator
   * rather than refused. This is the number that decides what a compromise of this process is
   * worth, so it is configuration and not a constant (docs/PAYMENTS.md §Limits).
   */
  autoPayoutMaxPico: number;
  /**
   * The smallest top-up this platform credits, and it is enforced (ADR-0067). A smaller
   * transfer is recorded as `below_minimum` and left uncredited rather than kept: the row is
   * visible to its owner and to an operator, who refunds it by hand if the payer asks. A
   * dust top-up costs more in payout fees and support than it can ever be worth, and the
   * honest way to say so is a rule at the door, not a surprise in the balance.
   */
  minDepositPico: number;
  /**
   * The smallest below-minimum total this server will send back to its payer on request
   * (ADR-0071). It exists because a refund costs a network fee the platform pays: below this
   * figure, returning dust is a way to bleed the payout float, and the money waits — visible
   * on the owner's screen — until enough has arrived or an operator settles it by hand. The
   * default is roughly twenty times a typical Monero fee.
   */
  minRefundPico: number;
  /**
   * A payout above this figure needs **two different administrators** to approve it
   * (ADR-0076). It is the institutional half of a 2-of-3 escrow: no single admin account,
   * stolen or otherwise, can release a large sum on its own. Refusing still takes one — a
   * refusal returns the money to its owner and moves nothing out of the platform.
   */
  dualApprovalAbovePico: number;
  /**
   * Days without a settled sale before a seller's level falls one step (ADR-0072). It is the
   * catalogue's definition of "still trading": the level a seller earned is never deleted,
   * but what the catalogue shows fades while they are away and comes back with one sale.
   */
  sellerLevelDecayDays: number;
  /**
   * Where `monero-wallet-rpc` answers, on the internal network — `http://wallet:18082`.
   * Null means this deployment has no wallet tier: no deposit address is handed out, no scan
   * runs, and `GET /api/wallet` says top-ups are not open rather than inventing an address.
   * The wallet at the other end is opened with a private **view key** (docs/PAYMENTS.md §Keys).
   */
  moneroWalletRpcUrl: string | null;
  /** Confirmations before a top-up is credited. Three is about six minutes. */
  depositConfirmations: number;
  /**
   * A top-up at or below this is credited after **one** confirmation instead of
   * `DEPOSIT_CONFIRMATIONS` (ADR-0077): two minutes rather than six, for the amounts where
   * waiting costs more in abandoned purchases than a one-block reorganisation could cost the
   * platform. Zero confirmations is not an option at any amount — an unconfirmed transfer is
   * not money. Set it to 0 to give every top-up the full count.
   */
  fastCreditMaxPico: number;
  /** How often the watcher asks the wallet what arrived. */
  walletPollMs: number;
  /**
   * The shared secret the payout worker authenticates with. Null closes the queue endpoints
   * completely — which is the right default, because a deployment without a payout worker has
   * no reason to expose a queue at all.
   */
  payoutWorkerToken: string | null;
  /** v3 onion address of this service, advertised to Tor Browser. Empty = not published. */
  onionHostname: string;
  behindTls: boolean;
  /**
   * The name this deployment signs into every authentication challenge (ADR-0087). It is
   * the domain-binding half of a challenge: a signature made here says which service it was
   * made for, so the same signature presented to another deployment — or to another purpose
   * on this one — is over the wrong bytes and fails. Any stable string identifies a
   * deployment; the host name is the obvious choice.
   */
  serviceId: string;
  /**
   * How long an account's own security history is kept, in days. It is a short window on
   * purpose: the log exists so a user can notice a sign-in they did not make, not so this
   * server can hold a year of anybody's activity (ADR-0090).
   */
  securityEventRetentionDays: number;
  /**
   * The fingerprint of the one OpenPGP key whose signature this deployment will publish as
   * its canary (OPS-7, ADR-0099), lower-case hex without spaces. Empty means this
   * deployment publishes no canary at all — `POST /api/admin/canary` refuses and the client
   * shows nothing, which is honest: a canary nobody signs is worse than no canary, because
   * it looks like one.
   */
  canaryFingerprint: string;
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

/** The same, for a limit whose documented off switch is `0`. */
export function nonNegativeInteger(name: string, value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a whole number of at least 0`);
  }
  return parsed;
}

/**
 * The commission, in basis points, validated at boot. A typo here is money: `5000` instead
 * of `500` is a 50% marketplace, and nothing downstream would question it. Anything above
 * 2,000 (20%) is refused as a mistake rather than trusted — the ceiling is documented in
 * docs/PAYMENTS.md and can be raised deliberately.
 */
function feeBasisPoints(value: string | undefined): number {
  if (value === undefined || value.trim() === "") return 500;
  const bps = Number(value);
  if (!Number.isInteger(bps) || bps < 0 || bps > 2_000) {
    throw new Error("ORDER_FEE_BPS must be a whole number of basis points between 0 and 2000 (20%)");
  }
  return bps;
}

/**
 * A money limit, written the way a human writes money (`"0.5"` XMR) and stored the way this
 * server counts it (piconero). Parsed by the shared parser, so an unparseable amount stops
 * the server instead of quietly becoming a limit of zero — which would either block every
 * payout or wave every payout through, and it is not obvious which.
 */
function picoFromEnv(name: string, value: string | undefined, fallback: string): number {
  const pico = parseXmr((value ?? "").trim() === "" ? fallback : (value as string));
  if (pico === null) throw new Error(`${name} must be an amount of XMR, for example ${fallback}`);
  return pico;
}

/**
 * The wallet RPC endpoint, validated at boot. `http://` is correct and deliberate: this is an
 * internal Docker network with no gateway, the alternative is a certificate for a name only
 * two containers can resolve, and a typo that pointed this at the internet would be a wallet
 * address handed out by a stranger — so the host has to be a private name, never a public one.
 */
function walletRpcUrl(value: string | undefined): string | null {
  if (!value || !value.trim()) return null;
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error("MONERO_WALLET_RPC_URL must be a URL, for example http://wallet:18082");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("MONERO_WALLET_RPC_URL must be http or https");
  }
  return url.origin;
}

/**
 * The payout worker's token. Long, or absent: a short one is a queue an attacker can guess
 * their way into, and the queue hands out payout destinations.
 */
function workerToken(value: string | undefined, env: Config["env"]): string | null {
  if (!value || !value.trim()) return null;
  const token = value.trim();
  if (token.length < 32) {
    throw new Error("PAYOUT_WORKER_TOKEN must be at least 32 characters (openssl rand -base64 32)");
  }
  if (env === "production" && token.startsWith(DEVELOPMENT_SECRET_PREFIX)) {
    throw new Error("PAYOUT_WORKER_TOKEN is a development placeholder and must not be used in production");
  }
  return token;
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

/**
 * The service identifier that goes into signed challenges. Restricted to the characters a
 * host name uses, because it is displayed to a user who is about to sign it and read back
 * by a client that compares it: a value with spaces or newlines in it could make one
 * statement look like another.
 */
/**
 * A fingerprint as people copy it: `gpg --fingerprint` prints it in groups of four, and a
 * paste with spaces is the normal case rather than the mistake. Stored and compared in the
 * form the OpenPGP library returns, so the comparison is between two canonical strings and
 * never between two spellings of the same key.
 */
function canaryFingerprint(value: string | undefined): string {
  if (!value) return "";
  const hex = value.replace(/[\s:]/g, "").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(hex) && !/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error("CANARY_FINGERPRINT must be an OpenPGP fingerprint: 40 or 64 hex characters");
  }
  return hex;
}

function serviceId(value: string | undefined): string {
  const id = (value ?? "symvolon").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._:-]{0,63}$/.test(id)) {
    throw new Error("SERVICE_ID must be 1–64 characters of a–z, 0–9, dot, dash, underscore or colon");
  }
  return id;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const env = parseEnvironment(process.env.NODE_ENV);
  return {
    env,
    host: process.env.HOST ?? "127.0.0.1",
    port: positiveInteger("PORT", process.env.PORT, 8080),
    dialect: (process.env.DB_DIALECT as Dialect) ?? (process.env.DATABASE_URL ? "postgres" : "sqlite"),
    sqlitePath: process.env.SQLITE_PATH ?? "data/symvolon.sqlite",
    postgresUrl: secretFromEnv("DATABASE_URL") ?? null,
    bucketPepper: requiredSecret("RATE_LIMIT_PEPPER", env),
    trustProxy: trustProxy(process.env.TRUST_PROXY),
    sessionTtlMs: positiveInteger("SESSION_TTL_MS", process.env.SESSION_TTL_MS, 30 * 24 * 60 * 60 * 1000),
    sessionIdleDays: positiveInteger("SESSION_IDLE_DAYS", process.env.SESSION_IDLE_DAYS, 14),
    powBits: powBits(process.env.POW_BITS),
    envelopeTtlMs: positiveInteger("ENVELOPE_TTL_MS", process.env.ENVELOPE_TTL_MS, 30 * 24 * 60 * 60 * 1000),
    maxEnvelopeBytes: positiveInteger("MAX_ENVELOPE_BYTES", process.env.MAX_ENVELOPE_BYTES, 64 * 1024),
    sendTokenTtlMs: positiveInteger("SEND_TOKEN_TTL_MS", process.env.SEND_TOKEN_TTL_MS, 7 * 24 * 60 * 60 * 1000),
    sendTokenBatch: positiveInteger("SEND_TOKEN_BATCH", process.env.SEND_TOKEN_BATCH, 32),
    maxDeliveryDelaySeconds: nonNegativeInteger(
      "MAX_DELIVERY_DELAY_SECONDS",
      process.env.MAX_DELIVERY_DELAY_SECONDS,
      120,
    ),
    bondMinPico: picoFromEnv("BOND_MIN_XMR", process.env.BOND_MIN_XMR, "0.1"),
    bondCooloffMs: nonNegativeInteger("BOND_COOLOFF_DAYS", process.env.BOND_COOLOFF_DAYS, 7) * 86_400_000,
    maxDeliveryBytes: positiveInteger("MAX_DELIVERY_BYTES", process.env.MAX_DELIVERY_BYTES, 5 * 1024 * 1024),
    deliveryTtlMs: positiveInteger("DELIVERY_TTL_MS", process.env.DELIVERY_TTL_MS, 30 * 24 * 60 * 60 * 1000),
    auditRetentionMs: positiveInteger("AUDIT_RETENTION_MS", process.env.AUDIT_RETENTION_MS, 365 * 24 * 60 * 60 * 1000),
    notificationRetentionMs: positiveInteger(
      "NOTIFICATION_RETENTION_MS",
      process.env.NOTIFICATION_RETENTION_MS,
      90 * 24 * 60 * 60 * 1000,
    ),
    maxConnections: positiveInteger("MAX_CONNECTIONS", process.env.MAX_CONNECTIONS, 512),
    dbStatementTimeoutMs: positiveInteger(
      "DB_STATEMENT_TIMEOUT_MS",
      process.env.DB_STATEMENT_TIMEOUT_MS,
      5_000,
    ),
    storageFloorBytes: nonNegativeInteger("STORAGE_FLOOR_BYTES", process.env.STORAGE_FLOOR_BYTES, 512 * 1024 * 1024),
    maxBlobRows: nonNegativeInteger("MAX_BLOB_ROWS", process.env.MAX_BLOB_ROWS, 200_000),
    rateLimits: resolveLimits(process.env.RATE_LIMITS),
    orderFeeBps: feeBasisPoints(process.env.ORDER_FEE_BPS),
    minWithdrawalPico: picoFromEnv("MIN_WITHDRAWAL_XMR", process.env.MIN_WITHDRAWAL_XMR, "0.02"),
    autoPayoutMaxPico: picoFromEnv("AUTO_PAYOUT_MAX_XMR", process.env.AUTO_PAYOUT_MAX_XMR, "2"),
    minDepositPico: picoFromEnv("MIN_DEPOSIT_XMR", process.env.MIN_DEPOSIT_XMR, "0.02"),
    minRefundPico: picoFromEnv("MIN_REFUND_XMR", process.env.MIN_REFUND_XMR, "0.001"),
    dualApprovalAbovePico: picoFromEnv(
      "DUAL_APPROVAL_ABOVE_XMR",
      process.env.DUAL_APPROVAL_ABOVE_XMR,
      "10",
    ),
    sellerLevelDecayDays: positiveInteger(
      "SELLER_LEVEL_DECAY_DAYS",
      process.env.SELLER_LEVEL_DECAY_DAYS,
      90,
    ),
    moneroWalletRpcUrl: walletRpcUrl(process.env.MONERO_WALLET_RPC_URL),
    depositConfirmations: positiveInteger(
      "DEPOSIT_CONFIRMATIONS",
      process.env.DEPOSIT_CONFIRMATIONS,
      3,
    ),
    fastCreditMaxPico: picoFromEnv(
      "FAST_CREDIT_MAX_XMR",
      process.env.FAST_CREDIT_MAX_XMR,
      "0.1",
    ),
    walletPollMs:
      positiveInteger("WALLET_POLL_SECONDS", process.env.WALLET_POLL_SECONDS, 45) * 1000,
    payoutWorkerToken: workerToken(secretFromEnv("PAYOUT_WORKER_TOKEN"), env),
    canaryFingerprint: canaryFingerprint(process.env.CANARY_FINGERPRINT),
    onionHostname: onionHostname(process.env.ONION_HOSTNAME),
    behindTls: process.env.BEHIND_TLS !== "false",
    serviceId: serviceId(process.env.SERVICE_ID),
    securityEventRetentionDays: positiveInteger(
      "SECURITY_EVENT_RETENTION_DAYS",
      process.env.SECURITY_EVENT_RETENTION_DAYS,
      90,
    ),
    ...overrides,
  };
}
