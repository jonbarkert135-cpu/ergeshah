/**
 * The only thing in this server that writes a log line (point 51).
 *
 * Logging is where privacy promises go to die: not through a decision, but through one
 * convenient `console.log(request.body)` added while debugging and never removed. So this
 * module is narrow on purpose — three event shapes, a fixed set of fields, and a scrubber
 * that runs on every value on the way out.
 *
 * The policy in one line: log what an operator needs to keep the service alive and to
 * investigate abuse of the *marketplace*, and nothing that identifies who talked to whom or
 * what they said. `docs/LOGGING.md` states what is logged, why, for how long, who can read it
 * and when it is deleted; `test/logging.test.ts` enforces the forbidden list.
 */

/** Never logged, in any field, at any level. If one appears in a message, it is redacted. */
const FORBIDDEN_KEYS = [
  "password",
  "authsecret",
  "secret",
  "token",
  "cookie",
  "session",
  "authorization",
  "privatekey",
  "private_key",
  "masterkey",
  "vault",
  "payload",
  "ciphertext",
  "plaintext",
  "recoveryphrase",
  "mnemonic",
  "pepper",
  "key=",
];

/**
 * Long opaque strings are what keys, tokens and ciphertext look like once they are in a
 * message: a 40-character run of base64/hex characters is never something a reader needs, and
 * it is exactly what must not be persisted.
 */
const SECRET_SHAPED = /[A-Za-z0-9+/_=-]{40,}/g;

/** Anything that looks like an address: an error message can carry one, and none is kept. */
const ADDRESS_SHAPED =
  /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:{1,2}){2,}[0-9a-f]{0,4}\b/gi;

export function scrub(value: unknown): string {
  const text = typeof value === "string" ? value : String(value);
  const withoutSecrets = text.replace(SECRET_SHAPED, "[redacted]").replace(ADDRESS_SHAPED, "[address]");
  // A message that *names* a secret (`invalid session token abc`) loses the whole message
  // rather than being trusted to have quoted it safely.
  const lowered = withoutSecrets.toLowerCase();
  return FORBIDDEN_KEYS.some((key) => lowered.includes(key)) ? "[redacted]" : withoutSecrets;
}

export interface LogEvent {
  level: "error" | "info";
  /** What happened, from a fixed vocabulary chosen by the caller (`request.failed`, `boot`). */
  event: string;
  /** A short reference a user can quote in a support conversation. Not an identifier. */
  ref?: string;
  /** The route *pattern*, never the concrete URL — `/api/market/orders/:id`, not an order id. */
  route?: string;
  method?: string;
  name?: string;
  message?: string;
  /** Numbers only: counts, durations, sizes. */
  metrics?: Record<string, number>;
}

/**
 * One line of JSON on stderr. No transport, no log file, no rotation: the process manager
 * (systemd, Docker) owns the stream, which is also where the retention window is configured —
 * see `docs/LOGGING.md`.
 */
export function log(event: LogEvent): void {
  const line: Record<string, unknown> = {
    at: new Date().toISOString(),
    level: event.level,
    event: event.event,
  };
  if (event.ref) line.ref = event.ref;
  if (event.method) line.method = event.method;
  if (event.route) line.route = scrub(event.route);
  if (event.name) line.name = scrub(event.name);
  if (event.message) line.message = scrub(event.message);
  if (event.metrics) line.metrics = event.metrics;
  process.stderr.write(`${JSON.stringify(line)}\n`);
}
