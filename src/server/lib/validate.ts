/** Input validation. Everything that reaches the database goes through here first. */
import { badRequest } from "./errors.ts";
import { base64UrlBytes } from "../../shared/uploads.ts";
import { MAX_PRICE_PICO, MIN_PRICE_PICO, XMR_DECIMALS, parseXmr, xmrString } from "../../shared/money.ts";

const USERNAME_RE = /^[a-z0-9](?:[a-z0-9_.-]{1,30})[a-z0-9]$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Characters that are invisible or that reorder what follows them. They belong in no field
 * this API accepts, and they are how a display name reads "Alice" while resolving to
 * something else — the classic marketplace impersonation trick, and a way to smuggle text
 * past a moderator reading the same string.
 */
// eslint-disable-next-line no-control-regex
const DANGEROUS_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

/**
 * A single-line field: everything except prose. Line breaks are refused here rather than
 * stored, because a name, a title or a device label that spans three lines is a spoofing
 * tool — it pushes text out of a card, hides the real value below the fold, and reads
 * differently to a moderator than to a buyer. Prose fields opt in through `asText`.
 */
export function asString(value: unknown, field: string, max: number, min = 1): string {
  const text = clean(value, field, max, min);
  if (/[\r\n]/.test(text)) throw badRequest(`${field} must be a single line`, "invalid_characters");
  return text;
}

export function asOptionalString(value: unknown, field: string, max: number): string {
  if (value === undefined || value === null || value === "") return "";
  return asString(value, field, max, 0);
}

/**
 * A field where line breaks are the point: a description, a statement, a dispute reason,
 * a moderator's note, an ASCII-armoured PGP key. Line endings are normalised rather than
 * refused — a paste from Windows carries CRLF, and rejecting it would be a validator
 * teaching users that the software is broken.
 */
export function asText(value: unknown, field: string, max: number, min = 1): string {
  if (typeof value !== "string") throw badRequest(`${field} must be a string`);
  return clean(value.replace(/\r\n?/g, "\n"), field, max, min);
}

export function asOptionalText(value: unknown, field: string, max: number): string {
  if (value === undefined || value === null || value === "") return "";
  return asText(value, field, max, 0);
}

function clean(value: unknown, field: string, max: number, min: number): string {
  if (typeof value !== "string") throw badRequest(`${field} must be a string`);
  // Canonicalise first, then measure: "e\u0301" and "é" must not have different limits,
  // and a length check on the unnormalised form is a length check on the wrong string.
  const normalized = value.normalize("NFC");
  if (DANGEROUS_CHARS.test(normalized)) {
    throw badRequest(`${field} contains characters that are not allowed`, "invalid_characters");
  }
  const trimmed = normalized.trim();
  if (trimmed.length < min) throw badRequest(`${field} is too short`);
  if (trimmed.length > max) throw badRequest(`${field} is longer than ${max} characters`);
  return trimmed;
}

export function asUsername(value: unknown): string {
  const username = asString(value, "username", 32, 3).normalize("NFKC").toLowerCase();
  if (!USERNAME_RE.test(username)) {
    throw badRequest(
      "username must be 3-32 characters of a-z, 0-9, dot, dash or underscore, starting and ending with a letter or digit",
      "invalid_username",
    );
  }
  return username;
}

/**
 * Base64url, capped by the number of bytes it *decodes to* — not by its length in
 * characters, which is a third larger and made every documented cap a lie by 33% (point 49).
 * A string of length `4n + 1` is rejected outright: it is not base64.
 */
export function asBase64Url(value: unknown, field: string, maxBytes: number): string {
  const text = asString(value, field, Math.ceil((maxBytes * 4) / 3) + 8);
  if (!BASE64URL_RE.test(text)) throw badRequest(`${field} must be base64url`);
  const bytes = base64UrlBytes(text);
  if (bytes === null) throw badRequest(`${field} is not valid base64url`);
  if (bytes > maxBytes) throw badRequest(`${field} is larger than ${maxBytes} bytes`, "too_large");
  return text;
}

/**
 * Rejects a request body that carries fields this endpoint does not accept.
 *
 * Ignoring unknown fields is the usual choice and it is the wrong one for an upload: a client
 * that sends `filename`, `mimeType` or `contentType` is telling the server something about a
 * file, and the answer has to be "this server does not want to know" — loudly, so nobody
 * builds a client that depends on being believed, and so no future handler starts reading it.
 */
export function onlyKeys(body: unknown, allowed: readonly string[], field = "body"): void {
  if (body === undefined || body === null) return;
  if (typeof body !== "object" || Array.isArray(body)) throw badRequest(`${field} must be an object`);
  const unexpected = Object.keys(body as Record<string, unknown>).filter(
    (key) => !allowed.includes(key),
  );
  if (unexpected.length > 0) {
    throw badRequest(
      `${field} does not accept: ${unexpected.sort().join(", ")}`,
      "unexpected_field",
    );
  }
}

export function asInteger(value: unknown, field: string, min: number, max: number): number {
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(number)) throw badRequest(`${field} must be an integer`);
  if (number < min || number > max) throw badRequest(`${field} must be between ${min} and ${max}`);
  return number;
}

export function asEnum<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw badRequest(`${field} must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

export function asId(value: unknown, field: string): string {
  const id = asString(value, field, 64);
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(id)) throw badRequest(`${field} is not a valid id`);
  return id;
}

export function asArray(value: unknown, field: string, maxLength: number): unknown[] {
  if (!Array.isArray(value)) throw badRequest(`${field} must be an array`);
  if (value.length > maxLength) throw badRequest(`${field} may contain at most ${maxLength} items`);
  return value;
}

/**
 * A price, in the only currency this marketplace has: XMR, written as a decimal string and
 * stored as piconero.
 *
 * A string and not a number, and this is the validator that insists on it. A JSON number
 * with twelve decimals is a double, a double cannot hold every piconero, and a price that
 * arrives 1e-12 off is an amount no payment will ever match exactly. Free (`"0"`) is
 * allowed; anything between zero and the dust floor is not, because a price smaller than the
 * fee to move it is a promise the network cannot keep (`src/shared/money.ts`).
 */
export function asXmrPrice(value: unknown, field: string): number {
  if (typeof value !== "string") {
    throw badRequest(`${field} must be a decimal string of XMR, for example "0.045"`);
  }
  const pico = parseXmr(value);
  if (pico === null) {
    throw badRequest(`${field} must be an amount of XMR with at most ${XMR_DECIMALS} decimals`);
  }
  if (pico > MAX_PRICE_PICO) {
    throw badRequest(`${field} must not exceed ${xmrString(MAX_PRICE_PICO)} XMR`);
  }
  if (pico !== 0 && pico < MIN_PRICE_PICO) {
    throw badRequest(`${field} must be 0 or at least ${xmrString(MIN_PRICE_PICO)} XMR`, "below_dust");
  }
  return pico;
}

/**
 * An amount of XMR a user asks this server to move, as opposed to a price on a listing:
 * strictly positive, at least `minPico`, and capped by the same ceiling prices have.
 */
export function asXmrAmount(value: unknown, field: string, minPico: number): number {
  if (typeof value !== "string") {
    throw badRequest(`${field} must be a decimal string of XMR, for example "0.05"`);
  }
  const pico = parseXmr(value);
  if (pico === null) {
    throw badRequest(`${field} must be an amount of XMR with at most ${XMR_DECIMALS} decimals`);
  }
  if (pico > MAX_PRICE_PICO) {
    throw badRequest(`${field} must not exceed ${xmrString(MAX_PRICE_PICO)} XMR`);
  }
  if (pico < minPico) {
    throw badRequest(`${field} must be at least ${xmrString(minPico)} XMR`, "below_minimum");
  }
  return pico;
}

/**
 * Monero's base58 alphabet: Bitcoin's, minus nothing — the difference is the block size, not
 * the digits. `0`, `O`, `I` and `l` are absent, which is most of what makes a hand-copied
 * address survive.
 */
const BASE58 = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;

/**
 * A Monero destination, checked as far as it can be checked here.
 *
 * What this catches: the wrong length, a character no Monero address contains, a network
 * prefix that belongs to no Monero network, and every form of injection (the value is
 * base58, so it cannot contain a quote, a space or a shell character).
 *
 * What it deliberately does not do: verify the checksum. That needs Keccak-256, and
 * `docs/SOURCES.md` allows exactly one hand-written primitive in this repository — writing a
 * second one to save an RPC call would be the wrong trade. The wallet's own
 * `validate_address` is the authority, and the payout worker calls it before it sends
 * anything (docs/PAYMENTS.md). So this is a cheap filter in front of an exact check, and it
 * is honest about which is which.
 */
export function asMoneroAddress(value: unknown, field: string): string {
  const address = asString(value, field, 106, 95).trim();
  if (address.length !== 95 && address.length !== 106) {
    throw badRequest(`${field} must be a 95-character Monero address (106 if integrated)`, "bad_address");
  }
  if (!BASE58.test(address)) {
    throw badRequest(`${field} contains a character no Monero address contains`, "bad_address");
  }
  // First character by network and kind: 4 and 8 are mainnet standard and subaddress, 5 and 7
  // stagenet, 9 and A/B testnet. Anything else is not an address for any Monero network.
  if (!/^[45789AB]/.test(address)) {
    throw badRequest(`${field} does not start like a Monero address`, "bad_address");
  }
  return address;
}

/**
 * `physical_good` exists so a client knows an order needs a delivery address. The address
 * itself never reaches this server: there is no field for it in any route, and no column
 * for it in any table — see ADR-0021.
 */
export const LISTING_KINDS = ["digital_good", "service", "physical_good"] as const;

/** What can be reported, and why. `dispute` is written by the order route, not by users directly. */
export const REPORT_TARGETS = ["listing", "user", "review", "order"] as const;
export const REPORT_REASONS = [
  "prohibited_goods",
  "fraud",
  "impersonation",
  "spam",
  "harassment",
  "dispute",
  "other",
] as const;

/**
 * The sealed vault is opaque to the server, but it is still checked: it must be an object
 * of the shape `sealVault()` produces, and it must be small enough that a client cannot
 * use the key backup as free storage.
 */
export function asSealedVault(value: unknown): string {
  if (!value || typeof value !== "object") {
    throw badRequest("sealedVault must be an object produced by sealVault()");
  }
  const sealed = JSON.stringify(value);
  if (sealed.length > 256 * 1024) throw badRequest("sealed vault too large");
  return sealed;
}
