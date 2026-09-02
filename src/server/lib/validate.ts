/** Input validation. Everything that reaches the database goes through here first. */
import { badRequest } from "./errors.ts";
import { base64UrlBytes } from "../../shared/uploads.ts";

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

export function asString(value: unknown, field: string, max: number, min = 1): string {
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

export function asOptionalString(value: unknown, field: string, max: number): string {
  if (value === undefined || value === null || value === "") return "";
  return asString(value, field, max, 0);
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

export const CURRENCIES = ["USD", "EUR", "XMR", "BTC"] as const;
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
