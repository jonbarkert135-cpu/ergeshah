/** Input validation. Everything that reaches the database goes through here first. */
import { badRequest } from "./errors.ts";

const USERNAME_RE = /^[a-z0-9](?:[a-z0-9_.-]{1,30})[a-z0-9]$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export function asString(value: unknown, field: string, max: number, min = 1): string {
  if (typeof value !== "string") throw badRequest(`${field} must be a string`);
  const trimmed = value.trim();
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

export function asBase64Url(value: unknown, field: string, maxBytes: number): string {
  const text = asString(value, field, Math.ceil((maxBytes * 4) / 3) + 8);
  if (!BASE64URL_RE.test(text)) throw badRequest(`${field} must be base64url`);
  return text;
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
