import { randomBytes, randomUUID, createHash, createHmac } from "node:crypto";

/** Opaque, unguessable identifiers. No sequence numbers: they leak volume and order. */
export function newId(): string {
  return randomUUID();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function hmac(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}
