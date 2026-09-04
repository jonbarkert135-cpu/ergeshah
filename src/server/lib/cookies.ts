/** Minimal cookie handling — one less dependency, and no surprises in the parser. */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) out[name] = decodeCookieValue(value);
  }
  return out;
}

/**
 * A cookie value is percent-decoded, and `decodeURIComponent` *throws* on a malformed
 * escape (`csrf=%zz`, a truncated UTF-8 sequence, a lone `%`). This function is called by
 * the CSRF hook and by `authenticate`, on the way in, for every request — so an unguarded
 * decode turned one bad header into a 500 on every route, an error log line per request,
 * and a browser that could not use the site until the cookie was cleared. A cookie is
 * attacker-influenced input (a related host can set one), which makes that a denial of
 * service with a one-line cause; it was found by the header fuzzing in `test/fuzz.test.ts`
 * (finding SEC-2026-001).
 *
 * The value that cannot be decoded is kept verbatim instead: it is compared against a
 * stored token and will not match, so the request is refused by the check that was going
 * to refuse it anyway — with a 401 or a 403, which is the truth, rather than a 500.
 */
function decodeCookieValue(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export interface CookieOptions {
  httpOnly?: boolean;
  maxAgeSeconds?: number;
  secure: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  path?: string;
}

export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${options.path ?? "/"}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  parts.push(`SameSite=${options.sameSite ?? "Strict"}`);
  if (options.maxAgeSeconds !== undefined) parts.push(`Max-Age=${options.maxAgeSeconds}`);
  return parts.join("; ");
}
