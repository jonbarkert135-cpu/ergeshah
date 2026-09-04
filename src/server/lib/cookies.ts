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

/** The two cookies this server sets, by their base names. */
export const SESSION_COOKIE = "session";
export const CSRF_COOKIE = "csrf";

/**
 * On HTTPS the cookies carry the `__Host-` prefix (RFC 6265bis §4.1.3.2): a browser accepts
 * such a cookie only from a `Secure` response, with `Path=/` and *no* `Domain` attribute, so
 * nothing on a sibling host (`blog.example.org`, a stale subdomain, a neighbour on shared
 * hosting) can plant a `session` or `csrf` cookie for this origin — which, without the
 * prefix, is a session-fixation / forced-login primitive that needs no credential at all
 * (SEC-2026-014). On plain HTTP the prefix is not allowed, so an onion service (reached over
 * HTTP inside the Tor circuit) keeps the bare names; there, the host is the circuit and has
 * no siblings. The choice is per request and deterministic, and the reader and the writer
 * make it with the same function.
 */
export function cookieName(base: string, secure: boolean): string {
  return secure ? `__Host-${base}` : base;
}

export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${options.path ?? "/"}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  parts.push(`SameSite=${options.sameSite ?? "Strict"}`);
  if (options.maxAgeSeconds !== undefined) parts.push(`Max-Age=${options.maxAgeSeconds}`);
  return parts.join("; ");
}
