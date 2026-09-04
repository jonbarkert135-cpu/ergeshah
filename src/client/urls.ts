/**
 * Link hygiene on the way in (ADR-0098, adapted from Brave's "debouncing").
 *
 * This client has no query parameters. Every route it knows is in the fragment
 * (`#/market`, `#/orders`), the fragment is never sent to a server, and nothing here reads
 * `location.search` — `test/fingerprint.test.ts` fails if that stops being true. So a `?`
 * on the address bar always arrived from somewhere else: `utm_source` from a mailing list,
 * `fbclid` from a share button, a click identifier from an affiliate page.
 *
 * Stripping named tracking parameters is the usual approach and it is a list that is always
 * one campaign out of date. Here the honest version is cheaper: remove the whole query
 * string, because none of it can mean anything to this application. What that buys is
 * modest and worth stating exactly — the identifier disappears from the address bar, from
 * this browser's history, and from the link a user copies out of it to give to somebody
 * else. It does not un-send the request that carried it here, and the parameters were never
 * forwarded to a third party in the first place: there is no third party.
 */

/**
 * The same location without its query string, or `null` when there is nothing to remove.
 * Pure, so the rule can be tested without a browser; the caller does the `replaceState`.
 */
export function withoutQuery(href: string): string | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  if (!url.search) return null;
  return `${url.pathname}${url.hash}`;
}
