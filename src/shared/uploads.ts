/**
 * Every upload is hostile (point 49).
 *
 * This project has an unusual shape for this problem: the only bytes a user can upload are
 * ciphertext the server cannot read, so the server has no MIME type to trust, no extension
 * to parse, no image to transcode and no archive to expand. That removes most of the classic
 * vectors by construction rather than by inspection — but it moves one of them, the file
 * *name*, onto the client, where it arrives from a peer through the encrypted channel and is
 * used to name a download.
 *
 * A peer-supplied name is untrusted input. `safeFileName` is what makes it safe to hand to
 * the browser's download machinery, and it is shared code because both sides use it: the
 * client when it stores a delivery key, and the tests that prove the rules hold.
 */

/** Long enough for a real title, short enough for every filesystem. */
const MAX_NAME = 80;

/**
 * Windows refuses these names with any extension, and a download that cannot be written is
 * a delivery that silently fails. Cheap to sidestep, so we do.
 */
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * A file name that is safe to save: no path, no traversal, no control characters, no
 * direction-changing tricks, never empty.
 *
 * - **Path traversal** — separators (`/`, `\`), colons and every `..` segment are removed, so
 *   the result cannot escape the browser's download directory or name a device.
 * - **Extension spoofing by bidi override** — the `\u202E` trick that makes `evil-txt.exe`
 *   render as `evilexe.txt` is stripped, along with every other invisible reordering
 *   character. What the reader sees is what they save.
 * - **Sniffing** — irrelevant here, because the caller saves the bytes as
 *   `application/octet-stream` and never opens them in the page. The name is a label.
 */
export function safeFileName(value: unknown, fallback = "delivery.bin"): string {
  if (typeof value !== "string") return fallback;
  const flattened = value
    .normalize("NFC")
    // Control characters, bidi overrides, zero-width joiners: invisible, and every one of
    // them is a way to make a name read differently from what it is.
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, "")
    // Traversal first, so that removing it cannot leave a `..` behind by joining neighbours.
    .replace(/\.{2,}/g, "")
    // Anything that could be a path, a drive, a wildcard or a shell surprise.
    .replace(/[/\\:*?"<>|]/g, "_")
    .replace(/\s+/g, " ")
    .trim();
  // A name is one segment, and it does not start with a dot, a dash or the debris above.
  const segment = flattened.replace(/_{2,}/g, "_").replace(/^[._\-\s]+/, "");
  const trimmed = segment.slice(0, MAX_NAME).trim();
  if (trimmed.length === 0) return fallback;
  return RESERVED.test(trimmed) ? `_${trimmed}` : trimmed;
}

/**
 * How many bytes a base64url string decodes to, exactly.
 *
 * Size limits that count *characters* are off by a third, which is the difference between a
 * cap an operator configured and the cap they got. A length of `4n + 1` decodes to nothing:
 * it is not base64 at all.
 */
export function base64UrlBytes(text: string): number | null {
  if (text.length % 4 === 1) return null;
  const padding = text.length % 4 === 0 ? 0 : 4 - (text.length % 4);
  return Math.floor(((text.length + padding) * 3) / 4) - padding;
}
