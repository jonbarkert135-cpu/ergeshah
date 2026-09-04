/**
 * Metadata a photograph carries whether or not its sender meant to send it.
 *
 * Every attachment in this system is encrypted in the browser, so the *operator* learns
 * nothing from a picture. The person on the other side of the conversation is a different
 * matter: they decrypt the file, and a JPEG straight off a phone hands them GPS
 * coordinates, the camera's serial number, the capture time to the second and an embedded
 * thumbnail of a frame that may not be the one that was cropped. End-to-end encryption is
 * not a defence against that — the recipient is the one holding the key.
 *
 * So the bytes are cleaned before they are encrypted, here, on the sender's device, for
 * both blob paths (a message attachment and a marketplace delivery).
 *
 * **This removes containers, not pixels.** The image is not decoded and re-encoded: a
 * re-encode would need a canvas, would lose a generation of quality on every JPEG, and
 * would still not remove anything hidden *in* the pixels. What it does remove is the
 * metadata blocks — EXIF (GPS, model, serial, timestamps, thumbnail), XMP, IPTC, Photoshop
 * resources, comments — by dropping the segments that carry them and copying the rest
 * through byte for byte. Colour is kept on purpose: an ICC profile and the JFIF density
 * block describe how to display the image, not who took it.
 *
 * What it is not: an anonymiser. Faces, screens, street signs, a filename, the shape of
 * the compression itself and anything steganographic all survive, and `docs/STORAGE.md`
 * says so where a user can read it.
 *
 * This file rewrites JPEG, PNG and WebP; HEIC/HEIF, AVIF and MP4/MOV go through the ISO base
 * media walker in `isobmff.ts` (roadmap UI-4), which zeroes their metadata boxes and items in
 * place. Anything else — TIFF and raw, GIF, PDF, SVG — and anything malformed is returned
 * unchanged. Corrupting a file somebody is trying to send is a worse failure than leaving
 * a metadata block in a format this code does not understand.
 */
import { stripIsoBmff } from "./isobmff.ts";

/** JPEG segments dropped: APP1 (EXIF, XMP), APP3–APP13 (IPTC, Photoshop, Ducky…), APP15, COM. */
function jpegSegmentIsMetadata(marker: number, payload: Uint8Array): boolean {
  if (marker === 0xe1 || marker === 0xef || marker === 0xfe) return true;
  if (marker >= 0xe3 && marker <= 0xed) return true;
  // APP2 is usually an ICC colour profile, which is display data and is kept. The same
  // marker also carries MPF — a multi-picture index whose "images" are embedded thumbnails.
  if (marker === 0xe2) return !startsWith(payload, "ICC_PROFILE");
  return false;
}

function startsWith(payload: Uint8Array, text: string): boolean {
  if (payload.length < text.length) return false;
  for (let i = 0; i < text.length; i += 1) {
    if (payload[i] !== text.charCodeAt(i)) return false;
  }
  return true;
}

function fourCc(bytes: Uint8Array, at: number): string {
  return String.fromCharCode(bytes[at]!, bytes[at + 1]!, bytes[at + 2]!, bytes[at + 3]!);
}

function be16(bytes: Uint8Array, at: number): number {
  return (bytes[at]! << 8) | bytes[at + 1]!;
}

/** RIFF counts its lengths the other way round. */
function le32(bytes: Uint8Array, at: number): number {
  return bytes[at]! + (bytes[at + 1]! << 8) + (bytes[at + 2]! << 16) + bytes[at + 3]! * 0x1000000;
}

function be32(bytes: Uint8Array, at: number): number {
  return ((bytes[at]! << 24) >>> 0) + (bytes[at + 1]! << 16) + (bytes[at + 2]! << 8) + bytes[at + 3]!;
}

function concat(parts: Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function stripJpeg(bytes: Uint8Array): Uint8Array {
  const keep: Uint8Array[] = [bytes.subarray(0, 2)];
  let kept = 2;
  let at = 2;
  while (at + 1 < bytes.length) {
    if (bytes[at] !== 0xff) return bytes; // not where a marker should be: give up, keep the file
    const marker = bytes[at + 1]!;
    // Padding between segments, and the standalone markers that have no payload.
    if (marker === 0xff) {
      at += 1;
      continue;
    }
    // End of image. Whatever follows it is not part of the picture, and a trailer is exactly
    // where some tools park a second copy of the EXIF block — so the file ends here.
    if (marker === 0xd9) {
      keep.push(bytes.subarray(at, at + 2));
      kept += 2;
      return kept === bytes.length ? bytes : concat(keep, kept);
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      keep.push(bytes.subarray(at, at + 2));
      kept += 2;
      at += 2;
      continue;
    }
    // Start of scan: the entropy-coded image follows and is not segmented, so it is copied
    // verbatim — up to the end-of-image marker, which cannot occur inside scan data (a real
    // 0xFF there is stuffed with 0x00 or is a restart marker). Anything after it is dropped
    // for the reason above.
    if (marker === 0xda) {
      let end = at + 2;
      while (end + 1 < bytes.length && !(bytes[end] === 0xff && bytes[end + 1] === 0xd9)) end += 1;
      // No end marker: the file is truncated. Return it untouched rather than guess where it
      // should have stopped.
      if (end + 1 >= bytes.length) return bytes;
      keep.push(bytes.subarray(at, end + 2));
      kept += end + 2 - at;
      return kept === bytes.length ? bytes : concat(keep, kept);
    }
    const length = be16(bytes, at + 2);
    if (length < 2 || at + 2 + length > bytes.length) return bytes;
    const end = at + 2 + length;
    if (!jpegSegmentIsMetadata(marker, bytes.subarray(at + 4, end))) {
      keep.push(bytes.subarray(at, end));
      kept += end - at;
    }
    at = end;
  }
  keep.push(bytes.subarray(at));
  kept += bytes.length - at;
  return kept === bytes.length ? bytes : concat(keep, kept);
}

/**
 * PNG chunks worth keeping: the critical ones, plus the ancillary chunks that decide how
 * the image is *displayed* (transparency, colour, resolution) and the three that make an
 * animated PNG animate. Everything else — tEXt, zTXt, iTXt, eXIf, tIME, private chunks —
 * is metadata by definition, since a decoder does not need it to draw the picture.
 */
const PNG_KEEP = new Set([
  "IHDR", "PLTE", "IDAT", "IEND",
  "tRNS", "gAMA", "cHRM", "sRGB", "iCCP", "bKGD", "pHYs", "sBIT", "hIST",
  "acTL", "fcTL", "fdAT",
]);

function stripPng(bytes: Uint8Array): Uint8Array {
  const keep: Uint8Array[] = [bytes.subarray(0, 8)];
  let kept = 8;
  let at = 8;
  while (at + 12 <= bytes.length) {
    const length = be32(bytes, at);
    const end = at + 12 + length;
    if (end > bytes.length) return bytes;
    const type = fourCc(bytes, at + 4);
    if (PNG_KEEP.has(type)) {
      keep.push(bytes.subarray(at, end));
      kept += end - at;
    }
    at = end;
    if (type === "IEND") break;
  }
  if (at !== bytes.length) return bytes; // trailing bytes we did not account for
  return kept === bytes.length ? bytes : concat(keep, kept);
}

/** WebP is RIFF: drop the EXIF and XMP chunks and rewrite the container length. */
function stripWebp(bytes: Uint8Array): Uint8Array {
  const keep: Uint8Array[] = [bytes.subarray(0, 12)];
  let kept = 12;
  let at = 12;
  while (at + 8 <= bytes.length) {
    const length = le32(bytes, at + 4);
    // Chunks are padded to an even length; the pad byte belongs to the chunk.
    const end = at + 8 + length + (length % 2);
    if (end > bytes.length) return bytes;
    const type = fourCc(bytes, at);
    if (type !== "EXIF" && type !== "XMP ") {
      keep.push(bytes.subarray(at, end));
      kept += end - at;
    }
    at = end;
  }
  if (at !== bytes.length || kept === bytes.length) return bytes;
  const out = concat(keep, kept);
  // RIFF size counts everything after the first eight bytes.
  const size = kept - 8;
  out[4] = size & 0xff;
  out[5] = (size >> 8) & 0xff;
  out[6] = (size >> 16) & 0xff;
  out[7] = (size >>> 24) & 0xff;
  return out;
}

/**
 * The one sentence every screen uses to say what an unhandled format keeps. It lives here,
 * beside the check that decides when to show it, so the chat attachment path and the
 * marketplace delivery path cannot drift into two different half-true claims (roadmap UI-4).
 * It states what is *not* removed, which is the fact the recipient — the party holding the
 * key — needs, and stops there: it does not promise the cleaned formats are anonymous.
 */
export const METADATA_KEPT_NOTE =
  "This file type keeps its own metadata — location and camera details are not removed from it.";

/**
 * Whether a file carries metadata this code does *not* remove, so a screen can disclose it
 * instead of implying the file was cleaned like a JPEG (`docs/STORAGE.md` §Image metadata,
 * roadmap UI-4). After the ISO base media walker landed, the formats left uncleaned are TIFF
 * and the raw formats built on it, GIF, PDF and SVG — plus any ISO base media file too
 * malformed for the walker to trust. Recognised by the file's own bytes, never by a name or a
 * type the user supplied.
 */
export function metadataUnhandled(bytes: Uint8Array): boolean {
  // ISO base media files (HEIC/HEIF/AVIF, MP4/MOV) are now stripped in place (roadmap UI-4,
  // `isobmff.ts`); a file is only unhandled here if that walker refused to parse it.
  const iso = stripIsoBmff(bytes);
  if (iso) return !iso.handled;
  const tiffLittle = [0x49, 0x49, 0x2a, 0x00];
  const tiffBig = [0x4d, 0x4d, 0x00, 0x2a];
  if (bytes.length >= 4 && [tiffLittle, tiffBig].some((magic) => magic.every((byte, index) => bytes[index] === byte))) {
    return true;
  }
  if (bytes.length >= 4 && (fourCc(bytes, 0) === "GIF8" || fourCc(bytes, 0) === "%PDF")) return true;
  const head = String.fromCharCode(...bytes.subarray(0, Math.min(bytes.length, 200)))
    .trimStart()
    .toLowerCase();
  return head.startsWith("<?xml") || head.startsWith("<svg");
}

/**
 * Remove the metadata blocks from an image or video. Returns the same bytes when the format is
 * not one this code understands, when it is malformed, or when there was nothing to remove —
 * so a caller can always use the result. JPEG, PNG and WebP are rewritten here; HEIC/HEIF,
 * AVIF and MP4/MOV are handled by the ISO base media walker (`isobmff.ts`, roadmap UI-4).
 */
export function stripImageMetadata(bytes: Uint8Array): Uint8Array {
  if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return stripJpeg(bytes);
  }
  const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length >= 8 && PNG_SIGNATURE.every((byte, index) => bytes[index] === byte)) {
    return stripPng(bytes);
  }
  if (bytes.length >= 12 && fourCc(bytes, 0) === "RIFF" && fourCc(bytes, 8) === "WEBP") {
    return stripWebp(bytes);
  }
  const iso = stripIsoBmff(bytes);
  if (iso) return iso.cleaned;
  return bytes;
}
