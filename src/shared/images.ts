/**
 * Metadata removed from a picture before it is encrypted, in the browser (points 87, 88).
 *
 * A photograph is the most talkative file a person can send. A phone writes the GPS
 * coordinates of the shot, the camera model, the serial number of the body, the software that
 * edited it, and — through a thumbnail nobody looks at — sometimes an older version of the
 * image itself. End-to-end encryption hides all of that from the *server* and from nobody
 * else: the peer, and anyone who later gets the file from the peer, reads every field. On a
 * marketplace where a seller photographs the goods, that is a home address attached to an
 * advertisement.
 *
 * So the metadata is dropped here, on the sending side, before `encryptFile` sees the bytes.
 * It has to be this side: the server holds ciphertext and could not strip anything even if it
 * were trusted to try, which is the trade this whole architecture makes (`docs/METADATA.md`).
 *
 * What this is, deliberately, *not*: a re-encoder. Nothing is decoded, no canvas, no
 * dependency, no quality loss — the container is walked and the segments that carry metadata
 * are left out. Three formats are understood (JPEG, PNG, WebP). Everything else is passed
 * through untouched and reported as such, because a caller that is told "cleaned" about a
 * HEIC file is worse off than one that is told nothing.
 *
 * Rewriting a container is parsing hostile input, so every walk here refuses rather than
 * guesses: a length that runs past the end, a marker where none belongs, a truncated chunk —
 * the original bytes are returned with `cleaned: false`. A picture that arrives slightly
 * unusual is sent as it is; it is never corrupted on the way out.
 */

/** What the walker recognised. `unknown` is everything from a PDF to a zip. */
export type ImageFormat = "jpeg" | "png" | "webp" | "unknown";

export interface StrippedImage {
  /** The bytes to send: rewritten when this format is understood, the input otherwise. */
  bytes: Uint8Array;
  format: ImageFormat;
  /** True when metadata segments were looked for and removed. */
  cleaned: boolean;
  /** How many bytes the stripping removed. Zero when there was nothing to remove. */
  removedBytes: number;
  /**
   * True when this file is a container known to carry camera or location metadata that this
   * code does not know how to remove — HEIC from an iPhone, a raw file, a video, an SVG.
   * The caller is expected to say so on the screen rather than pretend otherwise.
   */
  mayCarryMetadata: boolean;
}

/**
 * JPEG application segments other than APP0 (JFIF), and comments.
 *
 * APP1 is EXIF and XMP, APP13 is IPTC, APP2 is ICC and Apple's multi-picture format — which
 * can embed a second copy of the photograph with its own EXIF. All of them go: the cost is
 * that a wide-gamut image loses its colour profile and may look slightly different, which is
 * a trade `docs/METADATA.md` states rather than hides.
 */
const dropJpegMarker = (marker: number): boolean =>
  (marker >= 0xe1 && marker <= 0xef) || marker === 0xfe;

/** PNG chunks that hold text, timestamps or EXIF. Everything else, including iCCP and APNG control chunks, stays. */
const DROP_PNG_CHUNKS = new Set(["eXIf", "tEXt", "iTXt", "zTXt", "tIME"]);

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

const ascii = (bytes: Uint8Array, at: number, length: number): string =>
  String.fromCharCode(...bytes.subarray(at, at + length));

const startsWith = (bytes: Uint8Array, prefix: number[]): boolean =>
  prefix.every((byte, index) => bytes[index] === byte);

/**
 * JPEG: a chain of `FF <marker> <length> <payload>` segments, then the entropy-coded scan.
 *
 * The scan is copied verbatim up to the end-of-image marker, and anything appended after that
 * marker is dropped — a trailer is where some tools park a second copy of the EXIF block, and
 * inside the scan `FFD9` cannot occur, because a real `FF` there is stuffed with `00` or is a
 * restart marker.
 */
function stripJpeg(bytes: Uint8Array): Uint8Array | null {
  const keep: Uint8Array[] = [bytes.subarray(0, 2)];
  let at = 2;
  while (at + 1 < bytes.length) {
    if (bytes[at] !== 0xff) return null;
    // Fill bytes: any number of FFs may precede a marker.
    let marker = bytes[at + 1]!;
    while (marker === 0xff && at + 2 < bytes.length) {
      at += 1;
      marker = bytes[at + 1]!;
    }
    if (marker === 0xd9) break; // End of image: whatever follows is not part of it.
    if (marker === 0xda) {
      // Start of scan. Find the end of the image and copy everything between verbatim.
      let end = at + 2;
      while (end + 1 < bytes.length && !(bytes[end] === 0xff && bytes[end + 1] === 0xd9)) end += 1;
      if (end + 1 >= bytes.length) return null; // No EOI: truncated, so do not rewrite it.
      keep.push(bytes.subarray(at, end + 2));
      return concat(keep);
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      keep.push(bytes.subarray(at, at + 2));
      at += 2;
      continue;
    }
    if (at + 3 >= bytes.length) return null;
    const length = (bytes[at + 2]! << 8) | bytes[at + 3]!;
    if (length < 2 || at + 2 + length > bytes.length) return null;
    if (!dropJpegMarker(marker)) keep.push(bytes.subarray(at, at + 2 + length));
    at += 2 + length;
  }
  keep.push(new Uint8Array([0xff, 0xd9]));
  return concat(keep);
}

/** PNG: `length type payload crc` chunks. Dropping one leaves every other chunk's CRC valid. */
function stripPng(bytes: Uint8Array): Uint8Array | null {
  const keep: Uint8Array[] = [bytes.subarray(0, 8)];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 8;
  let sawEnd = false;
  while (at + 12 <= bytes.length) {
    const length = view.getUint32(at);
    const end = at + 12 + length;
    if (length > 0x7fffffff || end > bytes.length) return null;
    const type = ascii(bytes, at + 4, 4);
    if (!DROP_PNG_CHUNKS.has(type)) keep.push(bytes.subarray(at, end));
    at = end;
    if (type === "IEND") {
      sawEnd = true;
      break; // Bytes appended after IEND are not image data; they are not carried over.
    }
  }
  return sawEnd ? concat(keep) : null;
}

/**
 * WebP: a RIFF container. `EXIF` and `XMP ` are their own chunks, so they are left out and
 * the flags in the `VP8X` header that announce them are cleared — a decoder that trusts the
 * flag and finds no chunk is a decoder handed something malformed.
 */
function stripWebp(bytes: Uint8Array): Uint8Array | null {
  if (bytes.length < 12 || ascii(bytes, 8, 4) !== "WEBP") return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunks: Uint8Array[] = [];
  let at = 12;
  let dropped = false;
  while (at + 8 <= bytes.length) {
    const fourcc = ascii(bytes, at, 4);
    const size = view.getUint32(at + 4, true);
    const end = at + 8 + size + (size % 2);
    if (size > 0x7fffffff || end > bytes.length) return null;
    if (fourcc === "EXIF" || fourcc === "XMP ") {
      dropped = true;
    } else if (fourcc === "VP8X" && size >= 1) {
      const header = bytes.slice(at, end);
      // Flags byte of the VP8X payload: bit 3 announces EXIF, bit 2 announces XMP.
      header[8] = header[8]! & ~0x0c;
      chunks.push(header);
    } else {
      chunks.push(bytes.subarray(at, end));
    }
    at = end;
  }
  if (chunks.length === 0) return null;
  if (!dropped) return bytes;
  const body = concat(chunks);
  const out = new Uint8Array(12 + body.length);
  out.set(bytes.subarray(0, 12));
  out.set(body, 12);
  new DataView(out.buffer).setUint32(4, 4 + body.length, true);
  return out;
}

/**
 * Containers that carry camera and location metadata and are not rewritten here: ISO base
 * media files (HEIC and AVIF from a phone camera, MP4 and MOV video), TIFF and the raw
 * formats built on it, GIF, PDF, SVG. Recognised by their own bytes, never by a name or a
 * type the user supplied (point 47).
 */
function knownRiskyContainer(bytes: Uint8Array, format: ImageFormat): boolean {
  if (format !== "unknown") return false;
  if (bytes.length >= 12 && ascii(bytes, 4, 4) === "ftyp") return true;
  if (startsWith(bytes, [0x49, 0x49, 0x2a, 0x00]) || startsWith(bytes, [0x4d, 0x4d, 0x00, 0x2a])) {
    return true; // TIFF, and the raw formats that are TIFF with private tags.
  }
  if (ascii(bytes, 0, 4) === "GIF8") return true;
  if (ascii(bytes, 0, 4) === "%PDF") return true;
  const head = ascii(bytes, 0, Math.min(bytes.length, 256)).trimStart().toLowerCase();
  return head.startsWith("<?xml") || head.startsWith("<svg");
}

function detect(bytes: Uint8Array): ImageFormat {
  if (bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "jpeg";
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  if (bytes.length >= 12 && ascii(bytes, 0, 4) === "RIFF" && ascii(bytes, 8, 4) === "WEBP") {
    return "webp";
  }
  return "unknown";
}

/**
 * Strip what this code knows how to strip, and say plainly what it did.
 *
 * Idempotent: stripping an already-stripped file returns the same bytes, which is what lets
 * the same function sit in front of both the upload and the evidence digest without the two
 * disagreeing about which bytes were exchanged (`docs/MODERATION.md`).
 */
export function stripImageMetadata(bytes: Uint8Array): StrippedImage {
  const format = detect(bytes);
  const rewritten =
    format === "jpeg"
      ? stripJpeg(bytes)
      : format === "png"
        ? stripPng(bytes)
        : format === "webp"
          ? stripWebp(bytes)
          : null;
  if (!rewritten) {
    return {
      bytes,
      format,
      cleaned: false,
      removedBytes: 0,
      // A file this walker refused is a file whose metadata is still in it, whether the
      // format is one we know or not.
      mayCarryMetadata: format !== "unknown" || knownRiskyContainer(bytes, format),
    };
  }
  return {
    bytes: rewritten,
    format,
    cleaned: true,
    removedBytes: bytes.length - rewritten.length,
    mayCarryMetadata: false,
  };
}
