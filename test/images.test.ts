/**
 * The metadata stripper, case by case (ADR-0092, `src/shared/media.ts`).
 *
 * `test/uploads.test.ts` covers the formats and what survives them. This file covers the three
 * things a second pass over the same requirement found, each of which is a way for a
 * photograph to reach its recipient still carrying where it was taken:
 *
 * 1. **A trailer after the end-of-image marker.** Several tools append one, and a second copy
 *    of the EXIF block is a normal thing to find there. The walker used to meet those bytes,
 *    fail to recognise a marker, and return the file untouched — so a JPEG with a trailer kept
 *    *all* of its metadata.
 * 2. **The evidence digest.** A delivery is stripped before it is encrypted, so a dispute
 *    commitment computed over the file the seller picked would never match the bytes the buyer
 *    holds. Both sides have to hash the same thing, which is only true if the digest strips too.
 * 3. **The formats it cannot clean.** TIFF, GIF and SVG are passed through — the right
 *    behaviour — but passing them through silently is not. (HEIC/HEIF/AVIF and MP4/MOV are no
 *    longer here: the ISO base media walker strips them now, see `test/isobmff.test.ts`.)
 *
 * The fixtures are built here byte by byte, because that is the only way a test knows exactly
 * which bytes are metadata and which are the picture — and every case asserts both halves: the
 * metadata is gone, and the image data is untouched.
 */
import { describe, expect, it } from "vitest";
import { METADATA_KEPT_NOTE, metadataUnhandled, stripImageMetadata } from "../src/shared/media.ts";

const ascii = (text: string): number[] => [...text].map((character) => character.charCodeAt(0));
const bytes = (...parts: (number | number[])[]): Uint8Array =>
  new Uint8Array(parts.flatMap((part) => (typeof part === "number" ? [part] : part)));
const text = (data: Uint8Array): string => Buffer.from(data).toString("latin1");

/** A JPEG segment: `FF <marker> <length including the length itself> <payload>`. */
function segment(marker: number, payload: number[]): number[] {
  const length = payload.length + 2;
  return [0xff, marker, (length >> 8) & 0xff, length & 0xff, ...payload];
}

/** The shape a phone writes: the `Exif\0\0` header, a TIFF header, and where the photo was taken. */
const EXIF = [
  ...ascii("Exif"),
  0,
  0,
  ...ascii("II"),
  0x2a,
  0x00,
  0x08,
  0x00,
  0x00,
  0x00,
  ...ascii("Canon EOS 5D GPSLatitude 51.5074 GPSLongitude -0.1278"),
  0,
];

const SCAN = [0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x12, 0x34, 0xff, 0x00, 0x56];
const FRAME = segment(0xc0, [0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00]);

/** A JPEG with metadata in front of the scan and a second copy appended after the end marker. */
function jpegWithTrailer(): Uint8Array {
  return bytes(
    0xff,
    0xd8,
    segment(0xe0, [...ascii("JFIF"), 0, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]),
    segment(0xe1, EXIF),
    FRAME,
    SCAN,
    0xff,
    0xd9,
    // What a "save for web" tool leaves behind: an unmarked trailer holding the block again.
    ascii("Exif\0\0 GPSLatitude 51.5074 second copy"),
  );
}

describe("a JPEG with a trailer after its end marker", () => {
  it("is cleaned rather than given up on", () => {
    const stripped = stripImageMetadata(jpegWithTrailer());
    const out = text(stripped);

    for (const secret of ["Exif", "GPSLatitude", "51.5074", "Canon EOS 5D", "second copy"]) {
      expect(out, secret).not.toContain(secret);
    }
    // The picture is intact: the frame header, the scan, and the JFIF block that describes
    // how to display it.
    expect(out).toContain(text(bytes(SCAN)));
    expect(out).toContain(text(bytes(FRAME)));
    expect(out).toContain("JFIF");
    expect([...stripped.subarray(-2)]).toEqual([0xff, 0xd9]);
  });

  it("leaves a truncated file exactly as it was", () => {
    // No end-of-image marker: rather than guess where the picture stops, the file is returned
    // untouched. A corrupted photograph is the worse failure.
    const truncated = bytes(0xff, 0xd8, segment(0xe1, EXIF), FRAME, SCAN);
    expect([...stripImageMetadata(truncated)]).toEqual([...truncated]);
  });

  it("is idempotent, so an upload and a digest of the same file agree", () => {
    const once = stripImageMetadata(jpegWithTrailer());
    expect([...stripImageMetadata(once)]).toEqual([...once]);
  });
});

describe("the formats it does not clean", () => {
  it("names them, so a screen can say so instead of implying the file was cleaned", () => {
    // HEIC/HEIF/AVIF and MP4/MOV moved to the ISO base media walker (roadmap UI-4,
    // `test/isobmff.test.ts`); what stays disclosed-not-stripped is TIFF, GIF and SVG.
    const tiff = bytes(0x49, 0x49, 0x2a, 0x00, 0x08, 0, 0, 0, ascii("GPS"));
    const gif = bytes(ascii("GIF89a"), 0x10, 0, 0x10, 0);
    const svg = bytes(ascii('<svg xmlns="http://www.w3.org/2000/svg"><metadata>home</metadata></svg>'));
    for (const [name, file] of [["tiff", tiff], ["gif", gif], ["svg", svg]] as const) {
      expect(metadataUnhandled(file), name).toBe(true);
      // Passed through byte for byte, which is the honest behaviour once it is disclosed.
      expect([...stripImageMetadata(file)], name).toEqual([...file]);
    }
  });

  it("says nothing about the three it does clean, or about a file that is not a picture", () => {
    const png = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const webp = bytes(ascii("RIFF"), [0x20, 0, 0, 0], ascii("WEBP"));
    const document = bytes(ascii("a licence key, or a zip, or a text file"));
    for (const [name, file] of [["jpeg", jpegWithTrailer()], ["png", png], ["webp", webp], ["other", document]] as const) {
      expect(metadataUnhandled(file), name).toBe(false);
    }
  });

  // The chat attachment path and the marketplace delivery path both disclose an unhandled
  // format, and both must say the same true thing. The wording lives in one exported constant
  // so the two screens cannot drift (roadmap UI-4) — this asserts it exists, names what is
  // *not* removed, and does not overclaim by calling the file anonymous or clean.
  it("gives both upload paths one honest sentence for the formats it cannot clean", () => {
    expect(METADATA_KEPT_NOTE).toMatch(/metadata/i);
    expect(METADATA_KEPT_NOTE).toMatch(/location/i);
    // Does not overclaim: the cleaned formats are never called anonymous, and this format is
    // not called cleaned or stripped — it says what stays, which is the honest half.
    expect(METADATA_KEPT_NOTE).not.toMatch(/anonymous|cleaned|stripped/i);
    // The delivery screen shows this note exactly when the strip could not touch the file —
    // the same gate the chat screen uses — so a TIFF warns and a JPEG stays silent.
    const tiff = bytes(0x49, 0x49, 0x2a, 0x00, 0x08, 0, 0, 0, ascii("GPS"));
    expect(metadataUnhandled(tiff) && METADATA_KEPT_NOTE.length > 0).toBe(true);
    expect(metadataUnhandled(jpegWithTrailer())).toBe(false);
  });
});
