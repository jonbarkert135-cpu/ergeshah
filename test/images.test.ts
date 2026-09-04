/**
 * Point 88: a picture with GPS in it goes in, and a picture without GPS comes out.
 *
 * The fixtures are built here, byte by byte, because this project has no image library and
 * does not want one — and because a hand-built container is the only way to be sure the test
 * knows exactly which bytes are metadata and which are the picture. Every case asserts both
 * halves of the property: the metadata is gone, *and* the image data is untouched. A stripper
 * that corrupts photographs would pass the first assertion on its own.
 */
import { crc32 } from "node:zlib";
import { describe, expect, it } from "vitest";
import { stripImageMetadata } from "../src/shared/images.ts";

const ascii = (text: string): number[] => [...text].map((character) => character.charCodeAt(0));
const bytes = (...parts: (number | number[])[]): Uint8Array =>
  new Uint8Array(parts.flatMap((part) => (typeof part === "number" ? [part] : part)));
const text = (data: Uint8Array): string => Buffer.from(data).toString("latin1");

/** A JPEG segment: `FF <marker> <length including the length itself> <payload>`. */
function segment(marker: number, payload: number[]): number[] {
  const length = payload.length + 2;
  return [0xff, marker, (length >> 8) & 0xff, length & 0xff, ...payload];
}

/**
 * An EXIF block of the shape a phone writes: the `Exif\0\0` header, a little-endian TIFF
 * header, and the two things that matter — where the photograph was taken and what took it.
 */
const EXIF_PAYLOAD = [
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
  ...ascii("Canon EOS 5D"),
  0,
  ...ascii("GPSLatitude 51.5074 GPSLongitude -0.1278"),
  0,
];

const SCAN = [0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x12, 0x34, 0xff, 0x00, 0x56];

function jpegWithMetadata(): Uint8Array {
  return bytes(
    0xff,
    0xd8, // SOI
    segment(0xe0, [...ascii("JFIF"), 0, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]), // APP0
    segment(0xe1, EXIF_PAYLOAD), // APP1: EXIF with GPS
    segment(0xe1, ascii('<x:xmpmeta xmlns:x="adobe:ns:meta/">home</x:xmpmeta>')), // APP1: XMP
    segment(0xed, ascii("Photoshop 3.0 IPTC Jane Doe")), // APP13
    segment(0xdb, [0x00, ...new Array(64).fill(0x10)]), // DQT
    segment(0xc0, [0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00]), // SOF0
    segment(0xc4, [0x00, ...new Array(28).fill(0x01)]), // DHT
    segment(0xfe, ascii("edited on my phone")), // COM
    SCAN,
    0xff,
    0xd9, // EOI
    ascii("APP1 trailer with a second copy of Exif GPSLatitude"), // appended after EOI
  );
}

function chunk(type: string, payload: number[]): number[] {
  const body = [...ascii(type), ...payload];
  const length = payload.length;
  const crc = crc32(Buffer.from(body));
  return [
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
    ...body,
    (crc >>> 24) & 0xff,
    (crc >>> 16) & 0xff,
    (crc >>> 8) & 0xff,
    crc & 0xff,
  ];
}

const IHDR = [0, 0, 0, 16, 0, 0, 0, 16, 8, 2, 0, 0, 0];
const IDAT = [0x78, 0x9c, 0x01, 0x02, 0x03, 0x04];

function pngWithMetadata(): Uint8Array {
  return bytes(
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    chunk("IHDR", IHDR),
    chunk("eXIf", EXIF_PAYLOAD),
    chunk("tEXt", ascii("Comment\0taken at home")),
    chunk("iTXt", ascii("Author\0\0\0\0Jane Doe")),
    chunk("tIME", [0x07, 0xe9, 0x01, 0x02, 0x03, 0x04, 0x05]),
    chunk("iCCP", ascii("sRGB\0\0")),
    chunk("IDAT", IDAT),
    chunk("IEND", []),
    ascii("trailing bytes nobody asked for"),
  );
}

/** A RIFF chunk: four characters, a little-endian size, the payload, and a pad byte to keep it even. */
function riffChunk(fourcc: string, payload: number[]): number[] {
  const size = payload.length;
  return [
    ...ascii(fourcc),
    size & 0xff,
    (size >> 8) & 0xff,
    (size >> 16) & 0xff,
    (size >>> 24) & 0xff,
    ...payload,
    ...(size % 2 === 1 ? [0] : []),
  ];
}

function webpWithMetadata(): Uint8Array {
  // Flags: ICC, alpha, EXIF, XMP and animation all announced. Then the canvas size.
  const vp8x = riffChunk("VP8X", [0x3e, 0, 0, 0, 0x0f, 0, 0, 0x0f, 0, 0]);
  const picture = riffChunk("VP8 ", [0x11, 0x22, 0x33, 0x44]);
  const body = [
    ...vp8x,
    ...picture,
    ...riffChunk("EXIF", EXIF_PAYLOAD),
    ...riffChunk("XMP ", ascii("<x:xmp/>")),
  ];
  const size = 4 + body.length;
  return bytes(
    ascii("RIFF"),
    [size & 0xff, (size >> 8) & 0xff, (size >> 16) & 0xff, (size >> 24) & 0xff],
    ascii("WEBP"),
    body,
  );
}

describe("stripping metadata from a picture (point 88)", () => {
  it("removes EXIF, GPS, XMP, IPTC and the comment from a JPEG", () => {
    const result = stripImageMetadata(jpegWithMetadata());

    expect(result.format).toBe("jpeg");
    expect(result.cleaned).toBe(true);
    expect(result.mayCarryMetadata).toBe(false);
    const out = text(result.bytes);
    for (const secret of ["Exif", "GPSLatitude", "51.5074", "Canon EOS 5D", "xmpmeta", "Jane Doe", "edited on my phone"]) {
      expect(out, secret).not.toContain(secret);
    }
    expect(result.removedBytes).toBeGreaterThan(100);
  });

  it("keeps the picture itself byte for byte", () => {
    const result = stripImageMetadata(jpegWithMetadata());

    // The scan, the quantisation and Huffman tables and the frame header are the image.
    expect(text(result.bytes)).toContain(text(bytes(SCAN)));
    expect(text(result.bytes)).toContain(text(bytes(segment(0xc0, [0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00]))));
    expect(text(result.bytes)).toContain("JFIF");
    // Ends at the end-of-image marker: the trailer that held a second EXIF copy is gone.
    expect([...result.bytes.subarray(-2)]).toEqual([0xff, 0xd9]);
  });

  it("removes eXIf, text and timestamp chunks from a PNG and leaves the rest valid", () => {
    const result = stripImageMetadata(pngWithMetadata());

    expect(result.format).toBe("png");
    expect(result.cleaned).toBe(true);
    const out = text(result.bytes);
    for (const secret of ["Exif", "GPSLatitude", "taken at home", "Jane Doe", "eXIf", "tEXt", "iTXt", "tIME"]) {
      expect(out, secret).not.toContain(secret);
    }
    // The colour profile and the image data are not metadata.
    expect(out).toContain("iCCP");
    expect(text(result.bytes)).toContain(text(bytes(chunk("IDAT", IDAT))));
    expect(out.endsWith(text(bytes(chunk("IEND", []))))).toBe(true);
  });

  it("removes the EXIF and XMP chunks from a WebP and clears the flags that announced them", () => {
    const result = stripImageMetadata(webpWithMetadata());

    expect(result.format).toBe("webp");
    expect(result.cleaned).toBe(true);
    const out = text(result.bytes);
    expect(out).not.toContain("EXIF");
    expect(out).not.toContain("XMP");
    expect(out).not.toContain("GPSLatitude");
    expect(out).toContain("VP8 ");
    // The RIFF size field describes what is actually there.
    const view = new DataView(result.bytes.buffer, result.bytes.byteOffset, result.bytes.byteLength);
    expect(view.getUint32(4, true)).toBe(result.bytes.length - 8);
    // VP8X flags: the EXIF and XMP bits are off, the ICC, alpha and animation bits are untouched.
    expect(result.bytes[20]! & 0x0c).toBe(0);
    expect(result.bytes[20]! & 0x32).toBe(0x32);
  });

  it("is idempotent, so an upload and a digest of the same file agree", () => {
    const once = stripImageMetadata(jpegWithMetadata()).bytes;
    const twice = stripImageMetadata(once);
    expect([...twice.bytes]).toEqual([...once]);
    expect(twice.removedBytes).toBe(0);
    const png = stripImageMetadata(pngWithMetadata()).bytes;
    expect([...stripImageMetadata(png).bytes]).toEqual([...png]);
  });
});

describe("what it refuses to touch", () => {
  it("passes a truncated or malformed image through unchanged rather than corrupting it", () => {
    const truncated = bytes(0xff, 0xd8, 0xff, 0xe1, 0x00, 0x40, ...ascii("Exif"));
    const result = stripImageMetadata(truncated);
    expect([...result.bytes]).toEqual([...truncated]);
    expect(result.cleaned).toBe(false);
    // Honest about the consequence: the metadata is still in there.
    expect(result.mayCarryMetadata).toBe(true);
  });

  it("names the containers it cannot clean instead of implying it did", () => {
    const heic = bytes(0, 0, 0, 0x18, ascii("ftypheic"), ascii("mif1"));
    const tiff = bytes(0x49, 0x49, 0x2a, 0x00, 0x08, 0, 0, 0, ascii("GPS"));
    const svg = bytes(ascii('<svg xmlns="http://www.w3.org/2000/svg"><metadata>home</metadata></svg>'));
    for (const [name, file] of [["heic", heic], ["tiff", tiff], ["svg", svg]] as const) {
      const result = stripImageMetadata(file);
      expect(result.format, name).toBe("unknown");
      expect(result.cleaned, name).toBe(false);
      expect(result.mayCarryMetadata, name).toBe(true);
      expect([...result.bytes], name).toEqual([...file]);
    }
  });

  it("says nothing about a file that is not a picture", () => {
    const document = bytes(ascii("a licence key, or a zip, or a text file"));
    const result = stripImageMetadata(document);
    expect(result.format).toBe("unknown");
    expect(result.mayCarryMetadata).toBe(false);
    expect([...result.bytes]).toEqual([...document]);
  });
});
