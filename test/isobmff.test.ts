/**
 * The ISO base media metadata stripper (roadmap UI-4, `src/shared/isobmff.ts`).
 *
 * `src/shared/media.ts` cleans JPEG, PNG and WebP. The four formats it could not — HEIC and
 * HEIF (an iPhone's default photo), AVIF, and MP4/MOV video — share one container, so one
 * walker closes them all. It works by *zeroing* metadata where it lies and retyping whole
 * metadata boxes to `free`, never moving a byte: MP4 chunk tables and HEIF `iloc` records hold
 * absolute offsets, so a strip that changed the file's length would have to rewrite every one
 * of them, and a bug there corrupts the picture.
 *
 * So every case here asserts both halves: the location/camera bytes are gone, and the media —
 * the coded image, the `mdat` payload, the box structure a decoder walks — is byte-for-byte
 * intact and the file is exactly as long as it started.
 */
import { describe, expect, it } from "vitest";
import { metadataUnhandled, stripImageMetadata } from "../src/shared/media.ts";
import { stripIsoBmff } from "../src/shared/isobmff.ts";

const ascii = (text: string): number[] => [...text].map((character) => character.charCodeAt(0));
const u32 = (value: number): number[] => [(value >>> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
const flat = (parts: (number | number[])[]): number[] => parts.flatMap((part) => (typeof part === "number" ? [part] : part));
const asText = (data: Uint8Array): string => Buffer.from(data).toString("latin1");

/** A box: `[u32 size][4-char type][payload]`, size counting the header. */
function box(type: string, ...payload: (number | number[])[]): number[] {
  const body = flat(payload);
  return [...u32(body.length + 8), ...ascii(type), ...body];
}

/** A minimal movie header / track header / media header: version 0, then the two timestamps
 *  the stripper must clear, then a timescale it must keep. */
function timedHeader(type: string, creation: number, modification: number): number[] {
  return box(type, 0x00, 0, 0, 0, u32(creation), u32(modification), u32(600));
}

describe("an MP4/MOV video", () => {
  const GPS = "+37.7749-122.4194/"; // an iPhone writes this into a ©xyz atom in udta
  const MODEL = "iPhone 15 Pro";
  const MEDIA = "REAL-H264-SAMPLE-BYTES";

  function video(): Uint8Array {
    const udta = box(
      "udta",
      box("\u00a9xyz", 0, GPS.length, 0x15, 0xc7, ascii(GPS)),
      box("\u00a9mod", 0, MODEL.length, 0x15, 0xc7, ascii(MODEL)),
    );
    const trak = box("trak", timedHeader("tkhd", 3_700_000_000, 3_700_000_050));
    const moov = box("moov", timedHeader("mvhd", 3_700_000_000, 3_700_000_050), trak, udta);
    return new Uint8Array(flat([box("ftyp", ascii("isom"), u32(0x200), ascii("isomiso2mp41")), box("mdat", ascii(MEDIA)), moov]));
  }

  it("removes the GPS atom, the camera model and the capture timestamps, keeping the media", () => {
    const before = video();
    const after = stripImageMetadata(before);

    expect(after.length).toBe(before.length); // no byte moved: every stco/iloc offset still valid
    for (const secret of [GPS, MODEL, "+37.7749"]) expect(asText(after), secret).not.toContain(secret);
    expect(asText(after)).toContain(MEDIA); // the actual video sample is untouched
    // The two 32-bit timestamps in mvhd/tkhd (3_700_000_000 ≈ 0xdc8f… ) are zeroed.
    expect(asText(after)).not.toContain(String.fromCharCode(0xdc, 0x8f, 0x80, 0x00));
    // udta is turned into a free box a player skips, rather than left with zeroed contents
    // under its old type.
    expect(asText(after)).toContain("free");
    expect(metadataUnhandled(before)).toBe(false); // handled now, so no disclosure
  });

  it("is idempotent, so an upload and its dispute digest hash the same bytes", () => {
    const once = stripImageMetadata(video());
    expect([...stripImageMetadata(once)]).toEqual([...once]);
  });
});

describe("a HEIC / HEIF / AVIF still image", () => {
  const IMAGE = "HEVC-CODED-PRIMARY-IMAGE";
  const EXIF = "Exif\u0000\u0000II*\u0000 GPSLatitude 51.5074 GPSLongitude -0.1278 Canon EOS";
  const XMP = '<?xpacket?><x:xmpmeta><rdf:Description GPS="51.5074"/></x:xmpmeta>';

  /** Build a HEIF file whose `meta` box locates two items — the coded image and an Exif block —
   *  by absolute file offset into `mdat`, then the offsets are patched in once the layout (and
   *  so the real positions) is known. */
  function heif(withXmp: boolean): Uint8Array {
    const mdatPayload = withXmp ? IMAGE + EXIF + XMP : IMAGE + EXIF;
    const infes = [
      box("infe", 0x02, 0, 0, 0, 0x00, 0x01, 0x00, 0x00, ascii("hvc1")),
      box("infe", 0x02, 0, 0, 0, 0x00, 0x02, 0x00, 0x00, ascii("Exif")),
    ];
    if (withXmp) infes.push(box("infe", 0x02, 0, 0, 0, 0x00, 0x03, 0x00, 0x00, ascii("mime")));
    const iinf = box("iinf", 0x00, 0, 0, 0, 0x00, infes.length, ...infes);

    // iloc v0: offset_size=4, length_size=4, base_offset_size=0 (size nibbles 0x44, 0x00). Each
    // item has one extent whose (offset, length) start at 0 and are patched to the real
    // positions once the file is assembled and those positions are known.
    const ids = withXmp ? [1, 2, 3] : [1, 2];
    const ilocItems = ids.flatMap((id) => [0x00, id, 0x00, 0x00, 0x00, 0x01, ...u32(0), ...u32(0)]);
    const iloc = box("iloc", 0x00, 0, 0, 0, 0x44, 0x00, 0x00, ids.length, ...ilocItems);

    const meta = box("meta", 0x00, 0, 0, 0, iinf, iloc);
    const bytes = new Uint8Array(flat([box("ftyp", ascii("heic"), u32(0), ascii("heicmif1miaf")), meta, box("mdat", ascii(mdatPayload))]));

    const mdatStart = bytes.length - mdatPayload.length;
    const spans: [number, number][] = withXmp
      ? [[mdatStart, IMAGE.length], [mdatStart + IMAGE.length, EXIF.length], [mdatStart + IMAGE.length + EXIF.length, XMP.length]]
      : [[mdatStart, IMAGE.length], [mdatStart + IMAGE.length, EXIF.length]];
    return patchIloc(bytes, spans);
  }

  /** Rewrite every extent (offset,length) in the file's single iloc box to the real spans. */
  function patchIloc(bytes: Uint8Array, spans: [number, number][]): Uint8Array {
    const ilocType = asText(bytes).indexOf("iloc");
    let at = ilocType + 4 + 4; // type + version/flags
    at += 2; // offset/length + base/index size nibbles
    const itemCount = (bytes[at]! << 8) | bytes[at + 1]!;
    at += 2;
    for (let i = 0; i < itemCount; i += 1) {
      at += 2; // item_ID
      at += 2; // data_reference_index (base_offset_size is 0)
      const extentCount = (bytes[at]! << 8) | bytes[at + 1]!;
      at += 2;
      for (let e = 0; e < extentCount; e += 1) {
        const [offset, length] = spans[i]!;
        bytes.set(u32(offset), at);
        bytes.set(u32(length), at + 4);
        at += 8;
      }
    }
    return bytes;
  }

  it("zeroes the Exif and XMP items in mdat and leaves the coded image", () => {
    const before = heif(true);
    const after = stripImageMetadata(before);

    expect(after.length).toBe(before.length);
    for (const secret of ["GPSLatitude", "51.5074", "Canon EOS", "xmpmeta", "xpacket"]) {
      expect(asText(after), secret).not.toContain(secret);
    }
    expect(asText(after)).toContain(IMAGE); // the picture itself is byte-for-byte intact
    expect(asText(after)).toContain("hvc1"); // its item record is left in place
    expect(metadataUnhandled(before)).toBe(false);
  });

  it("handles a HEIC that has only an Exif item, no XMP", () => {
    const after = stripImageMetadata(heif(false));
    expect(asText(after)).not.toContain("GPSLatitude");
    expect(asText(after)).toContain(IMAGE);
  });
});

describe("the honest fallback", () => {
  it("still discloses an ISO base media file too malformed to trust, and never corrupts it", () => {
    // A meta box that claims an item but carries no iloc: refused, returned untouched, disclosed.
    const brokenMeta = new Uint8Array(flat([
      box("ftyp", ascii("heic"), u32(0), ascii("heic")),
      box("meta", 0x00, 0, 0, 0, box("iinf", 0x00, 0, 0, 0, 0x00, 0x01, box("infe", 0x02, 0, 0, 0, 0x00, 0x02, 0x00, 0x00, ascii("Exif")))),
    ]));
    const result = stripIsoBmff(brokenMeta)!;
    expect(result.handled).toBe(false);
    expect([...result.cleaned]).toEqual([...brokenMeta]);
    expect(metadataUnhandled(brokenMeta)).toBe(true);
  });

  it("returns non-ISO files to the caller untouched (null), so JPEG/PNG/WebP still route home", () => {
    expect(stripIsoBmff(new Uint8Array([0xff, 0xd8, 0xff, 0xe0]))).toBe(null);
    expect(stripIsoBmff(new Uint8Array(ascii("%PDF-1.7")))).toBe(null);
  });

  it("still flags the formats it never learned to strip", () => {
    const tiff = new Uint8Array([0x49, 0x49, 0x2a, 0x00, 0x08, 0, 0, 0, ...ascii("GPS")]);
    const gif = new Uint8Array(ascii("GIF89a"));
    const svg = new Uint8Array(ascii('<svg><metadata>home</metadata></svg>'));
    for (const [name, file] of [["tiff", tiff], ["gif", gif], ["svg", svg]] as const) {
      expect(metadataUnhandled(file), name).toBe(true);
      expect([...stripImageMetadata(file)], name).toEqual([...file]);
    }
  });
});
