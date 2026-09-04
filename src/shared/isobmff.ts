/**
 * ISO base media file format (ISO/IEC 14496-12) metadata removal — the second half of
 * roadmap UI-4. One container underlies four of the formats the JPEG/PNG/WebP walker in
 * `media.ts` could not touch: HEIC and HEIF (what an iPhone camera writes by default), AVIF,
 * and MP4/MOV video (ISO/IEC 23008-12 layers HEIF on top of this same box grammar). They are
 * all boxes — `[u32 size][u32 type][payload]`, nested — so one walker covers all four.
 *
 * Same contract as `media.ts`: this removes metadata *containers*, never pixels, and never
 * re-encodes. It also never changes the file's length or moves a single byte of media. A
 * metadata box is turned into a `free` box of exactly its old size with its payload zeroed;
 * a metadata item that lives inside `mdat`/`idat` is zeroed where it lies. That is
 * deliberate, not lazy: MP4 chunk-offset tables (`stco`/`co64`) and HEIF item locations
 * (`iloc`) store absolute byte offsets, so moving anything would mean rewriting every one of
 * them, and a bug in that arithmetic corrupts the picture. Zeroing in place cannot — every
 * offset still points where it did, at bytes that are now zero.
 *
 * If the structure does not parse cleanly — a size that runs past the end, a box version this
 * code does not know, an item located by reference into another item — nothing is changed and
 * the caller is told the file was *not* handled, so the screen still discloses it. A corrupted
 * file someone was trying to send is the worse failure (the rule `media.ts` opens with).
 */

/** Thrown the instant the parse meets something it does not trust; caught at the entry point,
 *  where it means "change nothing, and tell the caller this file was not handled". */
class Bail extends Error {}

function be16(bytes: Uint8Array, at: number): number {
  return (bytes[at]! << 8) | bytes[at + 1]!;
}

function be32(bytes: Uint8Array, at: number): number {
  return ((bytes[at]! << 24) >>> 0) + (bytes[at + 1]! << 16) + (bytes[at + 2]! << 8) + bytes[at + 3]!;
}

function fourCc(bytes: Uint8Array, at: number): string {
  return String.fromCharCode(bytes[at]!, bytes[at + 1]!, bytes[at + 2]!, bytes[at + 3]!);
}

/** iloc offsets and lengths are 0, 4 or 8 bytes wide; 0 means the value is zero. */
function readSized(bytes: Uint8Array, at: number, size: number): number {
  if (size === 0) return 0;
  if (size === 4) return be32(bytes, at);
  if (size === 8) return be32(bytes, at) * 0x100000000 + be32(bytes, at + 4);
  throw new Bail();
}

interface Box {
  type: string;
  start: number;
  /** First byte of the box's payload (after the 8- or 16-byte header). */
  content: number;
  /** One past the last byte of the box. */
  end: number;
}

/** Walk the boxes tiling `[start, end)`. Every size is checked against the range, so a length
 *  field from the file can never send a read past the buffer or into an earlier box. */
function boxes(buf: Uint8Array, start: number, end: number): Box[] {
  const out: Box[] = [];
  let at = start;
  while (at + 8 <= end) {
    let size = be32(buf, at);
    let content = at + 8;
    if (size === 1) {
      // 64-bit largesize in the eight bytes after the type.
      if (at + 16 > end) throw new Bail();
      size = be32(buf, at + 8) * 0x100000000 + be32(buf, at + 12);
      content = at + 16;
    } else if (size === 0) {
      size = end - at; // runs to the end of its container
    }
    const boxEnd = at + size;
    if (boxEnd > end || content > boxEnd) throw new Bail();
    out.push({ type: fourCc(buf, at + 4), start: at, content, end: boxEnd });
    at = boxEnd;
  }
  if (at !== end) throw new Bail(); // bytes left over that are not a whole box
  return out;
}

/** Overwrite a whole box with a `free` box of identical size: keep the size field, retype it
 *  `free` (legal free space anywhere, skipped by every reader), and zero the payload so the
 *  bytes themselves — a `©xyz` GPS string, a camera model, an XMP packet — are gone, not just
 *  unreferenced. Length and every following offset are untouched. */
function neutralise(out: Uint8Array, box: Box): void {
  out[box.start + 4] = 0x66; // 'f'
  out[box.start + 5] = 0x72; // 'r'
  out[box.start + 6] = 0x65; // 'e'
  out[box.start + 7] = 0x65; // 'e'
  out.fill(0, box.content, box.end);
}

/** `mvhd`/`tkhd`/`mdhd` all open (after the version/flags word) with creation_time then
 *  modification_time — the capture clock, to the second. Zero just those two fields; the
 *  timescale, duration and dimensions that follow are what a player needs and stay. */
function zeroTimes(out: Uint8Array, box: Box): void {
  const version = out[box.content]!;
  const at = box.content + 4;
  const bytesPerTime = version === 1 ? 8 : 4; // v1 stores 64-bit times, v0 stores 32-bit
  if (at + bytesPerTime * 2 > box.end) throw new Bail();
  out.fill(0, at, at + bytesPerTime * 2); // creation_time then modification_time
}

/** A `moov` (or its `trak`/`mdia` children) carries video metadata in three places: `udta`
 *  user data (the `©xyz` GPS atom an iPhone writes, make/model, the iTunes `meta`/`ilst`), a
 *  `meta` box of the same iTunes kind, and the header timestamps. None of the three is needed
 *  to decode the picture, so all three go. */
function processMoovChild(out: Uint8Array, box: Box, changed: { any: boolean }): void {
  if (box.type === "udta" || box.type === "meta" || box.type === "uuid") {
    neutralise(out, box);
    changed.any = true;
    return;
  }
  if (box.type === "mvhd" || box.type === "tkhd" || box.type === "mdhd") {
    zeroTimes(out, box);
    changed.any = true;
    return;
  }
  // Recurse only into the containers that actually hold the boxes above.
  if (box.type === "trak" || box.type === "mdia" || box.type === "minf") {
    for (const child of boxes(out, box.content, box.end)) processMoovChild(out, child, changed);
  }
}

interface Item {
  itemId: number;
  method: number;
  dataRef: number;
  base: number;
  extents: { offset: number; length: number }[];
}

/** `iinf` lists every item and its type; a HEIF photo's location and camera live in the item
 *  typed `Exif`, its XMP packet in a `mime` (or `xml `) item. Only version-2+ `infe` boxes name
 *  the type — an older file is refused rather than guessed at. */
function parseItemTypes(out: Uint8Array, iinf: Box): Map<number, string> {
  const version = out[iinf.content]!;
  let at = iinf.content + 4;
  if (version === 0) at += 2;
  else at += 4; // v1+ uses a 32-bit entry count
  const types = new Map<number, string>();
  for (const infe of boxes(out, at, iinf.end)) {
    if (infe.type !== "infe") continue;
    const v = out[infe.content]!;
    if (v < 2) throw new Bail(); // no item_type field to read; do not guess
    let p = infe.content + 4;
    let itemId: number;
    if (v === 2) {
      itemId = be16(out, p);
      p += 2;
    } else {
      itemId = be32(out, p);
      p += 4;
    }
    p += 2; // item_protection_index
    types.set(itemId, fourCc(out, p));
  }
  return types;
}

/** `iloc` says where each item's bytes are: a base plus one or more (offset, length) extents,
 *  read against the file (method 0) or the `idat` box (method 1). Method 2 (bytes inside
 *  another item) is refused — the arithmetic to clear part of a shared item is exactly the
 *  offset surgery this module exists to avoid. */
function parseLocations(out: Uint8Array, iloc: Box): Item[] {
  const version = out[iloc.content]!;
  if (version > 2) throw new Bail();
  let at = iloc.content + 4;
  const offsetSize = out[at]! >> 4;
  const lengthSize = out[at]! & 0xf;
  const baseOffsetSize = out[at + 1]! >> 4;
  const indexSize = out[at + 1]! & 0xf;
  at += 2;
  let count: number;
  if (version < 2) {
    count = be16(out, at);
    at += 2;
  } else {
    count = be32(out, at);
    at += 4;
  }
  const items: Item[] = [];
  for (let i = 0; i < count; i += 1) {
    let itemId: number;
    if (version < 2) {
      itemId = be16(out, at);
      at += 2;
    } else {
      itemId = be32(out, at);
      at += 4;
    }
    let method = 0;
    if (version === 1 || version === 2) {
      method = be16(out, at) & 0xf;
      at += 2;
    }
    const dataRef = be16(out, at);
    at += 2;
    const base = readSized(out, at, baseOffsetSize);
    at += baseOffsetSize;
    const extentCount = be16(out, at);
    at += 2;
    const extents: { offset: number; length: number }[] = [];
    for (let e = 0; e < extentCount; e += 1) {
      if ((version === 1 || version === 2) && indexSize > 0) at += indexSize; // extent_index, unused here
      const offset = readSized(out, at, offsetSize);
      at += offsetSize;
      const length = readSized(out, at, lengthSize);
      at += lengthSize;
      extents.push({ offset, length });
    }
    items.push({ itemId, method, dataRef, base, extents });
  }
  return items;
}

const METADATA_ITEMS = new Set(["Exif", "mime", "xml "]);

/** A HEIF/AVIF still image: the top-level `meta` box is the file's spine (it locates the
 *  picture), so it is kept and read, not dropped. What is dropped is the bytes of its `Exif`
 *  and XMP items, zeroed where `iloc` says they sit — inside `mdat` or the `meta` box's own
 *  `idat`. */
function processImageMeta(out: Uint8Array, meta: Box, changed: { any: boolean }): void {
  const children = boxes(out, meta.content + 4, meta.end); // meta is a FullBox
  const iinf = children.find((b) => b.type === "iinf");
  const iloc = children.find((b) => b.type === "iloc");
  const idat = children.find((b) => b.type === "idat");
  if (!iinf || !iloc) throw new Bail(); // a well-formed HEIF has both; refuse the unexpected
  const types = parseItemTypes(out, iinf);
  for (const item of parseLocations(out, iloc)) {
    const itemType = types.get(item.itemId);
    if (!itemType || !METADATA_ITEMS.has(itemType)) continue; // a coded image item, left alone
    if (item.dataRef !== 0) continue; // its bytes are in another file; nothing here to clear
    if (item.method === 2) throw new Bail(); // located inside another item — refuse
    if (item.method === 1 && !idat) throw new Bail(); // offsets are into an idat that is absent
    const origin = item.method === 1 ? idat!.content : 0;
    for (const extent of item.extents) {
      const start = origin + item.base + extent.offset;
      const stop = start + extent.length;
      if (start < 0 || stop > out.length || stop < start) throw new Bail();
      if (extent.length > 0) {
        out.fill(0, start, stop);
        changed.any = true;
      }
    }
  }
}

export interface IsoResult {
  cleaned: Uint8Array;
  /** True when the file parsed cleanly and its metadata boxes/items were removed; false when
   *  the parse was refused, in which case `cleaned` is the original bytes and a caller should
   *  still disclose the file as uncleaned. */
  handled: boolean;
}

/** Returns null when `bytes` is not an ISO base media file, so a caller can fall through to the
 *  formats it does handle itself. Otherwise strips the metadata in place (see the file header)
 *  and reports whether the file was fully handled. Never throws, never grows the input. */
export function stripIsoBmff(bytes: Uint8Array): IsoResult | null {
  if (bytes.length < 12 || fourCc(bytes, 4) !== "ftyp") return null;
  const out = bytes.slice();
  const changed = { any: false };
  try {
    const top = boxes(out, 0, out.length);
    const hasMoov = top.some((b) => b.type === "moov");
    for (const box of top) {
      if (box.type === "moov") {
        for (const child of boxes(out, box.content, box.end)) processMoovChild(out, child, changed);
      } else if (box.type === "uuid") {
        // Vendor extension boxes carry XMP and maker notes; none is needed to decode.
        neutralise(out, box);
        changed.any = true;
      } else if (box.type === "meta") {
        if (hasMoov) {
          neutralise(out, box); // file-level iTunes metadata beside a moov
          changed.any = true;
        } else {
          processImageMeta(out, box, changed);
        }
      }
    }
  } catch (error) {
    if (error instanceof Bail) return { cleaned: bytes, handled: false };
    throw error;
  }
  return { cleaned: changed.any ? out : bytes, handled: true };
}
