/**
 * A QR encoder for exactly one job: showing a safety number that another phone can scan.
 *
 * Scope is the reason this is ~180 lines instead of a dependency. It encodes byte mode,
 * version 3 (29×29), error-correction level M — one block, 44 data codewords, 26 error
 * correction codewords — which fits any payload up to 42 bytes, and a safety number is 40.
 * Anything longer throws rather than silently producing a code that will not scan.
 *
 * Everything here is from ISO/IEC 18004: GF(256) with the QR primitive 0x11d, Reed-Solomon
 * over that field, the version-3 module layout, and the eight standard masks. Mask choice
 * uses the specification's first two penalty rules; rules 3 and 4 are omitted because they
 * only refine an already-decodable choice, and every decoder handles any mask.
 *
 * `test/qr.test.ts` decodes the output with a reference decoder kept as a dev dependency —
 * the same arrangement as the BIP-39 implementation: our code ships, their code checks it.
 */

const SIZE = 29; // version 3
const DATA_CODEWORDS = 44;
const ECC_CODEWORDS = 26;
const MAX_BYTES = DATA_CODEWORDS - 2; // 4-bit mode indicator + 8-bit length + terminator

/** Format information for level M and each mask, already BCH-encoded and XOR-masked. */
const FORMAT_BITS = [
  0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0,
];

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i += 1) {
  EXP[i] = x;
  LOG[x] = i;
  x <<= 1;
  if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255]!;

function mul(a: number, b: number): number {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a]! + LOG[b]!]!;
}

/** Reed-Solomon remainder: the error-correction codewords appended to the data. */
function ecc(data: Uint8Array, count: number): Uint8Array {
  const generator = new Uint8Array(count + 1);
  generator[0] = 1;
  for (let degree = 0; degree < count; degree += 1) {
    for (let i = degree + 1; i > 0; i -= 1) {
      generator[i] = generator[i - 1]! ^ mul(generator[i]!, EXP[degree]!);
    }
    generator[0] = mul(generator[0]!, EXP[degree]!);
  }
  const remainder = new Uint8Array(count);
  for (const byte of data) {
    const factor = byte ^ remainder[0]!;
    remainder.copyWithin(0, 1);
    remainder[count - 1] = 0;
    for (let i = 0; i < count; i += 1) remainder[i] = remainder[i]! ^ mul(generator[count - 1 - i]!, factor);
  }
  return remainder;
}

/** Byte-mode bitstream: mode, length, payload, terminator, then the alternating pad. */
function codewords(payload: Uint8Array): Uint8Array {
  const bits: number[] = [];
  const push = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };
  push(0b0100, 4);
  push(payload.length, 8);
  for (const byte of payload) push(byte, 8);
  push(0, Math.min(4, DATA_CODEWORDS * 8 - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);

  const out = new Uint8Array(DATA_CODEWORDS + ECC_CODEWORDS);
  for (let i = 0; i < bits.length; i += 8) {
    out[i / 8] = bits.slice(i, i + 8).reduce((byte, bit) => (byte << 1) | bit, 0);
  }
  for (let i = bits.length / 8, pad = 0; i < DATA_CODEWORDS; i += 1, pad += 1) {
    out[i] = pad % 2 === 0 ? 0xec : 0x11;
  }
  out.set(ecc(out.subarray(0, DATA_CODEWORDS), ECC_CODEWORDS), DATA_CODEWORDS);
  return out;
}

type Grid = Int8Array[]; // -1 free, 0 light, 1 dark

function blank(): Grid {
  return Array.from({ length: SIZE }, () => new Int8Array(SIZE).fill(-1));
}

function place(grid: Grid, row: number, column: number, value: number): void {
  grid[row]![column] = value;
}

/** Finder patterns, separators, timing patterns, the alignment pattern, the dark module. */
function patterns(grid: Grid): void {
  const finder = (top: number, left: number) => {
    for (let r = -1; r <= 7; r += 1) {
      for (let c = -1; c <= 7; c += 1) {
        const row = top + r;
        const column = left + c;
        if (row < 0 || row >= SIZE || column < 0 || column >= SIZE) continue;
        const inside = r >= 0 && r <= 6 && c >= 0 && c <= 6;
        const ring = r === 0 || r === 6 || c === 0 || c === 6;
        const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        place(grid, row, column, inside && (ring || core) ? 1 : 0);
      }
    }
  };
  finder(0, 0);
  finder(0, SIZE - 7);
  finder(SIZE - 7, 0);

  for (let i = 8; i < SIZE - 8; i += 1) {
    const value = i % 2 === 0 ? 1 : 0;
    place(grid, 6, i, value);
    place(grid, i, 6, value);
  }
  // Version 3 has exactly one alignment pattern, centred on (22, 22).
  for (let r = -2; r <= 2; r += 1) {
    for (let c = -2; c <= 2; c += 1) {
      const edge = Math.abs(r) === 2 || Math.abs(c) === 2;
      place(grid, 22 + r, 22 + c, edge || (r === 0 && c === 0) ? 1 : 0);
    }
  }
  place(grid, SIZE - 8, 8, 1); // the always-dark module

  // Reserve the format-information areas so the data walk skips them.
  for (let i = 0; i <= 8; i += 1) {
    if (grid[8]![i] === -1) place(grid, 8, i, 0);
    if (grid[i]![8] === -1) place(grid, i, 8, 0);
    if (i < 8) {
      place(grid, 8, SIZE - 1 - i, 0);
      if (grid[SIZE - 1 - i]![8] === -1) place(grid, SIZE - 1 - i, 8, 0);
    }
  }
}

const MASKS = [
  (r: number, c: number) => (r + c) % 2 === 0,
  (r: number) => r % 2 === 0,
  (_r: number, c: number) => c % 3 === 0,
  (r: number, c: number) => (r + c) % 3 === 0,
  (r: number, c: number) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r: number, c: number) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r: number, c: number) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r: number, c: number) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

/** Penalty rules 1 and 2: long same-colour runs, and 2×2 same-colour blocks. */
function penalty(modules: Int8Array[]): number {
  let score = 0;
  for (let i = 0; i < SIZE; i += 1) {
    for (const line of [
      Array.from({ length: SIZE }, (_, j) => modules[i]![j]!),
      Array.from({ length: SIZE }, (_, j) => modules[j]![i]!),
    ]) {
      let run = 1;
      for (let j = 1; j < SIZE; j += 1) {
        if (line[j] === line[j - 1]) run += 1;
        else run = 1;
        if (run === 5) score += 3;
        else if (run > 5) score += 1;
      }
    }
  }
  for (let r = 0; r < SIZE - 1; r += 1) {
    for (let c = 0; c < SIZE - 1; c += 1) {
      const value = modules[r]![c];
      if (value === modules[r]![c + 1] && value === modules[r + 1]![c] && value === modules[r + 1]![c + 1]) {
        score += 3;
      }
    }
  }
  return score;
}

/**
 * Encodes up to 42 bytes as a 29×29 matrix of booleans (true = dark), ready to draw.
 */
export function encodeQr(text: string): boolean[][] {
  const payload = new TextEncoder().encode(text);
  if (payload.length > MAX_BYTES) {
    throw new Error(`qr: ${payload.length} bytes exceeds the ${MAX_BYTES} this encoder supports`);
  }
  const stream = codewords(payload);
  const reserved = blank();
  patterns(reserved);

  // The standard zig-zag walk: upward and downward column pairs, skipping column 6.
  const positions: Array<[number, number]> = [];
  for (let right = SIZE - 1; right > 0; right -= 2) {
    const column = right <= 6 ? right - 1 : right;
    const upward = ((SIZE - 1 - column) / 2) % 2 === 0;
    for (let i = 0; i < SIZE; i += 1) {
      const row = upward ? SIZE - 1 - i : i;
      for (const c of [column, column - 1]) {
        if (reserved[row]![c] === -1) positions.push([row, c]);
      }
    }
  }

  let best: { modules: Int8Array[]; mask: number; score: number } | null = null;
  for (let mask = 0; mask < MASKS.length; mask += 1) {
    const modules = reserved.map((row) => Int8Array.from(row));
    positions.forEach(([row, column], index) => {
      const bit = (stream[index >> 3]! >> (7 - (index & 7))) & 1;
      modules[row]![column] = MASKS[mask]!(row, column) ? bit ^ 1 : bit;
    });
    // Format information, written after masking because it is not itself masked here.
    const format = FORMAT_BITS[mask]!;
    for (let i = 0; i < 15; i += 1) {
      const bit = (format >> i) & 1;
      if (i < 6) modules[8]![i] = bit;
      else if (i === 6) modules[8]![7] = bit;
      else if (i === 7) modules[8]![8] = bit;
      else modules[14 - i]![8] = bit;

      if (i < 8) modules[8]![SIZE - 1 - i] = bit;
      else modules[SIZE - 15 + i]![8] = bit;
    }
    modules[SIZE - 8]![8] = 1;
    const score = penalty(modules);
    if (!best || score < best.score) best = { modules, mask, score };
  }
  return best!.modules.map((row) => Array.from(row, (value) => value === 1));
}

/** The matrix as an SVG document — no canvas, no image decoding, and CSP-safe as a data URL. */
export function qrSvg(text: string, moduleSize = 6, quiet = 4): string {
  const modules = encodeQr(text);
  const span = (modules.length + quiet * 2) * moduleSize;
  const rects = modules
    .flatMap((row, r) =>
      row.map((dark, c) =>
        dark
          ? `<rect x="${(c + quiet) * moduleSize}" y="${(r + quiet) * moduleSize}" width="${moduleSize}" height="${moduleSize}"/>`
          : "",
      ),
    )
    .join("");
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${span}" height="${span}" viewBox="0 0 ${span} ${span}" role="img" aria-label="safety number">` +
    `<rect width="${span}" height="${span}" fill="#fff"/><g fill="#000">${rects}</g></svg>`
  );
}
