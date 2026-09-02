import { describe, expect, it } from "vitest";
import {
  MAX_PLAINTEXT_BYTES,
  pad,
  paddedLength,
  unpad,
} from "../src/shared/crypto/padding.ts";

describe("message padding", () => {
  it("round-trips every boundary length", () => {
    for (const length of [0, 1, 62, 63, 64, 255, 1023, 4095, 4096, 9000]) {
      const plaintext = new Uint8Array(length).fill(0x41);
      const restored = unpad(pad(plaintext));
      expect(restored.length).toBe(length);
      expect([...restored]).toEqual([...plaintext]);
    }
  });

  it("round-trips plaintext that ends in the marker or in zeros", () => {
    for (const tail of [0x80, 0x00]) {
      const plaintext = Uint8Array.of(1, 2, 3, tail);
      expect([...unpad(pad(plaintext))]).toEqual([...plaintext]);
    }
  });

  it("collapses lengths into buckets", () => {
    expect(paddedLength(0)).toBe(64);
    expect(paddedLength(63)).toBe(64);
    expect(paddedLength(64)).toBe(256);
    expect(paddedLength(255)).toBe(256);
    expect(paddedLength(1023)).toBe(1024);
    expect(paddedLength(4095)).toBe(4096);
    expect(paddedLength(4096)).toBe(8192);
    expect(paddedLength(20_000)).toBe(20_480);
  });

  it("rejects malformed padding and oversized plaintext", () => {
    expect(() => unpad(new Uint8Array(64))).toThrow(/malformed/);
    expect(() => unpad(Uint8Array.of(1, 2, 3))).toThrow(/malformed/);
    expect(() => unpad(new Uint8Array(0))).toThrow(/malformed/);
    expect(() => pad(new Uint8Array(MAX_PLAINTEXT_BYTES + 1))).toThrow(/exceeds/);
  });
});
