import { describe, expect, it, beforeAll } from "vitest";
import { hkdf, hkdfExtract, hkdfExpand } from "../src/shared/crypto/hkdf.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";

const hex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
const toHex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

beforeAll(async () => {
  await sodiumReady();
});

/** RFC 5869 appendix A — the only acceptable proof that a KDF is the KDF it claims to be. */
describe("HKDF-SHA256 (RFC 5869 test vectors)", () => {
  it("A.1 basic", () => {
    const ikm = hex("0b".repeat(22));
    const salt = hex("000102030405060708090a0b0c");
    const info = hex("f0f1f2f3f4f5f6f7f8f9");
    expect(toHex(hkdfExtract(salt, ikm))).toBe(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    );
    expect(toHex(hkdf(ikm, salt, info, 42))).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("A.2 longer inputs and outputs", () => {
    const ikm = hex(
      Array.from({ length: 80 }, (_, i) => i.toString(16).padStart(2, "0")).join(""),
    );
    const salt = hex(
      Array.from({ length: 80 }, (_, i) => (0x60 + i).toString(16).padStart(2, "0")).join(""),
    );
    const info = hex(
      Array.from({ length: 80 }, (_, i) => (0xb0 + i).toString(16).padStart(2, "0")).join(""),
    );
    expect(toHex(hkdf(ikm, salt, info, 82))).toBe(
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );
  });

  it("A.3 zero-length salt and info", () => {
    const ikm = hex("0b".repeat(22));
    expect(toHex(hkdf(ikm, new Uint8Array(0), new Uint8Array(0), 42))).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
  });

  it("refuses to expand beyond 255 blocks", () => {
    expect(() => hkdfExpand(new Uint8Array(32), new Uint8Array(0), 255 * 32 + 1)).toThrow(
      /too large/,
    );
  });
});
