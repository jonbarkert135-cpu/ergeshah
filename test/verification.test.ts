/**
 * Safety numbers (UI-1): the scannable code, and the state machine behind the badge.
 *
 * The encoder is ours (`src/shared/qr.ts`, no dependency); `jsqr` is a *dev* dependency
 * used here as a reference decoder, the same arrangement as `@scure/bip39` for BIP-39. A
 * QR code that our own tests declare valid but no scanner can read would be worse than
 * none, so the test decodes the rendered modules the way a camera would.
 */
import { beforeAll, describe, expect, it } from "vitest";
// The published types describe a CommonJS default export that TypeScript cannot call
// directly under this module setting; the interop shape is what actually ships.
import jsQRModule from "jsqr";

const jsQR = jsQRModule as unknown as (
  data: Uint8ClampedArray,
  width: number,
  height: number,
) => { data: string } | null;
import { encodeQr, qrSvg } from "../src/shared/qr.ts";
import { verificationState } from "../src/client/verification.ts";
import { safetyNumber } from "../src/shared/crypto/identity.ts";
import { createDeviceIdentity } from "../src/shared/crypto/identity.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import type { Conversation } from "../src/client/state.ts";

/** Renders the matrix into RGBA pixels with a quiet zone, exactly like the page does. */
function decode(text: string, scale = 4): string | undefined {
  const modules = encodeQr(text);
  const quiet = 4;
  const span = (modules.length + quiet * 2) * scale;
  const pixels = new Uint8ClampedArray(span * span * 4).fill(255);
  modules.forEach((row, r) =>
    row.forEach((dark, c) => {
      if (!dark) return;
      for (let y = 0; y < scale; y += 1) {
        for (let x = 0; x < scale; x += 1) {
          const at = (((r + quiet) * scale + y) * span + (c + quiet) * scale + x) * 4;
          pixels[at] = pixels[at + 1] = pixels[at + 2] = 0;
        }
      }
    }),
  );
  return jsQR(pixels, span, span)?.data;
}

function conversation(sessions: string[], verified: Record<string, number> = {}): Conversation {
  return {
    channel: "c",
    peer: "peer",
    messages: [],
    sessions: Object.fromEntries(sessions.map((key) => [key, {} as never])),
    verifiedKeys: Object.keys(verified).length ? verified : undefined,
  };
}

describe("safety number code", () => {
  beforeAll(async () => {
    await sodiumReady();
  });

  it("produces something a real scanner decodes", () => {
    const alice = createDeviceIdentity(0).identity.publicKey;
    const bob = createDeviceIdentity(0).identity.publicKey;
    const number = safetyNumber(alice, bob).replace(/ /g, "");
    expect(number).toHaveLength(40);
    expect(decode(number)).toBe(number);

    // Both sides compute the same number, so both sides show the same code.
    expect(safetyNumber(bob, alice)).toBe(safetyNumber(alice, bob));
    for (const payload of ["x", "0123456789", "y".repeat(42)]) {
      expect(decode(payload)).toBe(payload);
    }
  });

  it("refuses a payload it cannot encode instead of emitting an unscannable code", () => {
    expect(() => encodeQr("z".repeat(43))).toThrow(/exceeds/);
  });

  it("renders as a self-contained SVG with no external anything", () => {
    const svg = qrSvg("abcdef");
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).not.toMatch(/https?:\/\/(?!www\.w3\.org)/);
    expect(svg).not.toContain("<script");
    // 29 modules plus a quiet zone of 4 on each side, at 6 px.
    expect(svg).toContain(`width="${(29 + 8) * 6}"`);
  });
});

describe("verification state", () => {
  it("is 'none' until a session exists and someone compares it", () => {
    expect(verificationState(conversation([]))).toBe("none");
    expect(verificationState(conversation(["key-a"]))).toBe("none");
    expect(verificationState(conversation(["key-a"], { "key-a": 1 }))).toBe("verified");
  });

  it("flags a new unverified device rather than silently trusting it", () => {
    // The peer added a device — or someone put a key in its place. Only they can say which.
    expect(verificationState(conversation(["key-a", "key-b"], { "key-a": 1 }))).toBe("changed");
    expect(verificationState(conversation(["key-a", "key-b"], { "key-a": 1, "key-b": 2 }))).toBe(
      "verified",
    );
  });

  it("ignores verification of a key that is no longer in use", () => {
    // A retired device does not keep the conversation looking verified.
    expect(verificationState(conversation(["key-b"], { "key-a": 1 }))).toBe("none");
  });
});
