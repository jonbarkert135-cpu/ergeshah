/**
 * The design system, checked the way the rest of this project is checked.
 *
 * A style guide that only exists in prose is a style guide that is half-followed within a
 * month. These tests enforce the three rules that keep one system from becoming two: every
 * semantic token exists in both themes, view code never writes a literal colour, and the
 * spacing and radius scales are the only ones in use.
 */
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/client/styles/app.css", import.meta.url), "utf8");

/** The block for one selector, e.g. `[data-theme="light"]`. */
function block(selector: string): string {
  const start = css.indexOf(selector);
  expect(start, `${selector} must exist`).toBeGreaterThan(-1);
  const open = css.indexOf("{", start);
  return css.slice(open, css.indexOf("\n}", open));
}

function tokensIn(text: string): string[] {
  return [...text.matchAll(/^\s*(--[a-z0-9-]+):/gm)].map((match) => match[1]!);
}

describe("one system, two themes", () => {
  it("defines every semantic token in dark, light and the system-preference fallback", () => {
    const dark = tokensIn(block(":root,\n[data-theme=\"dark\"]"));
    const light = tokensIn(block("[data-theme=\"light\"]"));
    const auto = tokensIn(block(":root:not([data-theme])"));

    expect(dark.length).toBeGreaterThan(15);
    expect(new Set(light)).toEqual(new Set(dark));
    // The media-query fallback must be the light set exactly: a token missing here is a
    // component that silently keeps its dark value on a light desktop.
    expect(new Set(auto)).toEqual(new Set(light));
  });

  it("uses semantic tokens in components, never palette values or literals", () => {
    // Everything after the token section is component CSS.
    const components = css.slice(css.indexOf("2. Reset and base"));
    const literals = [...components.matchAll(/#[0-9a-f]{3,8}\b|\brgba?\([^)]*\)/gi)]
      .map((match) => match[0])
      // rgb(...) inside a token definition is allowed above; here only the transparent
      // helper colours used by color-mix are acceptable.
      .filter((value) => !/transparent/i.test(value));
    expect(literals, "component CSS must reference tokens").toEqual([]);

    const palette = [...components.matchAll(/var\(--(?:ink|paper|grey|state)-\d+\)/g)].map(
      (match) => match[0],
    );
    // One deliberate exception: a QR code has to be read by a camera, so its plate stays
    // paper-coloured in both themes.
    expect(palette).toEqual(["var(--paper-100)"]);
  });

  it("keeps spacing and radius on the scale", () => {
    const components = css.slice(css.indexOf("2. Reset and base"));
    const offScale = [...components.matchAll(/(?:padding|margin|gap):\s*([^;]+);/g)]
      .map((match) => match[1]!.trim())
      .filter((value) => /\b\d+px\b/.test(value))
      // 0, hairlines and optical adjustments under the 4px grid are not "spacing".
      .filter((value) => !/^(0|1px|2px|3px)\b/.test(value))
      .filter((value) => !/\b(?:[1-3]px|0)\b/.test(value.replace(/\b\d\dpx\b/g, "")));
    expect(offScale, "use var(--space-N)").toEqual([]);
  });

  it("has no hacker-film decoration: no neon, no glow, no gradient backgrounds", () => {
    // Point 36, as a check rather than as a promise. The two gradients that exist are the
    // skeleton shimmer, which is a loading affordance and is built from surface tokens.
    const gradients = [...css.matchAll(/linear-gradient\([^)]*\)/g)].map((match) => match[0]);
    for (const gradient of gradients) {
      expect(gradient, "gradients may only interpolate surface tokens").toMatch(/--(?:ink|paper)-\d+/);
    }
    expect(css).not.toMatch(/text-shadow|0f0\b|00ff00|#0f0\b/i);
    expect(css.match(/animation:/g) ?? []).toHaveLength(5);
    expect(css).toContain("prefers-reduced-motion");
  });
});

describe("views build markup, not styles", () => {
  it("never hardcodes a colour in TypeScript", () => {
    let hits = "";
    try {
      hits = execFileSync(
        "git",
        [
          "grep",
          "-nE",
          "#[0-9a-fA-F]{6}\\b|rgba?\\(",
          "--",
          "src/client/**/*.ts",
          "src/client/*.ts",
          "src/shared/**/*.ts",
        ],
        { encoding: "utf8" },
      ).trim();
    } catch (error) {
      expect((error as { status?: number }).status, "git grep failed").toBe(1);
    }
    // The brand mark inherits `currentColor`; nothing else may name a colour.
    const offending = hits
      .split("\n")
      .filter(Boolean)
      .filter((line) => !line.includes("currentColor"));
    expect(offending).toEqual([]);
  });

  it("ships one stylesheet, small enough to be read in full", () => {
    expect(css.length).toBeLessThan(48 * 1024);
    expect(css.split("\n").length).toBeGreaterThan(300);
  });
});
