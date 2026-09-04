/**
 * UI-3. Accessibility, checked by reading the client rather than by intending it.
 *
 * ADR-0031 put the properties into the helpers — `field()`, `table()`, `formDialog()`,
 * `announce()` — and checked the stylesheet. What no test covered was the code that uses
 * them: a view can still build a bare `<input>`, write an error into a silent `<div>`, or
 * redraw a region and drop the keyboard on the floor. Those are the three failures this
 * file refuses, plus the unit tests for the focus helper that makes the third fixable.
 *
 * The rules are deliberately mechanical. Anything that needs judgement — does the label
 * say something useful, is the reading order sensible — belongs to the browser pass
 * recorded in docs/DESIGN.md, not here.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { focusKey, nearestIndex } from "../src/client/ui.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const viewsDir = join(root, "src/client/views");
const views = readdirSync(viewsDir).filter((name) => name.endsWith(".ts"));
const read = (file: string) => readFileSync(file, "utf8");
const source = (file: string) => read(join(viewsDir, file));

describe("every control has a name", () => {
  it("builds no input, select or textarea without a label, an aria-label or a name", () => {
    // `field()` associates a `<label>`; `input()` takes a name; anything built directly
    // has to say what it is. A control the browser cannot name is a control a screen
    // reader announces as "edit text, blank".
    const nameless: string[] = [];
    for (const file of views) {
      const text = source(file);
      for (const match of text.matchAll(
        /const\s+(\w+)\s*=\s*(?:\(\)\s*=>\s*)?el\(\s*"(input|select|textarea)"\s*,\s*\{([^}]*)\}/g,
      )) {
        const [, binding, tag, attrs] = match as unknown as [string, string, string, string];
        // Named by an attribute the browser reads…
        if (/aria-label|"name"|\bname:/.test(attrs)) continue;
        // …or handed to `field()`, which associates a real <label> with it.
        if (new RegExp(`field\\([^;]*\\b${binding}\\b`).test(text)) continue;
        nameless.push(`${file}: <${tag}> ${binding}`);
      }
    }
    expect(nameless).toEqual([]);
  });

  it("gives every icon-only button an accessible name", () => {
    // A button whose whole content is an SVG has no text to announce; `aria-label` is the
    // only name it will ever have.
    const files = [join(root, "src/client/main.ts"), ...views.map((name) => join(viewsDir, name))];
    for (const file of files) {
      const text = read(file);
      for (const match of text.matchAll(/\{[^{}]*class:\s*"[^"]*\bicon\b[^"]*"[^{}]*\}/g)) {
        expect(match[0], `icon button in ${file} needs aria-label`).toContain("aria-label");
      }
    }
  });
});

describe("what changes is said", () => {
  it("writes outcomes into a live region, never into a bare div", () => {
    // A message that appears after a submit is silence for a screen reader unless the
    // container it lands in is live. `statusRegion()` is that container.
    const silent: string[] = [];
    for (const file of views) {
      for (const [, decl] of source(file).matchAll(/const\s+(status|message)\s*=\s*el\("div",\s*\{\s*\}\)/g)) {
        silent.push(`${file}: ${decl}`);
      }
    }
    expect(silent).toEqual([]);
  });

  it("keeps the live regions polite and few", () => {
    // Assertive interrupts whatever is being read; there is nothing in a marketplace
    // urgent enough to deserve it. And a live region around a whole view reads every
    // render aloud, which is the mistake ADR-0031 removed from index.html.
    const client = [
      join(root, "src/client/ui.ts"),
      join(root, "src/client/main.ts"),
      ...views.map((name) => join(viewsDir, name)),
    ];
    for (const file of client) {
      expect(read(file), `${file} must not use aria-live="assertive"`).not.toContain('"assertive"');
    }
    expect(read(join(root, "src/client/main.ts"))).not.toMatch(/el\("main",\s*\{[^}]*aria-live/);
  });
});

describe("the keyboard keeps its place", () => {
  it("anchors focus in every view that redraws a region under the reader", () => {
    // These views rebuild a container after an action — a filter, a status change, a
    // deletion. Without `focusAnchor()` the element the reader was standing on is
    // destroyed and focus falls to <body>, which is the top of the page.
    for (const file of ["account.ts", "admin.ts", "chat.ts", "market.ts", "notifications.ts", "orders.ts", "security.ts", "wallet.ts"]) {
      expect(source(file), `${file} redraws and must anchor focus`).toContain("focusAnchor(");
    }
  });

  it("uses no positive tabindex anywhere in the client", () => {
    // A positive tabindex reorders the whole document's tab sequence, not just its own
    // corner of it. `-1` (a programmatic landing point) is the only value used here.
    const files = [
      join(root, "src/client/ui.ts"),
      join(root, "src/client/main.ts"),
      ...views.map((name) => join(viewsDir, name)),
    ];
    for (const file of files) {
      for (const match of read(file).matchAll(/tabindex["']?\s*[:,]\s*["'](-?\d+)["']/g)) {
        expect(Number(match[1]), `${file} uses tabindex ${match[1]}`).toBeLessThanOrEqual(0);
      }
    }
  });
});

/**
 * The focus helper's two decisions, tested without a DOM: which name identifies a control
 * across a redraw, and which of its surviving twins to land on. Everything else in
 * `focusAnchor()` is `querySelectorAll` and `.focus()`, which the browser pass covers.
 */
describe("focusKey and nearestIndex", () => {
  const node = (tagName: string, attrs: Record<string, string> = {}, text = "") => ({
    tagName,
    getAttribute: (name: string) => attrs[name] ?? null,
    textContent: text,
  });

  it("names a control by its key, id, label, name, then its words", () => {
    expect(focusKey(node("BUTTON", { "data-focus": "settle" }, "Settle"))).toBe("button:settle");
    expect(focusKey(node("INPUT", { id: "f3", name: "q" }))).toBe("input:f3");
    expect(focusKey(node("BUTTON", { "aria-label": "Report a listing" }, "Report"))).toBe("button:Report a listing");
    expect(focusKey(node("INPUT", { name: "username" }))).toBe("input:username");
    expect(focusKey(node("BUTTON", {}, "  Confirm &\n  complete "))).toBe("button:Confirm & complete");
  });

  it("treats a redrawn twin as the same control", () => {
    const before = node("BUTTON", {}, "Accept");
    const after = node("BUTTON", {}, "Accept");
    expect(focusKey(before)).toBe(focusKey(after));
    // …and distinguishes controls that merely look alike.
    expect(focusKey(node("A", {}, "Accept"))).not.toBe(focusKey(before));
  });

  it("lands on the nearest survivor when the list got shorter, and nowhere when it is empty", () => {
    expect(nearestIndex(6, 2)).toBe(2); // same row, redrawn
    expect(nearestIndex(3, 5)).toBe(2); // rows removed: the last one that remains
    expect(nearestIndex(4, -1)).toBe(0); // the control was not found before: the first
    expect(nearestIndex(0, 2)).toBe(-1); // nothing survived: the caller lands on the heading
  });
});
