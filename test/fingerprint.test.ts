/**
 * Fingerprinting surface, and links that arrive carrying somebody else's identifier
 * (ADR-0098).
 *
 * A web page cannot make its visitors look alike — letterboxing, canvas noise and a spoofed
 * user agent are the browser's job, and Tor Browser does them properly. What a web page can
 * do is not *be* the thing that identifies its visitor: read no canvas, no WebGL renderer,
 * no audio stack, no screen dimensions, no plugin list, no time zone. That is a promise a
 * grep can keep, so it is a lint rule and these are its tests.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
// @ts-expect-error - plain ESM script, no types needed for one pure function
import { lintFile } from "../scripts/lint.mjs";
import { withoutQuery } from "../src/client/urls.ts";

const clientDir = fileURLToPath(new URL("../src/client/", import.meta.url));

function clientSources(dir = clientDir, prefix = "src/client/"): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) found.push(...clientSources(`${dir}${entry.name}/`, `${prefix}${entry.name}/`));
    else if (entry.name.endsWith(".ts")) found.push([`${prefix}${entry.name}`, readFileSync(`${dir}${entry.name}`, "utf8")]);
  }
  return found;
}

describe("the client does not fingerprint its own users", () => {
  it("flags every API that exists to tell one browser from another", () => {
    const cases = [
      'const ua = navigator.userAgent;', // audit:allow — fixture for the rule under test
      'const cores = navigator.hardwareConcurrency;', // audit:allow — fixture for the rule under test
      'const size = screen.width;', // audit:allow — fixture for the rule under test
      'const ctx = canvas.getContext("2d");', // audit:allow — fixture for the rule under test
      'const print = canvas.toDataURL();', // audit:allow — fixture for the rule under test
      'const audio = new AudioContext();', // audit:allow — fixture for the rule under test
      'const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;', // audit:allow — fixture for the rule under test
      'const ratio = window.devicePixelRatio;', // audit:allow — fixture for the rule under test
    ];
    for (const line of cases) {
      const findings = lintFile(`${line}\n`, "src/client/x.ts") as Array<{ name: string }>;
      expect(findings.map((f) => f.name), line).toContain("fingerprint-surface");
    }
  });

  it("leaves the APIs a client legitimately needs alone", () => {
    for (const line of ['void navigator.clipboard.writeText("x");', 'const el = document.createElement("div");']) {
      const findings = lintFile(`${line}\n`, "src/client/x.ts") as Array<{ name: string }>;
      expect(findings.map((f) => f.name), line).not.toContain("fingerprint-surface");
    }
  });

  it("is clean today, in every client and shared module", () => {
    const offenders = clientSources()
      .filter(([file, text]) =>
        (lintFile(text, file) as Array<{ name: string }>).some((f) => f.name === "fingerprint-surface"),
      )
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });
});

describe("a query string on this application came from somewhere else", () => {
  it("no client module reads one, which is what makes removing it safe", () => {
    // `urls.ts` is the module that removes it, and it reads the string it is handed rather
    // than the address bar; `views/market.ts` builds a query for an API call, which is the
    // other direction entirely.
    const readers = clientSources()
      .filter(([file]) => file !== "src/client/urls.ts")
      .filter(([, text]) => /\blocation\s*\.\s*search\b/.test(text))
      .map(([file]) => file);
    expect(readers, "a route that needs a query parameter must not be stripped on boot").toEqual([]);
  });

  it("removes the whole query and keeps the route, which lives in the fragment", () => {
    expect(withoutQuery("https://symvolon.example/?utm_source=mail&fbclid=x#/market")).toBe(
      "/#/market",
    );
    expect(withoutQuery("https://symvolon.example/?ref=partner")).toBe("/");
  });

  it("leaves a clean address alone, so no history entry is rewritten for nothing", () => {
    expect(withoutQuery("https://symvolon.example/#/orders")).toBeNull();
    expect(withoutQuery("https://symvolon.example/")).toBeNull();
    expect(withoutQuery("not a url at all")).toBeNull();
  });
});
