/**
 * Points 103, 106: two pages that rot the moment nobody checks them.
 *
 * `docs/FEATURES.md` claims every feature is complete in nine ways. `docs/SOURCES.md` claims
 * every construction comes from a named primary source. Both are worth exactly as much as the
 * test that fails when a new route, view, table or specification does not appear in them.
 */
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const features = read("docs/FEATURES.md");
const sources = read("docs/SOURCES.md");

function filesIn(directory: string): string[] {
  return readdirSync(new URL(`../${directory}`, import.meta.url)).filter((name) =>
    name.endsWith(".ts"),
  );
}

describe("the feature matrix (point 106)", () => {
  it("has a row for every route file", () => {
    const missing = filesIn("src/server/routes")
      .filter((name) => name !== "static.ts")
      .filter((name) => !features.includes(`routes/${name}`));
    expect(missing, "routes with no row in docs/FEATURES.md").toEqual([]);
  });

  it("has a row for every screen", () => {
    const missing = filesIn("src/client/views").filter(
      (name) => !features.includes(`views/${name}`),
    );
    expect(missing, "views with no row in docs/FEATURES.md").toEqual([]);
  });

  it("accounts for every table in the schema", () => {
    const directory = new URL("../src/server/db/migrations/", import.meta.url);
    const tables = new Set<string>();
    for (const file of readdirSync(directory).filter((name) => name.endsWith(".sql"))) {
      const sql = readFileSync(new URL(file, directory), "utf8");
      for (const match of sql.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)/g)) {
        tables.add(match[1]!);
      }
    }
    // `schema_migrations` is the migration runner's own bookkeeping, not a feature.
    tables.delete("schema_migrations");
    const missing = [...tables].filter((table) => !features.includes(table));
    expect(missing, "tables no feature admits to owning").toEqual([]);
  });

  it("names test files that exist", () => {
    const suites = new Set(filesIn("test"));
    const named = [...features.matchAll(/`([a-z]+\.test\.ts)`/g)].map((match) => match[1]!);
    expect(named.length).toBeGreaterThan(15);
    expect(named.filter((name) => !suites.has(name))).toEqual([]);
  });

  it("still admits what is unfinished", () => {
    // The value of this page is the second half. A commit that deletes the honest section to
    // make the matrix look complete should fail here.
    const gaps = features.slice(features.indexOf("## What is missing"));
    expect(gaps).toMatch(/roadmap OPS-6/);
    expect(gaps).toMatch(/roadmap CRY-1/);
    expect(gaps.split("\n- ").length).toBeGreaterThanOrEqual(4);
  });
});

describe("primary sources (point 103)", () => {
  it("cites every specification the documentation mentions", () => {
    const cited = new Set<string>();
    for (const file of readdirSync(new URL("../docs/", import.meta.url))) {
      if (!file.endsWith(".md") || file === "SOURCES.md") continue;
      for (const match of read(`docs/${file}`).matchAll(/\bRFC ?(\d{3,5})\b/g)) {
        cited.add(match[1]!);
      }
    }
    const missing = [...cited].filter((rfc) => !new RegExp(`RFC ?${rfc}\\b`).test(sources));
    expect(missing, "RFCs cited elsewhere but absent from docs/SOURCES.md").toEqual([]);
  });

  it("labels what is known, assumed, chosen, risked and unknown", () => {
    for (const label of ["FACT", "ASSUMPTION", "DESIGN CHOICE", "RISK", "UNKNOWN"]) {
      expect(sources, `${label} is missing`).toContain(`**${label}**`);
    }
  });

  it("keeps the two rules that make the table meaningful", () => {
    // Point 104, in the words the rest of the repository uses.
    expect(sources).toMatch(/primitives are never\s*\n?written here/i);
    expect(sources).toMatch(/published specification/i);
    // HKDF is the single hand-written construction; if a second one appears, this page has to
    // say so, and this assertion is the reminder.
    const written = sources.match(/Written here/g) ?? [];
    expect(written).toHaveLength(1);
  });
});
