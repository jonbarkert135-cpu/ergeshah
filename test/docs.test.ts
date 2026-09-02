/**
 * Documentation that drifts is worse than no documentation, because people trust it. These
 * tests compare three documents with the running system: every route against Fastify's own
 * route table, every table against the schema the migrations produce, every environment
 * variable against what `config.ts` actually reads.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { startTestServer, type TestServer } from "./helpers.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;

beforeAll(async () => {
  server = await startTestServer();
});

afterAll(async () => {
  await server.close();
});

describe("docs/API.md matches the routes that exist", () => {
  it("documents every endpoint", () => {
    const doc = read("docs/API.md");
    const undocumented = server.app.routeInventory
      .filter((route) => route.method !== "HEAD" && route.method !== "OPTIONS")
      // Built assets are content-addressed: their names change with every build, so the
      // documentation describes the pattern rather than today's hashes.
      .map((route) => `${route.method} ${route.url.replace(/^\/assets\/.*/, "/assets/*")}`)
      .filter((signature) => !doc.includes(`\`${signature}\``))
      .sort();
    expect(undocumented, "add these to docs/API.md").toEqual([]);
  });

  it("documents nothing that has been removed", () => {
    const doc = read("docs/API.md");
    const live = new Set(
      server.app.routeInventory.map(
        (route) => `${route.method} ${route.url.replace(/^\/assets\/.*/, "/assets/*")}`,
      ),
    );
    // Routes served from `public/` exist only once the client is built, and audit.test.ts
    // rebuilds it in a parallel worker while this server starts — so their presence here is
    // a race, not a fact about the documentation. That they are served is asserted there.
    for (const built of ["GET /assets/*", "GET /favicon.svg", "GET /build.txt"]) live.add(built);
    const stale = [...doc.matchAll(/`(GET|POST|PUT|PATCH|DELETE) (\/[^`]*)`/g)]
      .map((match) => `${match[1]} ${match[2]}`)
      .filter((signature) => !live.has(signature))
      .sort();
    expect([...new Set(stale)], "remove these from docs/API.md").toEqual([]);
  });
});

describe("docs/DATABASE.md matches the schema", () => {
  it("describes every table the migrations create", async () => {
    const doc = read("docs/DATABASE.md");
    const tables = (
      await server.db.all<{ name: string }>(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
      )
    ).map((row) => row.name);
    expect(tables.length).toBeGreaterThan(10);
    const undocumented = tables.filter((name) => !doc.includes(`\`${name}\``)).sort();
    expect(undocumented, "add these to docs/DATABASE.md").toEqual([]);
  });
});

describe("docs/ENVIRONMENT.md matches what the server reads", () => {
  it("documents every variable, and .env.example stays in step", () => {
    const config = read("src/server/config.ts");
    const doc = read("docs/ENVIRONMENT.md");
    const names = new Set<string>();
    for (const match of config.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) names.add(match[1]!);
    for (const match of config.matchAll(/secretFromEnv\("([A-Z][A-Z0-9_]*)"\)/g)) names.add(match[1]!);
    for (const match of config.matchAll(/requiredSecret\("([A-Z][A-Z0-9_]*)"/g)) names.add(match[1]!);

    expect(names.size).toBeGreaterThan(10);
    const undocumented = [...names].filter((name) => !doc.includes(`\`${name}\``)).sort();
    expect(undocumented, "add these to docs/ENVIRONMENT.md").toEqual([]);

    // The example file is what an operator copies; it may omit defaults, but it must not
    // mention a variable that no longer exists.
    const example = read(".env.example");
    const invented = [...example.matchAll(/^([A-Z][A-Z0-9_]*)=/gm)]
      .map((match) => match[1]!)
      .filter((name) => !names.has(name) && !name.endsWith("_FILE") && name !== "NODE_ENV")
      .sort();
    expect(invented, "these are in .env.example but nothing reads them").toEqual([]);
  });
});

describe("the documents point 31 requires are present and not empty", () => {
  it("has each one, with substance", () => {
    for (const [path, minimumLines] of [
      ["README.md", 40],
      ["CONTRIBUTING.md", 40],
      ["SECURITY.md", 20],
      ["LICENSE", 5],
      ["THIRD_PARTY.md", 15],
      ["docs/ARCHITECTURE.md", 60],
      ["docs/THREAT_MODEL.md", 60],
      ["docs/CRYPTO.md", 60],
      ["docs/PRIVACY.md", 60],
      ["docs/API.md", 60],
      ["docs/DATABASE.md", 60],
      ["docs/DEPENDENCIES.md", 40],
      ["docs/DEPLOYMENT.md", 60],
      ["docs/ENVIRONMENT.md", 40],
      ["docs/TESTING.md", 30],
      ["docs/DESIGN.md", 40],
      ["docs/PERFORMANCE.md", 40],
      ["docs/AUDIT.md", 40],
      ["docs/DECISIONS.md", 100],
    ] as const) {
      const lines = read(path).split("\n").length;
      expect(lines, path).toBeGreaterThanOrEqual(minimumLines);
    }
  });

  it("makes no absolute security claim anywhere in the documentation", () => {
    // The rule from the brief, enforced rather than remembered: no "unbreakable", no
    // "100% anonymous", no "impossible to deanonymise".
    const forbidden =
      /\b(unbreakable|unhackable|100% (?:secure|anonymous|private)|absolutely (?:secure|anonymous|private)|mathematically guarantees? (?:anonymity|privacy)|impossible to (?:break|deanonymi[sz]e)|no metadata (?:at all|whatsoever))\b/i;
    for (const path of [
      "README.md",
      "SECURITY.md",
      "docs/ARCHITECTURE.md",
      "docs/THREAT_MODEL.md",
      "docs/CRYPTO.md",
      "docs/PRIVACY.md",
      "docs/API.md",
      "docs/AUDIT.md",
    ]) {
      // Naming the forbidden phrase in order to *reject* it is exactly what these documents
      // are supposed to do ("Not unbreakable.", "does not claim to be anonymous"). So the
      // test looks at what precedes the phrase — within the sentence, which may begin on the
      // line above — and accepts it when it is negated.
      const negated = /\b(?:not|never|no|nor|neither|cannot|refuses?)\b[^.]{0,80}$/i;
      const lines = read(path).split("\n");
      const offending = lines
        .map((line, index) => [index + 1, line] as const)
        .filter(([number, line]) => {
          const match = line.replace(/[*_`]/g, "").match(forbidden);
          if (!match) return false;
          const before = `${lines[number - 2] ?? ""} ${line}`.replace(/[*_`]/g, "");
          return !negated.test(before.slice(0, before.lastIndexOf(match[0])));
        });
      expect(offending, path).toEqual([]);
    }
  });
});
