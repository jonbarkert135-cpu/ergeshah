/**
 * Point 42: domain boundaries in a modular monolith, enforced by reading the imports rather
 * than by asking. One process, one deployable, no microservices — and still no module may
 * reach across a boundary the architecture document says is closed.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : path.endsWith(".ts") ? [path] : [];
  });
}

/** Every relative import of a file, resolved to a repository-relative path. */
function importsOf(file: string): string[] {
  const source = readFileSync(file, "utf8");
  return [...source.matchAll(/from\s+"(\.[^"]+)"/g)].map((m) => relative(root, resolve(dirname(file), m[1]!)));
}

const rules: Array<{ from: RegExp; mayNotImport: RegExp; why: string }> = [
  { from: /^src\/shared\//, mayNotImport: /^src\/(server|client)\//, why: "the protocol has no side" },
  { from: /^src\/client\//, mayNotImport: /^src\/server\//, why: "the client talks HTTP, not modules" },
  { from: /^src\/server\//, mayNotImport: /^src\/client\//, why: "the server serves the client, it does not run it" },
  { from: /^src\/server\/lib\//, mayNotImport: /^src\/server\/routes\//, why: "lib is below routes" },
  { from: /^src\/server\/db\//, mayNotImport: /^src\/server\/(routes|lib)\//, why: "the driver knows no domain" },
  {
    from: /^src\/server\/routes\/([a-z]+)\.ts$/,
    mayNotImport: /^src\/server\/routes\//,
    why: "one domain per route module; shared logic goes to lib/, wiring to app.ts",
  },
];

describe("domain boundaries hold", () => {
  it("no module imports across a closed boundary", () => {
    const violations: string[] = [];
    for (const file of files(join(root, "src"))) {
      const from = relative(root, file);
      for (const rule of rules) {
        if (!rule.from.test(from)) continue;
        for (const target of importsOf(file)) {
          if (rule.mayNotImport.test(target)) violations.push(`${from} → ${target} (${rule.why})`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("documents every route module as a domain", () => {
    const doc = readFileSync(join(root, "docs/ARCHITECTURE.md"), "utf8");
    for (const name of readdirSync(join(root, "src/server/routes"))) {
      expect(doc, `docs/ARCHITECTURE.md must name routes/${name}`).toContain(`routes/${name}`);
    }
  });
});
