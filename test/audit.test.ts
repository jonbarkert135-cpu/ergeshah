import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { startTestServer } from "./helpers.ts";
// @ts-expect-error - plain ESM script, no types needed for two pure functions
import { scanBundle, scanSource } from "../scripts/audit.mjs";
// @ts-expect-error - same: the linter is a plain ESM script
import { lintFile } from "../scripts/lint.mjs";

// This file necessarily contains every string the secret audit looks for, so its own
// fixture lines carry `audit:allow` — the same escape hatch the audit documents.
const rules = (findings: Array<{ rule: string }>) => findings.map((f) => f.rule);

describe("bundle audit", () => {
  it("catches anything that makes the browser talk to another host", () => {
    expect(rules(scanBundle(`fetch("https://cdn.example.net/a.js")`))).toContain("remote URL");
    expect(rules(scanBundle(`<script src="//cdn.jsdelivr.net/x.js">`))).toContain("protocol-relative URL");
    expect(rules(scanBundle(`new WebSocket("wss://analytics.tracker.io/s")`))).toContain("remote URL");
    expect(rules(scanBundle(`navigator.sendBeacon("/x", d)`))).toContain("telemetry API");
    expect(rules(scanBundle(`//# sourceMappingURL=app.js.map`))).toContain("source map reference");
    expect(rules(scanBundle(`import { readKey } from "openpgp";`))).toContain("server-only dependency");
  });

  it("leaves our own origin and loopback alone", () => {
    expect(scanBundle(`fetch("/api/messages"); const dev = "http://127.0.0.1:8080";`)).toEqual([]);
  });

  it("does not mistake an XML namespace for a network call", () => {
    // The QR code is an inline SVG, and a standalone SVG must carry this exact attribute.
    expect(scanBundle(`<svg xmlns="http://www.w3.org/2000/svg">`)).toEqual([]);
    // The exemption is that one identifier, not the domain.
    expect(rules(scanBundle(`fetch("https://www.w3.org/tracker.js")`))).toContain("remote URL");
  });

  it("reports the line number, so a 1 MB bundle is still reviewable", () => {
    const findings = scanBundle(`ok\nok\nfetch("https://evil.example.com/x")\n`);
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(3);
  });
});

describe("secret audit", () => {
  it("catches committed key material", () => {
    expect(rules(scanSource("-----BEGIN OPENPGP PRIVATE KEY BLOCK-----"))).toContain("private key block"); // audit:allow fixture
    expect(rules(scanSource("-----BEGIN EC PRIVATE KEY-----"))).toContain("private key block"); // audit:allow fixture
    expect(rules(scanSource("aws_key = AKIAIOSFODNN7EXAMPLE"))).toContain("AWS access key id"); // audit:allow fixture
    expect(rules(scanSource("auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP0mB92K"))).toContain( // audit:allow fixture
      "JWT",
    );
    expect(rules(scanSource(`const dbPassword = "hunter2-9f3a-b71c-2210"`))).toContain("credential literal");
  });

  it("does not fire on placeholders, env lookups or short values", () => {
    expect(scanSource(`SESSION_SECRET=changeme-in-production`)).toEqual([]);
    expect(scanSource(`const secret = process.env.SESSION_SECRET;`)).toEqual([]);
    expect(scanSource(`const token = "short";`)).toEqual([]);
    expect(scanSource(`password: "your-password-here"`)).toEqual([]);
  });

  it("allows an opted-out line, and only that line", () => {
    const text = `const key = "AKIAIOSFODNN7EXAMPLZ" // audit:allow test vector\nconst k2 = "AKIAIOSFODNN7EXAMPLZ"`;
    const findings = scanSource(text);
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(2);
  });

  it("keeps fixture passwords in test/ quiet but never key material", () => {
    const fixture = `const PASSWORD = "correct horse battery staple";`;
    expect(scanSource(fixture, "test/helpers.ts")).toEqual([]);
    expect(scanSource(fixture, "src/server/config.ts")).toHaveLength(1);
    expect(rules(scanSource("-----BEGIN PGP PRIVATE KEY BLOCK-----", "test/pgp.test.ts"))).toContain( // audit:allow fixture
      "private key block",
    );
  });
});

/**
 * Reproducible builds (OPS-1). The expensive property — two builds are byte-identical —
 * is checked by `npm run audit:bundle` in CI; here we check the parts that would silently
 * make that check meaningless: that the build actually publishes digests, that they match
 * the files on disk, and that the page pins the bundle it was built with.
 */
describe("reproducible build", () => {
  const root = new URL("../", import.meta.url);
  const digest = (bytes: Uint8Array | string) =>
    `sha256-${createHash("sha256").update(bytes).digest("base64")}`;

  it("publishes digests that match the files it produced", () => {
    execFileSync(process.execPath, ["scripts/build-client.mjs"], {
      cwd: fileURLToPath(root),
      env: { ...process.env, NODE_ENV: "production" },
    });
    const listed = readFileSync(new URL("public/BUILD.txt", root), "utf8").trim().split("\n");
    expect(listed).toHaveLength(4);
    for (const line of listed) {
      const [hash, file] = line.split("  ");
      expect(digest(readFileSync(new URL(`public/${file}`, root)))).toBe(hash);
    }
  });

  it("pins the script and stylesheet in the page, so a swapped bundle is refused", () => {
    const shell = readFileSync(new URL("public/index.html", root), "utf8");
    const js = digest(readFileSync(new URL("public/app.js", root)));
    const css = digest(readFileSync(new URL("public/app.css", root)));
    expect(shell).toContain(`src="/assets/app.js" integrity="${js}"`);
    expect(shell).toContain(`href="/assets/app.css" integrity="${css}"`);
  });

  it("serves the digests, so a deployment can be compared with a local build", async () => {
    const server = await startTestServer();
    try {
      const response = await server.app.inject({ method: "GET", url: "/build.txt" });
      expect(response.statusCode).toBe(200);
      expect(response.headers["content-type"]).toContain("text/plain");
      expect(response.body).toBe(readFileSync(new URL("public/BUILD.txt", root), "utf8"));
    } finally {
      await server.close();
    }
  });
});

describe("lint", () => {
  it("catches the mistakes it exists for", () => {
    const cases: Array<[string, string, string]> = [
      ["html-from-string", "src/client/x.ts", 'node.innerHTML = value;'], // audit:allow — fixture for the rule under test
      ["dynamic-code", "src/client/x.ts", 'const f = new Function("return 1");'], // audit:allow — fixture for the rule under test
      ["weak-random", "src/shared/x.ts", "const n = Math.random();"], // audit:allow — fixture for the rule under test
      ["environment-outside-config", "src/server/routes/x.ts", "const p = process.env.PORT;"], // audit:allow — fixture for the rule under test
      ["console-in-server", "src/server/x.ts", 'console.log("hello");'], // audit:allow — fixture for the rule under test
      ["sql-interpolation", "src/server/x.ts", "await db.all(`SELECT * FROM t WHERE id = ${id}`);"], // audit:allow — fixture for the rule under test
      ["focused-test", "test/x.test.ts", 'it.only("x", () => {});'], // audit:allow — fixture for the rule under test
      ["unsafe-any", "src/server/x.ts", "const value = body as any;"], // audit:allow — fixture for the rule under test
    ];
    for (const [rule, file, line] of cases) {
      const findings = lintFile(`${line}\n`, file) as Array<{ name: string }>;
      expect(
        findings.map((f) => f.name),
        `${rule} in ${file}`,
      ).toContain(rule);
    }
  });

  it("respects a waiver on the line and on the line above, and nowhere else", () => {
    const file = "src/server/x.ts";
    expect(lintFile("const v = body as any; // audit:allow reviewed\n", file)).toEqual([]);
    expect(lintFile("// audit:allow reviewed\nconst v = body as any;\n", file)).toEqual([]);
    expect(lintFile("// audit:allow reviewed\n\nconst v = body as any;\n", file)).toHaveLength(1);
  });

  it("does not fire on a comment that describes the rule", () => {
    // The codebase explains its own invariants in prose; a linter that cannot tell prose
    // from code makes people delete the prose.
    expect(lintFile("// never assign innerHTML from user content\nconst a = 1;\n", "src/client/x.ts")).toEqual([]);
  });
});
