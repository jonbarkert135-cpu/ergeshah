import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { startTestServer } from "./helpers.ts";
// @ts-expect-error - plain ESM script, no types needed for two pure functions
import { isTelemetryPackage, scanBundle, scanEgress, scanSource } from "../scripts/audit.mjs";
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

describe("egress audit (points 51, 52, 53)", () => {
  it("finds a call that leaves the process", () => {
    expect(rules(scanEgress(`const r = await fetch(endpoint, { method: "POST" });`))).toContain(
      "outbound request",
    );
    expect(rules(scanEgress(`https.request(options, handle);`))).toContain("outbound request");
    expect(rules(scanEgress(`const s = net.connect(9000, host);`))).toContain("raw socket");
    expect(rules(scanEgress(`import { lookup } from "node:dns";`))).toContain("name resolution");
  });

  it("does not mistake the database or the router for a network call", () => {
    // The reason a rule like this gets switched off is false positives, and this codebase is
    // full of `db.get(` and `app.get(`.
    expect(scanEgress(`const row = await db.get("SELECT 1 AS ok");`)).toEqual([]);
    expect(scanEgress(`app.get("/api/attachments/:id", handler);`)).toEqual([]);
    expect(scanEgress(`const held = state.vault?.deliveries?.[order.id];`)).toEqual([]);
  });

  it("knows a telemetry package by name, and leaves the four real dependencies alone", () => {
    for (const name of [
      "node_modules/@sentry/node",
      "node_modules/posthog-node",
      "node_modules/dd-trace",
      "node_modules/@opentelemetry/api",
    ]) {
      expect(isTelemetryPackage(name), name).toBe(true);
    }
    for (const name of ["node_modules/pg", "node_modules/fastify", "node_modules/openpgp"]) {
      expect(isTelemetryPackage(name), name).toBe(false);
    }
  });

  it("passes on this tree, which is the assertion that matters", () => {
    // Six call sites, all in files the audit names with a reason. A seventh fails the build.
    const output = execFileSync("node", ["scripts/audit.mjs", "egress"], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      encoding: "utf8",
    });
    expect(output).toMatch(/all accounted for/);
    expect(output).toMatch(/no telemetry/);
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

  // SEC-2026-021: the lockfile was skipped by path in both the working-tree and the history
  // scan, so a registry URL carrying `user:TOKEN@` ended up committed with a green build.
  it("catches a credential in a URL, including inside the lockfile", () => {
    const lock = JSON.stringify({
      packages: { "node_modules/x": { resolved: "https://ci-bot:npm_9f3ab71c2210deadbeef@registry.example.internal/x/-/x-1.0.0.tgz" } }, // audit:allow fixture
    });
    expect(rules(scanSource(lock, "package-lock.json"))).toContain("credential in URL");
    expect(rules(scanSource("//registry.example.internal/:_authToken=npm_9f3ab71c2210deadbeef00", ".npmrc"))).toContain("npm auth token"); // audit:allow fixture
    // The lockfile is scanned with the key-material rules only: a JSON of `"integrity": "sha512-…"`
    // lines is not a credential literal.
    expect(scanSource(JSON.stringify({ token: "sha512-abcdefghijklmnopqrstuvwxyz" }), "package-lock.json")).toEqual([]);
    // And a placeholder is still a placeholder.
    expect(scanSource("https://user:changeme@registry.example.org/", "README.md")).toEqual([]);
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
    // Entry, the lazily loaded crypto chunk (plus esbuild's shared stub), stylesheet,
    // icon and shell: every byte the server will serve, and nothing that it will not.
    expect(listed.length).toBeGreaterThanOrEqual(5);
    for (const line of listed) {
      const [hash, file] = line.split("  ");
      expect(digest(readFileSync(new URL(`public/${file}`, root))), file).toBe(hash);
    }
  });

  it("pins the script and stylesheet in the page, so a swapped bundle is refused", () => {
    const shell = readFileSync(new URL("public/index.html", root), "utf8");
    const script = shell.match(/src="\/assets\/(app-[A-Z0-9]+\.js)" integrity="([^"]+)"/i);
    const style = shell.match(/href="\/assets\/(app-[A-Z0-9]+\.css)" integrity="([^"]+)"/i);
    expect(script, "the shell must pin its entry script").not.toBeNull();
    expect(style, "the shell must pin its stylesheet").not.toBeNull();
    expect(digest(readFileSync(new URL(`public/assets/${script![1]}`, root)))).toBe(script![2]);
    expect(digest(readFileSync(new URL(`public/assets/${style![1]}`, root)))).toBe(style![2]);
  });

  it("keeps the first load small, and the cryptography out of it", () => {
    // A budget, not a measurement: the shell is what a visitor waits for before anything
    // appears, and libsodium is a megabyte that they do not need until they sign in.
    const listed = readFileSync(new URL("public/BUILD.txt", root), "utf8").trim().split("\n");
    const files = listed.map((line) => line.split("  ")[1]!);
    const entry = files.find((file) => /^assets\/app-[A-Z0-9]+\.js$/i.test(file))!;
    const entryBytes = readFileSync(new URL(`public/${entry}`, root));
    expect(entryBytes.length, `${entry} is the first-load budget`).toBeLessThan(150 * 1024);

    // The library itself — the megabyte of WebAssembly — must be in a lazily imported
    // chunk, not in the entry. (Call sites like `s.crypto_pwhash(...)` stay in the entry;
    // what must not be there is the payload.)
    const chunks = files.filter((file) => /^assets\/chunk-/.test(file));
    const heaviest = Math.max(
      ...chunks.map((file) => readFileSync(new URL(`public/${file}`, root)).length),
    );
    expect(heaviest, "the crypto chunk").toBeGreaterThan(500 * 1024);
    expect(entryBytes.length).toBeLessThan(heaviest / 5);

    const shellBytes = readFileSync(new URL("public/index.html", root));
    expect(shellBytes.length).toBeLessThan(4 * 1024);
    const css = files.find((file) => file.endsWith(".css"))!;
    expect(readFileSync(new URL(`public/${css}`, root)).length).toBeLessThan(48 * 1024);

    // Everything worth compressing is pre-compressed, so the server spends no CPU per
    // request. (Below a kilobyte, compression costs more headers than it saves bytes.)
    for (const file of files.filter((name) => /\.(js|css)$/.test(name))) {
      const size = readFileSync(new URL(`public/${file}`, root)).length;
      if (size < 1024) continue;
      expect(existsSync(new URL(`public/${file}.br`, root)), `${file}.br`).toBe(true);
    }
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
    // Point 98: a file long enough that nobody reads it end to end.
    const long = `${"const a = 1;\n".repeat(701)}`;
    expect((lintFile(long, "src/server/routes/huge.ts") as Array<{ name: string }>)[0]?.name).toBe(
      "giant-file",
    );
    expect(lintFile(long, "src/shared/crypto/bip39-wordlist.ts")).toEqual([]);
    expect(lintFile("// audit:allow reviewed\nconst v = body as any;\n", file)).toEqual([]);
    expect(lintFile("// audit:allow reviewed\n\nconst v = body as any;\n", file)).toHaveLength(1);
  });

  it("does not fire on a comment that describes the rule", () => {
    // The codebase explains its own invariants in prose; a linter that cannot tell prose
    // from code makes people delete the prose.
    expect(lintFile("// never assign innerHTML from user content\nconst a = 1;\n", "src/client/x.ts")).toEqual([]);
  });
});

/**
 * Point 99: the cost audit. The claim is that a core deployment needs nothing that sends an
 * invoice, and the point of running the auditor here is that the claim is re-checked on
 * every commit rather than on the day somebody wonders.
 */
describe("cost audit", () => {
  it("reports zero mandatory external services for this tree", () => {
    const output = execFileSync(process.execPath, ["scripts/audit.mjs", "cost"], {
      cwd: new URL("..", import.meta.url),
      encoding: "utf8",
    });
    for (const line of [
      "MANDATORY EXTERNAL SERVICES: 0",
      "MANDATORY PAID APIS: 0",
      "MANDATORY API KEYS: 0",
      "MANDATORY CLOUD SERVICES: 0",
      "MANDATORY THIRD-PARTY TRACKERS: 0",
      "MANDATORY EXTERNAL DATABASES: 0",
      "MANDATORY EXTERNAL STORAGE: 0",
    ]) {
      expect(output).toContain(line);
    }
  });

  it("is part of `npm run audit`, so nobody has to remember to run it", () => {
    const scripts = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).scripts;
    expect(scripts["audit:cost"]).toBe("node scripts/audit.mjs cost");
    expect(scripts.audit).toContain("audit:cost");
  });
});
