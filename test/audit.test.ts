import { describe, expect, it } from "vitest";
// @ts-expect-error - plain ESM script, no types needed for two pure functions
import { scanBundle, scanSource } from "../scripts/audit.mjs";

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
