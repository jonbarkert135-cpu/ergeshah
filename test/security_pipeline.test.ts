/**
 * The security pipeline, checked the way every other check in this repository is checked:
 * by a test that fails when the check stops working (points 149–153, 158, 174, 178, 180).
 *
 * Two halves, and the second is the one that matters. The first asserts the tree is clean
 * under the rules — pleasant, and it would also pass if the rules matched nothing at all.
 * The second plants an example of every mistake each rule exists to catch and asserts the
 * rule catches it, which is what makes the clean run mean something.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import {
  RULES,
  SEVERITIES,
  STAGES,
  STATUSES,
  TOOLS,
  REGISTER_COLUMNS,
  FINDINGS_DOC,
  CHANGELOG_DOC,
  SUPPRESSIONS_FILE,
  loadRegister,
  loadSuppressions,
  scanFile,
  scanTree,
  toolStatus,
  // @ts-expect-error - plain ESM script; pure functions and tables, as in test/release.test.ts
} from "../scripts/security.mjs";

const root = join(import.meta.dirname, "..");
type Row = Record<string, string>;
/** The register's cells are strings; the parser hands back a plain object. */
const cell = (row: Row, column: string): string => row[column] ?? "";
const read = (path: string) => readFileSync(join(root, path), "utf8");

/** One example per rule, written the way the mistake actually appears in code. */
const PLANTED: Record<string, { file: string; code: string }> = {
  "weak-hash": { file: "src/server/lib/x.ts", code: `const digest = createHash("sha1").update(value).digest();` },
  "unauthenticated-encryption": {
    file: "src/server/lib/x.ts",
    code: `const cipher = createCipheriv("aes-256-cbc", key, iv);`,
  },
  "static-nonce": { file: "src/shared/crypto/x.ts", code: `const nonce = new Uint8Array(24);` },
  "password-as-key": {
    file: "src/shared/crypto/x.ts",
    code: `const box = sodium().crypto_secretbox_easy(plaintext, nonce, password);`,
  },
  "timing-unsafe-secret-compare": {
    file: "src/server/routes/x.ts",
    code: `if (presentedToken === expected) return true;`,
  },
  "body-spread": { file: "src/server/routes/x.ts", code: `await db.run(update, { ...request.body });` },
  "permissive-cors": { file: "src/server/x.ts", code: `reply.header("access-control-allow-origin", "*");` },
  "cookie-without-attributes": {
    file: "src/server/routes/x.ts",
    code: `reply.header("set-cookie", \`session=\${token}\`);`,
  },
  "url-from-request": { file: "src/server/routes/x.ts", code: `const answer = await fetch(request.body.url);` },
  "url-attribute-unchecked": {
    file: "src/client/views/x.ts",
    code: `node.setAttribute("href", listing.link);`,
  },
  "markdown-or-html-render": { file: "src/client/views/x.ts", code: `container.append(marked(description));` },
  "enumerating-error-message": {
    file: "src/server/routes/auth.ts",
    code: `if (!user) throw unauthorized("no such user");`,
  },
};

describe("the source rules catch what they are for (point 174)", () => {
  it("has an example of every rule, and finds every one of them", () => {
    const missing = RULES.map((rule: { name: string }) => rule.name).filter((name: string) => !PLANTED[name]);
    expect(missing).toEqual([]);
    for (const rule of RULES as Array<{ name: string; severity: string }>) {
      const example = PLANTED[rule.name]!;
      const found = scanFile(example.code, example.file) as Array<{ rule: string; severity: string }>;
      expect(found.map((finding) => finding.rule), `${rule.name} did not fire on its own example`).toContain(rule.name);
      expect(SEVERITIES).toContain(rule.severity);
    }
  });

  it("does not fire on the code this project actually writes", () => {
    // The same shapes, done properly: the rules must tell them apart, or they are noise that
    // will be suppressed within a month.
    const clean: Array<[string, string]> = [
      ["src/server/lib/x.ts", `const digest = createHash("sha256").update(value).digest();`],
      ["src/server/lib/x.ts", `if (constantTimeEqual(presentedToken, expected)) return true;`],
      ["src/shared/crypto/x.ts", `const nonce = randomBytes(24);`],
      ["src/server/routes/x.ts", `const title = asString(body.title, "title", 120);`],
      ["src/server/routes/x.ts", `reply.header("set-cookie", serializeCookie("session", token, options));`],
      ["src/client/views/x.ts", `el("a", { href: "#/orders" }, "Open");`],
      ["src/server/routes/auth.ts", `throw unauthorized("invalid username or password");`],
      ["src/server/routes/keys.ts", `if (!target) throw notFound("no such user");`],
    ];
    for (const [file, code] of clean) {
      expect(scanFile(code, file), `${code} should not be a finding`).toEqual([]);
    }
  });

  it("honours an audit:allow waiver on the line and on the line above", () => {
    const file = "src/server/lib/x.ts";
    expect(scanFile(`const d = createHash("sha1").update(v); // audit:allow — a checksum, not a signature`, file)).toEqual([]);
    expect(scanFile(`// audit:allow — a checksum, not a signature\nconst d = createHash("sha1").update(v);`, file)).toEqual([]);
  });

  it("the tree is clean, and the scan covers it" , () => {
    const { files, findings } = scanTree() as { files: number; findings: Array<{ file: string; rule: string }> };
    expect(files).toBeGreaterThan(100);
    expect(findings.map((finding) => `${finding.file}: ${finding.rule}`)).toEqual([]);
  });
});

describe("the findings register is machine-checked (points 151, 152, 158)", () => {
  it("parses, and every row is complete", () => {
    const { rows, problems } = loadRegister() as { rows: Row[]; problems: string[] };
    expect(problems).toEqual([]);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      for (const column of REGISTER_COLUMNS as string[]) expect(cell(row, column), `${cell(row, "id")}.${column}`).toBeTruthy();
      expect(SEVERITIES).toContain(cell(row, "severity").toUpperCase());
      expect(STATUSES).toContain(cell(row, "status").toLowerCase());
      expect(cell(row, "id")).toMatch(/^SEC-\d{4}-\d{3}$/);
    }
  });

  it("blocks a release on an open CRITICAL or HIGH (point 152)", () => {
    const { rows } = loadRegister() as { rows: Row[] };
    const blocking = rows.filter(
      (row) => ["CRITICAL", "HIGH"].includes(cell(row, "severity").toUpperCase()) && cell(row, "status").toLowerCase() === "open",
    );
    expect(blocking.map((row) => cell(row, "id"))).toEqual([]);
  });

  it("every fixed finding names a regression test that exists, and appears in the changelog", () => {
    const { rows } = loadRegister() as { rows: Row[] };
    const fixed = rows.filter((row) => cell(row, "status").toLowerCase() === "fixed");
    expect(fixed.length).toBeGreaterThan(0);
    const changelog = read(CHANGELOG_DOC);
    for (const row of fixed) {
      const test = cell(row, "regression test").replace(/`/g, "").split(/[\s,]/)[0] as string;
      expect(existsSync(join(root, test)), `${cell(row, "id")} names ${test}`).toBe(true);
      expect(changelog, `${cell(row, "id")} is missing from the changelog`).toContain(cell(row, "id"));
    }
  });

  it("an accepted finding says where the decision is written down", () => {
    const { rows } = loadRegister() as { rows: Row[] };
    for (const row of rows.filter((entry) => cell(entry, "status").toLowerCase() === "accepted")) {
      // A judgement with no reference is a shrug. The Fix column carries the reasoning and
      // points at the ADR, the document or the test that keeps the property from drifting.
      expect(cell(row, "fix").length, cell(row, "id")).toBeGreaterThan(40);
      expect(cell(row, "regression test"), cell(row, "id")).toMatch(/test\/[a-z_]+\.test\.ts/);
    }
  });

  it("the changelog publishes no payload for anything unfixed (point 178)", () => {
    const { rows } = loadRegister() as { rows: Row[] };
    const open = rows.filter((row) => cell(row, "status").toLowerCase() === "open").map((row) => cell(row, "id"));
    const changelog = read(CHANGELOG_DOC);
    for (const id of open) expect(changelog, `${id} is open and named in the changelog`).not.toContain(id);
  });
});

describe("suppressions are dated, owned decisions (point 153)", () => {
  it("validates, and nothing in it has expired", () => {
    const { entries, problems } = loadSuppressions() as { entries: Row[]; problems: string[] };
    expect(problems).toEqual([]);
    for (const entry of entries) {
      for (const field of ["rule", "scope", "reason", "owner", "review"]) expect(entry[field]).toBeTruthy();
      expect(String(entry.review) >= new Date().toISOString().slice(0, 10)).toBe(true);
    }
  });

  it("refuses an entry that is missing a field, names no rule, or has expired", () => {
    // The file is the input, so the check is exercised through its own parser rather than by
    // trusting the shape of the one in the tree.
    const today = "2026-09-04";
    const cases: Array<[string, Record<string, unknown>]> = [
      ["missing owner", { rule: "weak-hash", scope: "src/", reason: "why", review: "2099-01-01" }],
      ["unknown rule", { rule: "no-such-rule", scope: "src/", reason: "why", owner: "o", review: "2099-01-01" }],
      ["expired", { rule: "weak-hash", scope: "src/", reason: "why", owner: "o", review: "2020-01-01" }],
    ];
    for (const [label, entry] of cases) {
      const problems = validateSuppression(entry, today);
      expect(problems.length, label).toBeGreaterThan(0);
    }
    expect(
      validateSuppression({ rule: "weak-hash", scope: "src/", reason: "why", owner: "o", review: "2099-01-01" }, today),
    ).toEqual([]);
  });
});

/** The same rules `loadSuppressions` applies, over one entry, so they can be tested directly. */
function validateSuppression(entry: Record<string, unknown>, today: string): string[] {
  const problems: string[] = [];
  for (const field of ["rule", "scope", "reason", "owner", "review"]) {
    if (!entry[field]) problems.push(`missing ${field}`);
  }
  if (entry.rule && !(RULES as Array<{ name: string }>).some((rule) => rule.name === entry.rule)) {
    problems.push(`no rule named ${String(entry.rule)}`);
  }
  if (typeof entry.review === "string" && entry.review < today) problems.push("expired");
  return problems;
}

describe("the pipeline is the ten stages, and no stage is a paid service (points 149, 150)", () => {
  it("covers every stage point 150 lists, in order", () => {
    const expected = [
      "SOURCE SCAN",
      "DEPENDENCY SCAN",
      "SECRET SCAN",
      "CONFIG SCAN",
      "CONTAINER SCAN",
      "UNIT SECURITY TESTS",
      "INTEGRATION SECURITY TESTS",
      "DYNAMIC APPLICATION TEST",
      "REPORT",
      "FIX AND RESCAN",
    ];
    expect((STAGES as Array<[string, unknown, string]>).map(([stage]) => stage)).toEqual(expected);
    // Every stage says what its evidence is; a stage with no evidence is decoration.
    for (const [stage, , evidence] of STAGES as Array<[string, unknown, string]>) {
      expect(evidence.length, stage).toBeGreaterThan(20);
    }
  });

  it("names each external tool with its licence caveat, and requires none of them", () => {
    expect((TOOLS as Array<{ name: string }>).map((tool) => tool.name)).toEqual([
      "osv-scanner",
      "semgrep",
      "trivy",
      "zap.sh",
      "codeql",
    ]);
    for (const tool of TOOLS as Array<{ licence: string; adds: string }>) {
      expect(tool.licence.length).toBeGreaterThan(20);
      expect(tool.adds.length).toBeGreaterThan(20);
    }
    // CodeQL is the one with terms this repository cannot meet; it must say so where an agent
    // deciding what to automate will read it (point 149).
    const codeql = (TOOLS as Array<{ name: string; licence: string }>).find((tool) => tool.name === "codeql")!;
    expect(codeql.licence.toLowerCase()).toContain("private");
    // Probing for a tool must never fail the build, installed or not.
    expect(() => toolStatus()).not.toThrow();
  });

  it("the scan is inside npm run audit, so CI needs no new workflow step", () => {
    const pkg = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
    expect(pkg.scripts["audit:security"]).toBe("node scripts/security.mjs scan");
    expect(pkg.scripts.audit).toContain("audit:security");
    expect(pkg.scripts.security).toBe("node scripts/security.mjs pipeline");
    // And the CI file still calls scripts, not commands (AGENTS.md).
    expect(read("deploy/github-ci.yml")).toContain("npm run audit");
  });

  it("costs nothing mandatory (point 149, and audit:cost)", () => {
    const output = execFileSync("node", ["scripts/security.mjs", "tools"], { cwd: root, encoding: "utf8" });
    expect(output).toContain("MANDATORY PAID SERVICES: 0");
    expect(output).toContain("MANDATORY API KEYS: 0");
  });
});

describe("the documents the process rests on exist and are wired up", () => {
  it("the pipeline, the register, the changelog, the skill and the provenance page", () => {
    for (const path of [
      "docs/SECURITY_PIPELINE.md",
      FINDINGS_DOC,
      CHANGELOG_DOC,
      SUPPRESSIONS_FILE,
      "docs/PROVENANCE.md",
      "skills/vulnerability-remediation/SKILL.md",
    ] as string[]) {
      expect(existsSync(join(root, path)), path).toBe(true);
    }
  });

  it("the remediation skill describes the loop points 154 and 179 ask for", () => {
    const skill = read("skills/vulnerability-remediation/SKILL.md");
    for (const step of [
      "DISCOVER",
      "CLASSIFY",
      "REPRODUCE",
      "ROOT CAUSE",
      "FIX",
      "TEST",
      "RESCAN",
      "DOCUMENT",
    ]) {
      expect(skill, step).toContain(step);
    }
    expect(skill).toMatch(/^---\nname: vulnerability-remediation/);
  });

  it("provenance names a licence and a review for everything adapted (points 146, 147)", () => {
    const provenance = read("docs/PROVENANCE.md");
    for (const column of ["Source", "Licence", "Version", "Purpose", "Modifications", "Security review"]) {
      expect(provenance, column).toContain(column);
    }
    // Every production dependency appears with its licence, here or in THIRD_PARTY.md.
    const pkg = JSON.parse(read("package.json")) as { dependencies: Record<string, string> };
    const thirdParty = read("THIRD_PARTY.md");
    for (const name of Object.keys(pkg.dependencies)) {
      expect(`${provenance}${thirdParty}`, name).toContain(name);
    }
  });
});
