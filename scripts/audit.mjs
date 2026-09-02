/**
 * Two audits that cost nothing and catch the two mistakes that would quietly break the
 * project's promises:
 *
 *   node scripts/audit.mjs bundle   — the client the browser gets talks to no one but us
 *   node scripts/audit.mjs secrets  — no key material or credential is committed
 *
 * Both are grep with a threat model attached. They do not replace review; they replace
 * *forgetting*. A line may opt out with an `audit:allow` comment on it, which is
 * deliberately visible in review.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Anything that would make the browser reach a host we do not operate. */
const EXTERNAL = [
  ["remote URL", /\b(?:https?|wss?|ftp):\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi],
  ["protocol-relative URL", /(?:^|[^:a-z0-9/])\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)+\//gi],
  ["source map reference", /sourceMappingURL/g],
  ["telemetry API", /\bnavigator\.sendBeacon\b/g],
  // ADR-0015 promises the one server-side dependency never reaches the browser.
  ["server-only dependency", /openpgp/gi],
];

/** Things that must never be in the repository, and never in what we serve. */
const SECRETS = [
  ["private key block", /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY(?: BLOCK)?-----/g],
  ["AWS access key id", /\bAKIA[0-9A-Z]{16}\b/g],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  [
    "credential literal",
    // keyword may be part of a camelCase name (dbPassword), so no leading word boundary
    /(?:api[_-]?key|secret|token|password|passphrase|credential)s?\s*[:=]\s*["'`]([^"'`\n]{16,})["'`]/gi,
  ],
];

/** Obvious non-secrets: docs, examples, and anything the code reads at runtime. */
const PLACEHOLDER = /example|changeme|placeholder|your[-_ ]|xxx|\.\.\.|\$\{|process\.env|<[a-z]/i;

/**
 * @param {string} text
 * @param {Array<[string, RegExp]>} rules
 * @returns {Array<{rule: string, line: number, match: string}>}
 */
export function scan(text, rules) {
  const found = [];
  for (const [rule, pattern] of rules) {
    for (const m of text.matchAll(new RegExp(pattern.source, pattern.flags))) {
      // The captured value, when a rule has one, is what decides placeholder-ness.
      if (m[1] !== undefined && PLACEHOLDER.test(m[1])) continue;
      const line = text.slice(0, m.index).split("\n").length;
      const source = text.split("\n")[line - 1] ?? "";
      if (source.includes("audit:allow")) continue;
      found.push({ rule, line, match: m[0].slice(0, 120).trim() });
    }
  }
  return found.sort((a, b) => a.line - b.line);
}

export const scanBundle = (text) => scan(text, [...EXTERNAL, ...SECRETS]);

/**
 * Test files use long literal passwords on purpose ("correct horse battery staple"), so
 * the credential-literal heuristic is dropped there. Key material still is not allowed
 * anywhere: a real private key or token in a fixture is a real leak.
 */
export const scanSource = (text, path = "") =>
  scan(text, path.startsWith("test/") ? SECRETS.filter(([r]) => r !== "credential literal") : SECRETS);

function report(findings) {
  for (const { file, rule, line, match } of findings) {
    console.error(`  ${file}:${line}  ${rule}: ${match}`);
  }
  console.error(`\n${findings.length} finding(s). Fix them, or mark the line 'audit:allow' with a reason.`);
  process.exit(1);
}

function bundle() {
  // Audit what production actually serves: minified, no inline source map, no comments.
  execFileSync(process.execPath, [join(root, "scripts/build-client.mjs")], {
    env: { ...process.env, NODE_ENV: "production" },
    stdio: "inherit",
  });
  const files = ["public/app.js", "public/app.css", "public/index.html"];
  const findings = [];
  for (const file of files) {
    const path = join(root, file);
    if (!existsSync(path)) throw new Error(`${file} missing — the build did not produce it`);
    findings.push(...scanBundle(readFileSync(path, "utf8")).map((f) => ({ ...f, file })));
  }
  if (findings.length) report(findings);
  console.log(`bundle audit: ${files.length} files, no external references, no secrets`);
}

function secrets() {
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter(Boolean)
    // Binary and vendored word lists have no credentials and produce noise.
    .filter((f) => !/\.(png|jpg|jpeg|gif|svg|ico|woff2?|pdf|lock)$/i.test(f) && f !== "package-lock.json");
  const findings = [];
  for (const file of tracked) {
    findings.push(...scanSource(readFileSync(join(root, file), "utf8"), file).map((f) => ({ ...f, file })));
  }
  if (findings.length) report(findings);
  console.log(`secret audit: ${tracked.length} tracked files, nothing that looks like a credential`);
}

// Only when run as a command; the tests import the scanners.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  if (mode === "bundle") bundle();
  else if (mode === "secrets") secrets();
  else throw new Error(`usage: node scripts/audit.mjs bundle|secrets (got '${mode ?? ""}')`);
}
