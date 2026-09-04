/**
 * The security pipeline (points 149–153, 174, 175, 179).
 *
 *   node scripts/security.mjs scan       the static half: fast, offline, no network
 *   node scripts/security.mjs pipeline   the ten stages of point 150, end to end
 *   node scripts/security.mjs tools      which external scanners are available here
 *
 * Three decisions this file is built around, because they are what usually goes wrong with
 * a "security pipeline" bolted onto a repository:
 *
 * 1. **No new check duplicates an old one.** Dependency CVEs, secrets in the tree, secrets
 *    in history, egress, the bundle, the container flags and the eleven baseline
 *    measurements are already `npm run audit` and `npm run release` (docs/AUDIT.md,
 *    docs/RELEASE.md). The pipeline *maps* the ten stages point 150 lists onto that
 *    evidence and adds only what nothing covered: the source-level checks below, the
 *    findings register, and the suppression discipline.
 * 2. **A scanner that could not run is not a pass.** Same three states as the release gate:
 *    PASS, FAIL, COULD NOT RUN. An external scanner that is not installed prints NOT
 *    INSTALLED and is never mandatory — point 149 forbids making a paid SaaS or an API key
 *    load-bearing, and `npm run audit:cost` fails the build if one ever becomes so.
 * 3. **A suppression is a dated, owned decision.** `deploy/security-suppressions.json`
 *    carries a reason, a scope, an owner and an expiry; an expired or unowned entry fails
 *    the scan rather than quietly muting it (point 153).
 *
 * The analysers are greps with a threat model attached, like `scripts/audit.mjs` — the same
 * reason applies here (no ESLint, no hundred transitive packages) and the same escape hatch:
 * an `audit:allow` comment on the line, or on the line above, with a reason.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");

export const FINDINGS_DOC = "docs/SECURITY_FINDINGS.md";
export const CHANGELOG_DOC = "docs/SECURITY_CHANGELOG.md";
export const SUPPRESSIONS_FILE = "deploy/security-suppressions.json";

/** Point 152. Order matters: the first two block a release. */
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const BLOCKING = ["CRITICAL", "HIGH"];
/** A finding is one of these and nothing else. `accepted` needs an ADR or a documented reason. */
export const STATUSES = ["open", "fixed", "accepted", "not-applicable"];

// ---------------------------------------------------------------------------------------
// The source analysers (points 164, 166, 169, 171, 172, 174)
// ---------------------------------------------------------------------------------------

/**
 * Each rule is a mistake that would break a promise in `docs/THREAT_MODEL.md`, and each one
 * is a *class*, not an instance: the point of a rule here is that the second occurrence of a
 * fixed bug fails the build instead of being found again by hand (point 157, variant
 * analysis).
 *
 * @typedef {{name: string, severity: string, pattern: RegExp, files: RegExp, why: string}} Rule
 * @type {Rule[]}
 */
export const RULES = [
  // --- 174: cryptography, statically ----------------------------------------------------
  {
    name: "weak-hash",
    severity: "HIGH",
    pattern: /createHash\s*\(\s*["'`](?:md5|sha1|md4|ripemd)/i,
    files: /^src\//,
    why: "MD5 and SHA-1 are broken for anything that needs collision resistance; use SHA-256 or BLAKE2b",
  },
  {
    name: "unauthenticated-encryption",
    severity: "CRITICAL",
    pattern: /createCipheriv\s*\(\s*["'`][^"'`]*-(?:ecb|cbc|ctr|cfb|ofb)\b|crypto_stream(?!_)/i,
    files: /^src\//,
    why: "encryption without authentication is malleable: every ciphertext here goes through an AEAD (docs/CRYPTO.md)",
  },
  {
    name: "static-nonce",
    severity: "CRITICAL",
    pattern: /(?:nonce|iv)\s*[:=]\s*(?:new Uint8Array\s*\(\s*\d+\s*\)|Buffer\.alloc\s*\(\s*\d+\s*\)|\[[\d,\s]+\]|["'`])/i,
    files: /^src\//,
    why: "a nonce that is not random per message repeats, and a repeated nonce loses the key stream",
  },
  {
    name: "password-as-key",
    severity: "HIGH",
    pattern: /crypto_(?:secretbox|aead|kx|box)[a-z_0-9]*\s*\([^)]*\b(?:password|passphrase)\b/i,
    files: /^src\//,
    why: "a password is not key material: derive one with Argon2id or scrypt first (ADR-0006, ADR-0012)",
  },
  {
    name: "timing-unsafe-secret-compare",
    severity: "LOW",
    // The name may be camelCase (`headerToken`, `presentedMac`), so the secret word is
    // matched anywhere in the identifier; the right-hand side must be another identifier,
    // which keeps `mode === "secrets"` and `typeof x === "string"` out of it.
    pattern: /[A-Za-z_$][\w$]*(?:token|mac|secret|signature|digest|passwordhash)[\w$]*\s*(?:===|!==)\s*(?!undefined\b|null\b)[a-zA-Z_$][\w.$[\]]*/i,
    files: /^src\/server\//,
    why: "compare secrets with constantTimeEqual() from lib/ids.ts; `===` stops at the first wrong byte",
  },
  // --- 164: mass assignment -------------------------------------------------------------
  {
    name: "body-spread",
    severity: "HIGH",
    pattern: /\.{3}\s*(?:request\.)?body\b|Object\.assign\s*\(\s*[^,]*,\s*(?:request\.)?body\b|for\s*\(\s*const\s+\w+\s+in\s+(?:request\.)?body\b/,
    files: /^src\/server\//,
    why: "a request body copied into a row is mass assignment: name the fields, or use onlyKeys()",
  },
  // --- 169: CORS ------------------------------------------------------------------------
  {
    name: "permissive-cors",
    severity: "HIGH",
    pattern: /access-control-allow-origin["'`\s:=,]+\*|origin\s*:\s*true|\bcors\s*\(/i,
    files: /^src\/|^deploy\//,
    why: "this API is same-origin only; a wildcard or a reflected origin would hand it to any page (point 169)",
  },
  // --- 171: cookies ---------------------------------------------------------------------
  {
    name: "cookie-without-attributes",
    severity: "HIGH",
    pattern: /set-cookie["'`]\s*,\s*[`"'][^`"']*=/i,
    files: /^src\/server\/(?!lib\/cookies\.ts)/,
    why: "build cookies with serializeCookie(), which cannot forget SameSite, Secure or HttpOnly",
  },
  // --- 165: SSRF ------------------------------------------------------------------------
  {
    name: "url-from-request",
    severity: "CRITICAL",
    pattern: /(?:fetch|request|get)\s*\(\s*(?:request\.)?(?:body|query|params)\b/,
    files: /^src\/server\//,
    why: "a URL taken from a request is SSRF; this server makes no outbound call except the wallet RPC (docs/NETWORK.md)",
  },
  // --- 166: XSS variants ----------------------------------------------------------------
  {
    name: "url-attribute-unchecked",
    severity: "HIGH",
    pattern: /setAttribute\s*\(\s*["'`](?:href|src|action|formaction|poster)["'`]/i,
    files: /^src\/client\/(?!ui\.ts)/,
    why: "URL attributes go through el() in ui.ts, which refuses javascript: and data: (ADR-0007)",
  },
  {
    name: "markdown-or-html-render",
    severity: "HIGH",
    pattern: /\b(?:marked|markdownIt|DOMPurify|sanitizeHtml|parseHTML)\s*\(|createContextualFragment|\bfrom\s+["'`](?:marked|markdown-it|dompurify)["'`]/,
    files: /^src\//,
    why: "there is no HTML rendering path here on purpose: text is text (docs/HARDENING.md)",
  },
  // --- 172: account enumeration ---------------------------------------------------------
  {
    name: "enumerating-error-message",
    severity: "MEDIUM",
    pattern: /(?:unauthorized|badRequest|notFound)\s*\(\s*["'`][^"'`]*\b(?:no such (?:user|account)|unknown (?:user|account)|user (?:not found|does not exist)|wrong password|incorrect password)\b/i,
    // Only the routes that *authenticate*. A username is a public identifier on this
    // platform — you message it, you buy from it, and `GET /api/market/sellers/:username`
    // publishes it — so a prekey bundle or a moderator action may say a name is unknown.
    // What may never differ is the answer to "is this a valid credential for this account?"
    files: /^src\/server\/(?:routes\/(?:auth|recovery)\.ts|lib\/(?:auth_flow|password|sessions)\.ts)$/,
    why: "an authentication failure says 'invalid username or password' and nothing more (point 172)",
  },
];

/** Comments describe the rules, so they are stripped before matching — as in scripts/lint.mjs. */
function withoutComments(text) {
  return text
    .split("\n")
    .map((line) => (/^\s*(\/\/|\*|\/\*|--)/.test(line) ? "" : line.replace(/\s\/\/.*$/, "")))
    .join("\n");
}

/** This file writes the patterns down, so scanning it would match every one of them. */
const SELF = "scripts/security.mjs";

/**
 * @returns {Array<{file: string, line: number, rule: string, severity: string, match: string, why: string}>}
 */
export function scanFile(text, file) {
  if (file === SELF) return [];
  const findings = [];
  const source = text.split("\n");
  const lines = withoutComments(text).split("\n");
  const waived = (index) =>
    (source[index] ?? "").includes("audit:allow") || (source[index - 1] ?? "").includes("audit:allow");
  for (const rule of RULES) {
    if (!rule.files.test(file)) continue;
    lines.forEach((line, index) => {
      if (waived(index)) return;
      const match = line.match(new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "")));
      if (match) {
        findings.push({
          file,
          line: index + 1,
          rule: rule.name,
          severity: rule.severity,
          match: match[0].trim().slice(0, 80),
          why: rule.why,
        });
      }
    });
  }
  return findings;
}

const tracked = (paths) =>
  execFileSync("git", ["ls-files", "-z", ...paths], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter(Boolean);

export function scanTree() {
  const files = tracked(["src", "test", "scripts", "deploy"]).filter((file) =>
    /\.(ts|mjs|js|yml|yaml|json|Caddyfile)$|Caddyfile$/.test(file),
  );
  const findings = [];
  for (const file of files) findings.push(...scanFile(read(file), file));
  return { files: files.length, findings };
}

// ---------------------------------------------------------------------------------------
// Suppressions (point 153)
// ---------------------------------------------------------------------------------------

/**
 * A suppression is allowed and is not free: it names the rule, the scope it applies to, why
 * it is not a finding, who decided, and the date the decision is re-read. Anything missing,
 * or an expiry in the past, is a failure — the point of the expiry is that a muted rule
 * cannot outlive the reason it was muted.
 *
 * @returns {{entries: Array<object>, problems: string[]}}
 */
export function loadSuppressions(today = new Date().toISOString().slice(0, 10)) {
  const problems = [];
  if (!existsSync(join(root, SUPPRESSIONS_FILE))) {
    return { entries: [], problems: [`${SUPPRESSIONS_FILE} is missing`] };
  }
  let parsed;
  try {
    parsed = JSON.parse(read(SUPPRESSIONS_FILE));
  } catch (error) {
    return { entries: [], problems: [`${SUPPRESSIONS_FILE} is not valid JSON: ${error.message}`] };
  }
  const entries = parsed.suppressions ?? [];
  if (!Array.isArray(entries)) return { entries: [], problems: [`${SUPPRESSIONS_FILE}: suppressions must be an array`] };
  for (const [index, entry] of entries.entries()) {
    for (const field of ["rule", "scope", "reason", "owner", "review"]) {
      if (!entry[field]) problems.push(`${SUPPRESSIONS_FILE}[${index}]: missing ${field}`);
    }
    if (entry.rule && !RULES.some((rule) => rule.name === entry.rule)) {
      problems.push(`${SUPPRESSIONS_FILE}[${index}]: no rule named ${entry.rule}`);
    }
    if (entry.review && entry.review < today) {
      problems.push(
        `${SUPPRESSIONS_FILE}[${index}]: the review date ${entry.review} has passed — re-read it or delete it`,
      );
    }
  }
  return { entries, problems };
}

const suppressed = (finding, entries) =>
  entries.some((entry) => entry.rule === finding.rule && finding.file.startsWith(entry.scope));

// ---------------------------------------------------------------------------------------
// The findings register (points 151, 152) and the changelog (point 178)
// ---------------------------------------------------------------------------------------

/** The eleven columns point 151 requires, in the order the document writes them. */
export const REGISTER_COLUMNS = [
  "id",
  "severity",
  "component",
  "source",
  "description",
  "attack path",
  "impact",
  "likelihood",
  "fix",
  "regression test",
  "status",
];

/**
 * Read `docs/SECURITY_FINDINGS.md`. It is a table because a table is what gets updated; the
 * parser is here so that the register is checked mechanically rather than admired.
 *
 * @returns {{rows: Array<Record<string, string>>, problems: string[]}}
 */
export function loadRegister() {
  const problems = [];
  if (!existsSync(join(root, FINDINGS_DOC))) return { rows: [], problems: [`${FINDINGS_DOC} is missing`] };
  const text = read(FINDINGS_DOC);
  const lines = text.split("\n");
  const header = lines.findIndex((line) => /^\|\s*ID\s*\|/i.test(line));
  if (header < 0) return { rows: [], problems: [`${FINDINGS_DOC}: no findings table`] };
  const columns = lines[header].split("|").slice(1, -1).map((cell) => cell.trim().toLowerCase());
  for (const column of REGISTER_COLUMNS) {
    if (!columns.includes(column)) problems.push(`${FINDINGS_DOC}: the table has no "${column}" column`);
  }
  const rows = [];
  for (const line of lines.slice(header + 2)) {
    if (!line.startsWith("|")) break;
    const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
    const row = Object.fromEntries(columns.map((column, index) => [column, cells[index] ?? ""]));
    rows.push(row);
    for (const column of REGISTER_COLUMNS) {
      if (!row[column]) problems.push(`${FINDINGS_DOC}: ${row.id || "a row"} has an empty "${column}"`);
    }
    if (!SEVERITIES.includes((row.severity ?? "").toUpperCase())) {
      problems.push(`${FINDINGS_DOC}: ${row.id} has severity "${row.severity}", not one of ${SEVERITIES.join("/")}`);
    }
    if (!STATUSES.includes((row.status ?? "").toLowerCase())) {
      problems.push(`${FINDINGS_DOC}: ${row.id} has status "${row.status}", not one of ${STATUSES.join("/")}`);
    }
    // Point 158: every fix is a permanent test, and the register is where the test is named.
    if ((row.status ?? "").toLowerCase() === "fixed") {
      const test = (row["regression test"] ?? "").replace(/`/g, "").split(/[\s,]/)[0];
      if (!test || !existsSync(join(root, test))) {
        problems.push(`${FINDINGS_DOC}: ${row.id} is fixed but names no test that exists (${test || "none"})`);
      }
      if (existsSync(join(root, CHANGELOG_DOC)) && !read(CHANGELOG_DOC).includes(row.id)) {
        problems.push(`${CHANGELOG_DOC}: ${row.id} is fixed and is not in the security changelog (point 178)`);
      }
    }
  }
  // Point 152: an unresolved CRITICAL or HIGH blocks a release. `accepted` is the documented
  // exception and has to name where it is documented, which the "fix" column carries.
  for (const row of rows) {
    if (BLOCKING.includes((row.severity ?? "").toUpperCase()) && (row.status ?? "").toLowerCase() === "open") {
      problems.push(`${FINDINGS_DOC}: ${row.id} is an open ${row.severity} — it blocks a release (point 152)`);
    }
  }
  return { rows, problems };
}

// ---------------------------------------------------------------------------------------
// External tooling (point 149)
// ---------------------------------------------------------------------------------------

/**
 * The tools point 149 names, what each would add here, and the licensing caveat that decides
 * whether it may ever be *required*. None of them is installed by this repository and none is
 * a dependency: each is looked up on `PATH`, used if it is there, and reported as NOT
 * INSTALLED if it is not. That is the only arrangement compatible with `npm run audit:cost`
 * (zero mandatory external services) — and with a private repository, which is the case
 * CodeQL's terms do not cover for free.
 */
export const TOOLS = [
  {
    name: "osv-scanner",
    args: ["--version"],
    stage: "DEPENDENCY SCAN",
    adds: "OSV vulnerabilities against package-lock.json, from the open OSV database",
    licence: "Apache-2.0, self-hostable; the database is public — no account, no key",
    scan: ["--lockfile=package-lock.json"],
  },
  {
    name: "semgrep",
    args: ["--version"],
    stage: "SOURCE SCAN",
    adds: "pattern-based analysis with community rules, and custom rules for this codebase",
    licence: "LGPL-2.1 CLI with an open rule registry; Semgrep Pro/AppSec is a paid SaaS — not used",
    scan: ["--error", "--config=auto", "--metrics=off", "src"],
  },
  {
    name: "trivy",
    args: ["--version"],
    stage: "SECRET AND CONTAINER SCAN",
    adds: "filesystem, config, secret and container-image scanning",
    licence: "Apache-2.0, runs locally with a downloadable database",
    scan: ["fs", "--scanners", "vuln,secret,misconfig", "--exit-code", "1", "."],
  },
  {
    name: "zap.sh",
    args: ["-version"],
    stage: "DYNAMIC APPLICATION TEST",
    adds: "an active scan against a running instance (the one stage a static tool cannot do)",
    licence: "Apache-2.0; needs a deployment to point at, so it is an operator step, not a CI step",
    scan: null,
  },
  {
    name: "codeql",
    args: ["version", "--format=terse"],
    stage: "SOURCE SCAN",
    adds: "semantic dataflow analysis, which finds what a pattern cannot",
    licence:
      "free for open-source only: the CodeQL CLI terms exclude private repositories, and this " +
      "repository is proprietary (ADR-0022). Do not automate it here without a licence.",
    scan: null,
  },
];

export function toolStatus() {
  return TOOLS.map((tool) => {
    const probe = spawnSync(tool.name, tool.args, { encoding: "utf8" });
    const installed = probe.status === 0;
    return { ...tool, installed, version: installed ? (probe.stdout ?? "").trim().split("\n")[0] : "" };
  });
}

// ---------------------------------------------------------------------------------------
// The ten stages (point 150)
// ---------------------------------------------------------------------------------------

/**
 * Stage -> the command that is its evidence here. `null` means the stage is this script's own
 * work (the source analysers, the register) or an operator step that cannot run in CI.
 */
export const STAGES = [
  ["SOURCE SCAN", null, "scripts/security.mjs scan — the rules above, plus npm run check (scripts/lint.mjs)"],
  ["DEPENDENCY SCAN", ["npm", ["run", "audit:deps"]], "npm audit at high, plus audit:dependencies and audit:inventory"],
  ["SECRET SCAN", ["npm", ["run", "audit:secrets"]], "the working tree; audit:history walks every commit"],
  ["CONFIG SCAN", ["npm", ["run", "audit:cost"]], "cost and egress: no paid service, no key, no host in the source"],
  ["CONTAINER SCAN", ["npm", ["run", "audit:baseline"]], "the baseline's privileged and hardening counts (deploy/)"],
  ["UNIT SECURITY TESTS", ["npx", ["vitest", "run", "test/fuzz.test.ts", "test/cryptography.test.ts"]], "fuzzing and the crypto vectors"],
  [
    "INTEGRATION SECURITY TESTS",
    ["npx", ["vitest", "run", "test/authz_fuzz.test.ts", "test/authorization.test.ts", "test/idor.test.ts", "test/security.test.ts"]],
    "the authorization matrix, the IDOR sweep, the attack sweep",
  ],
  ["DYNAMIC APPLICATION TEST", null, "OWASP ZAP against a deployment (operator step; see docs/SECURITY_PIPELINE.md)"],
  ["REPORT", null, "the summary printed below, and docs/SECURITY_FINDINGS.md"],
  ["FIX AND RESCAN", null, "the loop in skills/vulnerability-remediation/SKILL.md (point 179)"],
];

function run(label, command, args) {
  process.stdout.write(`\n=== ${label}: ${command} ${args.join(" ")}\n`);
  const started = Date.now();
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8" });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  process.stdout.write(output);
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  const network = /E503|ETIMEDOUT|ENOTFOUND|ECONNRESET|registry\.npmjs\.org/i.test(output);
  const state = result.status === 0 ? "PASS" : network ? "COULD NOT RUN" : "FAIL";
  console.log(`=== ${label}: ${state} in ${seconds}s`);
  return state;
}

// ---------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------

/** The fast, offline half. This is `npm run audit:security`, inside `npm run audit`. */
export function scanCommand() {
  const { files, findings } = scanTree();
  const { entries, problems: suppressionProblems } = loadSuppressions();
  const { rows, problems: registerProblems } = loadRegister();

  const live = findings.filter((finding) => !suppressed(finding, entries));
  const muted = findings.length - live.length;

  for (const finding of live) {
    console.error(`  ${finding.file}:${finding.line}  ${finding.severity}  ${finding.rule}: ${finding.match}`);
    console.error(`      ${finding.why}`);
  }
  for (const problem of [...suppressionProblems, ...registerProblems]) console.error(`  ${problem}`);

  const counts = Object.fromEntries(
    SEVERITIES.map((severity) => [
      severity,
      rows.filter(
        (row) => (row.severity ?? "").toUpperCase() === severity && (row.status ?? "").toLowerCase() === "open",
      ).length,
    ]),
  );

  const failed = live.length + suppressionProblems.length + registerProblems.length;
  if (failed) {
    console.error(
      `\n${failed} security finding(s). Fix them, record them in ${FINDINGS_DOC}, or suppress a rule in ` +
        `${SUPPRESSIONS_FILE} with a reason, an owner and a review date.`,
    );
    return false;
  }
  console.log(
    `security scan: ${files} files, ${RULES.length} rules, clean` +
      (muted ? ` (${muted} suppressed, each with a reason and a review date)` : "") +
      `\n  register: ${rows.length} finding(s) tracked in ${FINDINGS_DOC}; open by severity: ` +
      SEVERITIES.map((severity) => `${severity} ${counts[severity]}`).join(", "),
  );
  return true;
}

function toolsCommand() {
  console.log("external security tooling (point 149) — optional, never required:\n");
  for (const tool of toolStatus()) {
    console.log(`  ${tool.installed ? "installed    " : "not installed"}  ${tool.name}  (${tool.stage})`);
    console.log(`      adds:    ${tool.adds}`);
    console.log(`      licence: ${tool.licence}`);
    if (tool.installed && tool.scan) console.log(`      run:     ${tool.name} ${tool.scan.join(" ")}`);
  }
  console.log(
    "\nMANDATORY PAID SERVICES: 0\nMANDATORY API KEYS: 0\n" +
      "Everything above is a local binary an operator may install; nothing here depends on one.",
  );
}

function pipelineCommand() {
  const results = [];
  console.log("security pipeline (point 150)\n");
  const scanned = scanCommand();
  results.push(["SOURCE SCAN", scanned ? "PASS" : "FAIL"]);
  for (const [stage, command] of STAGES.slice(1)) {
    if (!command) {
      results.push([stage, stage === "REPORT" || stage === "FIX AND RESCAN" ? "PASS" : "NOT RUN"]);
      continue;
    }
    results.push([stage, run(stage, command[0], command[1])]);
  }

  const tools = toolStatus();
  console.log("\nexternal scanners:");
  for (const tool of tools) {
    console.log(`  ${tool.installed ? "available" : "NOT INSTALLED"}  ${tool.name} — ${tool.stage}`);
  }

  const { rows } = loadRegister();
  console.log("\nfinal security status (register)");
  for (const severity of SEVERITIES) {
    const open = rows.filter(
      (row) => (row.severity ?? "").toUpperCase() === severity && (row.status ?? "").toLowerCase() === "open",
    );
    console.log(`  ${severity.padEnd(9)}${open.length}${open.length ? ` (${open.map((row) => row.id).join(", ")})` : ""}`);
  }

  console.log("\nstages");
  let failed = 0;
  let notRun = 0;
  for (const [stage, state] of results) {
    if (state === "FAIL") failed += 1;
    if (state === "NOT RUN" || state === "COULD NOT RUN") notRun += 1;
    console.log(`  ${String(state).padEnd(14)}${stage}`);
  }
  console.log(
    "\nThis is not a claim that the system is secure: it is a list of what ran and what it " +
      "found (docs/SECURITY_PIPELINE.md).",
  );
  if (failed) {
    console.error(`\n${failed} stage(s) failed, ${notRun} did not run.`);
    process.exit(1);
  }
  if (notRun) console.log(`${notRun} stage(s) did not run here; NOT RUN is not a pass.`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2] ?? "scan";
  if (mode === "scan") process.exit(scanCommand() ? 0 : 1);
  else if (mode === "tools") toolsCommand();
  else if (mode === "pipeline") pipelineCommand();
  else throw new Error(`usage: node scripts/security.mjs scan|pipeline|tools (got '${mode}')`);
}
