/**
 * Lint: the rules that are specific to *this* project.
 *
 * There is deliberately no ESLint here. A generic linter would bring roughly a hundred
 * transitive packages into the build in exchange for style opinions, which point 33 of the
 * brief tells us not to do, and its default rule sets do not know a single thing that
 * matters in this codebase: that the client may never build markup from a string, that
 * randomness must come from the CSPRNG, that the environment is read in exactly one file.
 * `tsc --noEmit` already catches everything a type-aware linter would catch. What is left
 * is below — each rule is a mistake that would break a promise made in docs/THREAT_MODEL.md
 * or docs/PRIVACY.md, and each can be waived on a line with an `audit:allow` comment, which
 * is visible in review (on the line itself, or in a comment on the line above it, where a
 * reason usually fits).
 *
 *   node scripts/lint.mjs
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * @typedef {{name: string, pattern: RegExp, message: string, files?: RegExp}} Rule
 * @type {Rule[]}
 */
const RULES = [
  {
    name: "html-from-string",
    pattern: /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write\(|dangerouslySetInnerHTML/,
    message:
      "build DOM with el() from src/client/ui.ts; markup from a string is how user content becomes script",
  },
  {
    name: "dynamic-code",
    pattern: /\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`]/,
    message: "no dynamic code evaluation; the CSP forbids it at runtime and so do we at build time",
  },
  {
    name: "weak-random",
    pattern: /\bMath\.random\s*\(/,
    message: "use crypto.getRandomValues / randomToken; Math.random is predictable",
  },
  {
    name: "environment-outside-config",
    pattern: /\bprocess\.env\b/,
    files: /^src\/(?!server\/config\.ts$)/,
    message: "read configuration in src/server/config.ts only, so the whole surface is one file",
  },
  {
    name: "console-in-server",
    pattern: /\bconsole\.(log|info|debug|warn)\s*\(/,
    files: /^src\/server\/(?!db\/cli\.ts$)/,
    message: "server output goes through the structured stderr line in app.ts; nothing else logs",
  },
  {
    name: "sql-interpolation",
    pattern: /`[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{/is,
    message: "parameterise queries; a template literal in SQL is an injection waiting for input",
  },
  {
    name: "silenced-type-error",
    pattern: /@ts-ignore/,
    message: "use @ts-expect-error with a reason, so the suppression fails when it stops being needed",
  },
  {
    name: "inline-style",
    pattern: /\bstyle:\s*["'`]/,
    files: /^src\/client\//,
    message:
      "style-src 'self' has no 'unsafe-inline', so the browser drops inline styles: use a class",
  },
  {
    name: "browser-prompt",
    pattern: /\bwindow\.(?:prompt|confirm|alert)\s*\(/,
    files: /^src\/client\//,
    message:
      "prompt/confirm/alert have no label, no hint and no styling: use formDialog() or confirmDialog() from ui.ts",
  },
  {
    name: "raw-table",
    pattern: /\bel\(\s*"(?:table|tr|th|td)"/,
    files: /^src\/client\/views\//,
    message: "build tables with table() from ui.ts, which adds thead/scope and stacks on phones",
  },
  {
    name: "focused-test",
    pattern: /\b(?:describe|it|test)\.only\s*\(/,
    files: /^test\//,
    message: ".only silently disables the rest of the suite, and CI would still be green",
  },
  {
    name: "unsafe-any",
    pattern: /:\s*any\b|\bas\s+any\b/,
    message: "`any` at a trust boundary is an unvalidated input; type it or validate it",
  },
];

/**
 * Whitespace hygiene, so that no formatter dependency is needed either. Line length is
 * deliberately not a rule: it is taste, it would rewrite hundreds of lines of view code for
 * nothing, and a diff full of reflowed lines is a diff nobody reviews properly.
 */
function formatting(text, file) {
  const findings = [];
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    if (line.includes("audit:allow") || (lines[index - 1] ?? "").includes("audit:allow")) return;
    if (/\s$/.test(line)) findings.push({ file, line: index + 1, name: "trailing-whitespace", match: "" });
    if (line.includes("\t")) findings.push({ file, line: index + 1, name: "tab", match: "" });
    if (line.includes("\r")) findings.push({ file, line: index + 1, name: "crlf", match: "" });
  });
  if (text.length && !text.endsWith("\n")) {
    findings.push({ file, line: lines.length, name: "no-final-newline", match: "" });
  }
  return findings;
}

/**
 * Comments describe the rules ("never innerHTML"), so a naive grep flags the very lines that
 * document the invariant. Strip comments and string-free code is what remains to be judged.
 */
function withoutComments(text) {
  return text
    .split("\n")
    .map((line) => (/^\s*(\/\/|\*|\/\*)/.test(line) ? "" : line.replace(/\s\/\/.*$/, "")))
    .join("\n");
}

export function lintFile(text, file) {
  const findings = formatting(text, file);
  const source = text.split("\n");
  const code = withoutComments(text);
  const lines = code.split("\n");
  /** A waiver may sit on the line, or in the comment above it, where the reason fits. */
  const waived = (index) =>
    (source[index] ?? "").includes("audit:allow") || (source[index - 1] ?? "").includes("audit:allow");
  for (const rule of RULES) {
    if (rule.files && !rule.files.test(file)) continue;
    lines.forEach((line, index) => {
      if (waived(index)) return;
      const match = line.match(new RegExp(rule.pattern.source, rule.pattern.flags.replace("g", "")));
      if (match) {
        findings.push({ file, line: index + 1, name: rule.name, match: match[0].trim().slice(0, 80) });
      }
    });
  }
  return findings.sort((a, b) => a.line - b.line);
}

/** This file writes the rules down, so a naive scan of it matches every one of them. */
const SELF = "scripts/lint.mjs";

function main() {
  // Tracked *and* new-but-not-yet-added files: a file that is only linted once it is
  // staged is a file whose first CI run fails. (That happened. Hence this comment.)
  const list = (args) =>
    execFileSync("git", args, { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  const files = [
    ...list(["ls-files", "-z", "src", "test", "scripts"]),
    ...list(["ls-files", "-z", "--others", "--exclude-standard", "src", "test", "scripts"]),
  ]
    .filter((f) => /\.(ts|mjs|js)$/.test(f))
    .sort();

  const findings = [];
  for (const file of files) {
    const text = readFileSync(join(root, file), "utf8");
    // The rule table is not code that runs; only whitespace hygiene applies to it.
    findings.push(...(file === SELF ? formatting(text, file) : lintFile(text, file)));
  }

  if (findings.length) {
    for (const f of findings) {
      const rule = RULES.find((r) => r.name === f.name);
      console.error(`  ${f.file}:${f.line}  ${f.name}${f.match ? `: ${f.match}` : ""}`);
      if (rule) console.error(`      ${rule.message}`);
    }
    console.error(`\n${findings.length} finding(s). Fix them, or mark the line 'audit:allow' with a reason.`);
    process.exit(1);
  }
  console.log(`lint: ${files.length} files, ${RULES.length} project rules, clean`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
