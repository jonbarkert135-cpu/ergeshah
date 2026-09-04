/**
 * `npm run verify:clean-clone` — the clean-clone gate (point 109).
 *
 * Every other check in this repository runs in a working directory that has been lived in:
 * a `node_modules` installed weeks ago, a built `public/`, a file somebody forgot to commit.
 * That directory is not what a deployment gets, and the difference is a real class of bug —
 * an untracked file the audit never saw, a dependency installed by hand, a build that only
 * works because an old artifact is still lying around. This script makes the official answer
 * come from somewhere else:
 *
 *   an empty directory -> git clone -> npm ci -> build -> tests -> audits
 *
 * Nothing from this tree is reused. The clone is full (not shallow), because `audit:history`
 * walks every commit; installation is `npm ci` against the committed lockfile, because that
 * is what CI and the Dockerfile do; and the temporary directory is removed unless `--keep`
 * says otherwise.
 *
 *   node scripts/clean-clone.mjs                 clone the origin remote of this repository
 *   node scripts/clean-clone.mjs <url-or-path>   clone something else (a fork, a mirror, HEAD)
 *   node scripts/clean-clone.mjs --keep          leave the directory for inspection
 *
 * The remote is read from git rather than written here: a host name in the source is
 * something `audit:cost` and `audit:egress` refuse, and rightly.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The pipeline point 109 asks for. Unit, integration and security tests are one command
 * here — `vitest` runs every suite under `test/` and they are not separated by kind (docs/TESTING.md
 * groups them by what they prove) — and "production checks" is `npm run audit`, the ten
 * audits CI runs.
 */
export const STEPS = [
  ["npm ci", ["npm", ["ci", "--no-audit", "--no-fund"]]],
  ["lint and types", ["npm", ["run", "check"]]],
  ["build", ["npm", ["run", "build"]]],
  ["tests", ["npm", ["test"]]],
  ["audits", ["npm", ["run", "audit"]]],
];

/** A registry that answers 503 is a network fault, not a finding. Say which one it was. */
function networkFailure(output) {
  return /E503|ETIMEDOUT|ENOTFOUND|ECONNRESET|network|registry\.npmjs\.org/i.test(output);
}

function main() {
  const args = process.argv.slice(2);
  const keep = args.includes("--keep");
  const source =
    args.find((arg) => !arg.startsWith("--")) ??
    execFileSync("git", ["remote", "get-url", "origin"], { cwd: root, encoding: "utf8" }).trim();
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root, encoding: "utf8" }).trim();

  const directory = mkdtempSync(join(tmpdir(), "symvolon-clean-clone-"));
  console.log(`clean-clone gate (point 109)`);
  console.log(`  source:    ${source}`);
  console.log(`  local HEAD: ${commit} (${branch})`);
  console.log(`  directory: ${directory}\n`);

  const results = [];
  let failed = null;

  const started = Date.now();
  const clone = spawnSync("git", ["clone", "--quiet", source, directory], { encoding: "utf8" });
  const cloneSeconds = ((Date.now() - started) / 1000).toFixed(1);
  if (clone.status !== 0) {
    console.error(`  FAILED  git clone in ${cloneSeconds}s`);
    console.error((clone.stderr ?? "").trim().split("\n").slice(-10).join("\n"));
    if (!keep) rmSync(directory, { recursive: true, force: true });
    console.error(
      networkFailure(`${clone.stderr}`)
        ? "\nCLEAN-CLONE RESULT: NOT VERIFIED — the clone itself failed on the network, which is not a finding about the code."
        : "\nCLEAN-CLONE RESULT: FAILED at git clone.",
    );
    process.exit(1);
  }
  const cloned = execFileSync("git", ["rev-parse", "HEAD"], { cwd: directory, encoding: "utf8" }).trim();
  console.log(`  ok      git clone in ${cloneSeconds}s -> ${cloned}`);
  if (cloned !== commit) {
    console.log(`  note    the clone is at ${cloned}, this tree is at ${commit}: unpushed commits are not verified`);
  }

  for (const [label, [command, commandArgs]] of STEPS) {
    const stepStarted = Date.now();
    const result = spawnSync(command, commandArgs, { cwd: directory, encoding: "utf8" });
    const seconds = ((Date.now() - stepStarted) / 1000).toFixed(1);
    const ok = result.status === 0;
    results.push({ label, ok, seconds });
    console.log(`  ${ok ? "ok    " : "FAILED"}  ${label} in ${seconds}s`);
    if (!ok) {
      const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
      console.error(output.trim().split("\n").slice(-40).join("\n"));
      failed = { label, network: networkFailure(output) };
      break;
    }
  }

  if (keep) console.log(`\n  kept: ${directory}`);
  else rmSync(directory, { recursive: true, force: true });

  console.log("");
  if (failed) {
    console.error(
      `CLEAN-CLONE RESULT: FAILED at ${failed.label}` +
        (failed.network
          ? " — the output looks like a network failure (the registry, not this commit). Re-run before treating it as a finding."
          : "") +
        `\n${results.filter((step) => step.ok).length}/${STEPS.length} steps passed on ${cloned}.`,
    );
    process.exit(1);
  }
  console.log(
    `CLEAN-CLONE RESULT: PASSED — ${STEPS.length} steps on ${cloned}, from an empty directory ` +
      `(${results.map((step) => `${step.label} ${step.seconds}s`).join(", ")}).`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
