/**
 * `npm run release` — the gate a commit passes before it is a production release
 * (points 138, 139, 140).
 *
 * Nothing here is a new check. Everything this project verifies is already a lint rule, a
 * test or an audit; what did not exist was the *gate* — one command that runs them, maps
 * each of the fourteen areas point 140 lists onto the evidence that actually covers it, and
 * compares the deployment's security surface with a recorded baseline so that an expansion
 * is a failure instead of a footnote.
 *
 * Three rules it is built around, because they are the ways a release gate usually lies:
 *
 * 1. **A check that did not run is never green.** A category with no evidence prints NOT RUN
 *    and the command exits non-zero. The clean-clone verification is the usual one: it takes
 *    minutes and a network, so it is opt-in (`--clean-clone`), and until it runs the gate
 *    says the commit is not production-ready.
 * 2. **The report carries real values.** 4 direct dependencies, 65 production packages, 2
 *    published ports — measured from the tree, not copied from a document.
 * 3. **The baseline is a ratchet.** A number that grew, a port that appeared, a header that
 *    disappeared: each is a failure that has to be either fixed or recorded deliberately in
 *    `deploy/security-baseline.json`, in the commit that caused it.
 *
 *   node scripts/release.mjs                  the gate (check, test, audit, baseline, static)
 *   node scripts/release.mjs --clean-clone    the same, plus a full fresh-clone verification
 *   node scripts/release.mjs baseline         only the baseline comparison
 *   node scripts/release.mjs baseline --update  record today's measurements as the baseline
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSource } from "./audit.mjs";
import { egressDestinations } from "./audit-egress.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const BASELINE_FILE = "deploy/security-baseline.json";

const read = (path) => readFileSync(join(root, path), "utf8");
const unique = (values) => [...new Set(values)].sort();

// ---------------------------------------------------------------------------------------
// Measuring the surface (point 139)
// ---------------------------------------------------------------------------------------

/**
 * The deployment file, one entry per *uncommented* service. A commented-out service is an
 * example an operator may enable; it is not this deployment's surface, and counting it would
 * make the baseline describe a system nobody is running.
 */
function services() {
  const lines = read("deploy/docker-compose.yml").split("\n");
  const start = lines.findIndex((line) => line.startsWith("services:"));
  const found = new Map();
  let current = null;
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break; // a new top-level key: volumes, networks
    if (line.trim().startsWith("#") || !line.trim()) continue;
    const header = line.match(/^ {2}([a-z0-9_-]+):\s*$/);
    if (header) {
      current = header[1];
      found.set(current, []);
      continue;
    }
    if (current) found.get(current).push(line.trim());
  }
  return found;
}

/** Every `name: value` and `name: [a, b]` line of one service, flattened for matching. */
const body = (lines) => lines.join("\n");

export function measure() {
  const pkg = JSON.parse(read("package.json"));
  const lock = JSON.parse(read("package-lock.json"));
  const productionPackages = Object.entries(lock.packages ?? {}).filter(
    ([path, entry]) => path.startsWith("node_modules/") && !entry.dev && !entry.link,
  ).length;

  const compose = services();
  const publishedPorts = [];
  const servicesWithInternetRoute = [];
  let privilegedContainers = 0;
  let containersWithoutHardening = 0;
  for (const [name, lines] of compose) {
    const text = body(lines);
    for (const match of text.matchAll(/ports:\s*\[([^\]]*)\]/g)) {
      for (const port of match[1].split(",")) {
        const value = port.trim().replace(/["']/g, "");
        if (value) publishedPorts.push(`${name} ${value}`);
      }
    }
    if (/networks:.*\bedge\b/.test(text)) servicesWithInternetRoute.push(name);
    if (/privileged:\s*true/.test(text)) privilegedContainers += 1;
    const hardened =
      /no-new-privileges:true/.test(text) && /cap_drop:\s*\[ALL\]/.test(text) && /read_only:\s*true/.test(text);
    if (!hardened) containersWithoutHardening += 1;
  }

  // Headers the server sets on every reply. A name that disappears is a defence that
  // disappeared, which is why this is compared as a set and not as a count.
  const securityHeaders = unique(
    [...read("src/server/security.ts").matchAll(/reply\.header\(\s*"([a-z0-9-]+)"/g)].map((m) => m[1]),
  );

  // Everything under /api/auth/: logins, the second factor, recovery, device linking,
  // sessions. A new route in that space is new authentication surface by definition.
  const authSources = `${read("src/server/routes/auth.ts")}\n${read("src/server/routes/recovery.ts")}`;
  const authRoutes = unique(
    [...authSources.matchAll(/"(\/api\/auth\/[a-z0-9/:_-]*)"/g)].map((match) => match[1]),
  );

  // The limits that decide how much of the operator's disk a stranger can consume: the
  // configured ceilings, and the two rate buckets that charge uploads.
  const config = read("src/server/config.ts");
  const storageLimits = unique([
    ...[...config.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)]
      .map((m) => m[1])
      .filter((name) => /_BYTES$|_ROWS$|^STORAGE_/.test(name))
      .map((name) => `config:${name}`),
    ...[...read("src/server/lib/rate_limit.ts").matchAll(/^ {2}([a-z_]+):\s*\{\s*burst/gm)]
      .map((m) => m[1])
      .filter((name) => /attachment|upload/.test(name))
      .map((name) => `bucket:${name}`),
  ]);

  // What never reaches a log line (docs/LOGGING.md). The two shape-based rules are named
  // separately: they are what catches a secret nobody thought to add to the list.
  const log = read("src/server/lib/log.ts");
  const forbidden = log.slice(log.indexOf("FORBIDDEN_KEYS"), log.indexOf("SECRET_SHAPED"));
  const loggingRedactions = unique([
    ...[...forbidden.matchAll(/^ {2}"([a-z_=]+)",$/gm)].map((m) => `key:${m[1]}`),
    ...(/const SECRET_SHAPED\s*=/.test(log) ? ["shape:secret"] : []),
    ...(/const ADDRESS_SHAPED\s*=/.test(log) ? ["shape:address"] : []),
  ]);

  return {
    directProductionDependencies: Object.keys(pkg.dependencies ?? {}).length,
    productionPackages,
    privilegedContainers,
    containersWithoutHardening,
    publishedPorts: publishedPorts.sort(),
    servicesWithInternetRoute: servicesWithInternetRoute.sort(),
    egressDestinations: egressDestinations().sort(),
    authRoutes,
    securityHeaders,
    storageLimits,
    loggingRedactions,
  };
}

/**
 * How each measurement is allowed to move. Three kinds, because three questions:
 *
 * - `count`   — more is more surface. Growth fails.
 * - `surface` — a member the baseline does not name is surface nobody approved. Additions fail.
 * - `defence` — a member the baseline names and the tree no longer has is a defence that was
 *               removed. Removals fail.
 *
 * The other direction is never a failure; it prints as DRIFT, which means the baseline is
 * describing a system that no longer exists and should be re-recorded.
 */
export const FIELDS = [
  { key: "directProductionDependencies", kind: "count", what: "direct production dependencies" },
  { key: "productionPackages", kind: "count", what: "packages in the production tree" },
  { key: "privilegedContainers", kind: "count", what: "privileged containers" },
  { key: "containersWithoutHardening", kind: "count", what: "containers missing a hardening flag" },
  { key: "publishedPorts", kind: "surface", what: "published ports" },
  { key: "servicesWithInternetRoute", kind: "surface", what: "services with a route to the internet" },
  { key: "egressDestinations", kind: "surface", what: "files allowed to make an outbound call" },
  { key: "authRoutes", kind: "surface", what: "authentication and session routes" },
  { key: "securityHeaders", kind: "defence", what: "security headers on every reply" },
  { key: "storageLimits", kind: "defence", what: "storage limits enforced server-side" },
  { key: "loggingRedactions", kind: "defence", what: "values a log line never carries" },
];

/** @returns {{lines: string[], failures: string[], drift: string[]}} */
export function compareBaseline(measured, baseline) {
  const lines = [];
  const failures = [];
  const drift = [];
  for (const field of FIELDS) {
    const now = measured[field.key];
    const was = baseline[field.key];
    if (was === undefined) {
      failures.push(`${field.key}: not in ${BASELINE_FILE} — record it`);
      continue;
    }
    if (field.kind === "count") {
      lines.push(`  ${field.what}: ${now} (baseline ${was})`);
      if (now > was) failures.push(`${field.key}: ${was} -> ${now}, the surface grew`);
      if (now < was) drift.push(`${field.key}: ${was} -> ${now}, tighten the baseline`);
      continue;
    }
    const added = now.filter((entry) => !was.includes(entry));
    const removed = was.filter((entry) => !now.includes(entry));
    lines.push(`  ${field.what}: ${now.length} (baseline ${was.length})`);
    if (field.kind === "surface") {
      if (added.length) failures.push(`${field.key}: new and unapproved — ${added.join(", ")}`);
      if (removed.length) drift.push(`${field.key}: gone — ${removed.join(", ")}`);
    } else {
      if (removed.length) failures.push(`${field.key}: no longer present — ${removed.join(", ")}`);
      if (added.length) drift.push(`${field.key}: added — ${added.join(", ")}`);
    }
  }
  return { lines, failures, drift };
}

// ---------------------------------------------------------------------------------------
// The static checks nothing else covers
// ---------------------------------------------------------------------------------------

/**
 * Five questions the release checklist asks that no test asks: they are about what is *not*
 * in the tree, and an absence has no natural home in a suite about behaviour.
 *
 * @returns {Array<{name: string, ok: boolean, detail: string}>}
 */
export function staticChecks() {
  const results = [];
  const config = read("src/server/config.ts");
  const example = read(".env.example");

  // Point 134: no hidden master credential. A break-glass mechanism is allowed and is
  // documented (ADR-0037, docs/RELEASE.md §Break-glass); a master password is not.
  const master = /MASTER_(?:PASSWORD|KEY|TOKEN|SECRET)|BACKDOOR|ROOT_PASSWORD|ADMIN_PASSWORD|SUPER_TOKEN/;
  const masterHits = [...`${config}\n${example}`.matchAll(new RegExp(master.source, "g"))].map((m) => m[0]);
  results.push({
    name: "no master credential in the configuration",
    ok: masterHits.length === 0,
    detail: masterHits.length ? `found ${unique(masterHits).join(", ")}` : "config.ts and .env.example read none",
  });

  // The emergency tool is an operator's shell command, and it stays outside the image the
  // service runs: a break-glass path inside the running service is a backdoor with a name.
  const dockerfile = read("deploy/Dockerfile");
  const runtimeStage = dockerfile.slice(dockerfile.lastIndexOf("FROM "));
  results.push({
    name: "the break-glass tool is not in the runtime image",
    ok: !/COPY[^\n]*\bscripts\b/.test(runtimeStage) && existsSync(join(root, "scripts/incident.mjs")),
    detail: /COPY[^\n]*\bscripts\b/.test(runtimeStage)
      ? "deploy/Dockerfile copies scripts/ into the runtime stage"
      : "scripts/ is build-stage only; scripts/incident.mjs runs from a clone",
  });

  // Debug output is not a switch here, so there is nothing to leave on by accident.
  const debug = [...config.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)]
    .map((m) => m[1])
    .filter((name) => /DEBUG|VERBOSE|TRACE|PROFIL/.test(name));
  const buildScript = read("scripts/build-client.mjs");
  results.push({
    name: "no debug switch, and no production source map",
    ok: debug.length === 0 && /sourcemap:\s*production\s*\?\s*false/.test(buildScript),
    detail: debug.length
      ? `config.ts reads ${debug.join(", ")}`
      : "no debug variable; the production build emits no source map",
  });

  // Point 138: no development route in the production route table.
  const routes = execFileSync("git", ["ls-files", "-z", "src/server/routes"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter(Boolean);
  const suspicious = [];
  for (const file of routes) {
    for (const match of read(file).matchAll(/"(\/(?:api\/)?[a-z0-9/:_.-]*)"/g)) {
      if (/debug|\/dev\b|__|playground|fixture|seed/.test(match[1])) suspicious.push(`${file}: ${match[1]}`);
    }
  }
  results.push({
    name: "no development or debug route is registered",
    ok: suspicious.length === 0,
    detail: suspicious.length ? suspicious.join("; ") : `${routes.length} route modules, none with a dev path`,
  });

  // Point 138: no test credential in anything an operator deploys. The CI workflow is
  // excluded and named: its throwaway PostgreSQL password lives for the length of one job,
  // in a container nothing else can reach.
  const deployFiles = execFileSync("git", ["ls-files", "-z", "deploy", ".env.example"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\0")
    .filter(Boolean)
    .filter((file) => file !== "deploy/github-ci.yml");
  const credentials = [];
  for (const file of deployFiles) {
    for (const finding of scanSource(read(file), file)) {
      credentials.push(`${file}:${finding.line} ${finding.rule}`);
    }
  }
  results.push({
    name: "no credential in a file an operator deploys",
    ok: credentials.length === 0,
    detail: credentials.length
      ? credentials.join("; ")
      : `${deployFiles.length} files scanned (deploy/github-ci.yml excluded: a per-job container password)`,
  });

  return results;
}

// ---------------------------------------------------------------------------------------
// The checklist (point 138) and the gate (point 140)
// ---------------------------------------------------------------------------------------

/** Each item of the release checklist, and the run that decides it. */
export const CHECKLIST = [
  ["tests green", "test", "npm test — every suite"],
  ["migration status", "audit", "audit:migrations — ordered, unedited since release, checksummed"],
  ["secrets clean", "audit", "audit:secrets and audit:history — working tree and every past commit"],
  ["dependencies audited", "audit", "audit:deps, audit:dependencies, audit:supply, audit:inventory"],
  ["containers hardened", "test", "test/deployment.test.ts, and containersWithoutHardening in the baseline"],
  ["security headers active", "test", "test/hardening.test.ts, and securityHeaders in the baseline"],
  ["database inaccessible externally", "test", "test/deployment.test.ts — no published database port, internal network"],
  ["storage inaccessible directly", "test", "test/uploads.test.ts — blobs are rows, served only as JSON to their owner"],
  ["debug disabled", "static", "no debug variable, no production source map"],
  ["production environment valid", "test", "test/environments.test.ts, test/defaults.test.ts"],
  ["no accidental external services", "audit", "audit:cost and audit:egress"],
  ["no test credentials", "static", "no credential in a deployed file"],
  ["no development routes", "static", "no dev, debug or fixture path in the route table"],
];

/**
 * The fourteen areas point 140 requires, and what each one rests on. A category whose
 * evidence did not run prints NOT RUN, and NOT RUN is not a pass.
 */
export const GATE = [
  ["ARCHITECTURE", "test", "test/architecture.test.ts, test/features.test.ts, test/adr.test.ts"],
  ["SECURITY", "test", "test/security.test.ts, test/hardening.test.ts, test/compromise.test.ts"],
  ["PRIVACY", "test", "test/metadata.test.ts, test/logging.test.ts, test/observability.test.ts"],
  ["AUTH", "test", "test/auth.test.ts, test/authorization.test.ts, test/sessions.test.ts, test/idor.test.ts"],
  ["CRYPTO", "test", "test/cryptography.test.ts, test/protocol.test.ts, test/hkdf.test.ts, test/pgp.test.ts"],
  ["DATABASE", "audit", "audit:migrations, test/migrations.test.ts, deploy/postgres-roles.sql (ADR-0095)"],
  ["STORAGE", "test", "test/uploads.test.ts, test/attachments.test.ts, test/images.test.ts, test/jobs.test.ts"],
  ["NETWORK", "audit", "audit:egress, audit:bundle, test/deployment.test.ts"],
  ["CONTAINER", "test", "test/deployment.test.ts, and the baseline's container counts"],
  ["BACKUP", "test", "test/backup.test.ts, and `npm run backup:drill` for a real restore"],
  ["DEPENDENCY", "audit", "audit:deps, audit:dependencies, audit:supply, audit:inventory"],
  ["CLEAN-CLONE", "clean-clone", "node scripts/clean-clone.mjs — fresh clone, npm ci, build, tests, audits"],
  ["COST", "audit", "audit:cost — zero mandatory paid services, keys or hosted dependencies"],
  ["REGRESSION", "baseline", `the security baseline in ${BASELINE_FILE}`],
];

function run(label, command, args) {
  process.stdout.write(`\n=== ${label}: ${command} ${args.join(" ")}\n`);
  const started = Date.now();
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit", shell: false });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  const ok = result.status === 0;
  console.log(`=== ${label}: ${ok ? "ok" : "FAILED"} in ${seconds}s`);
  return ok;
}

function baselineMode(update) {
  const measured = measure();
  const path = join(root, BASELINE_FILE);
  if (update) {
    const recorded = {
      recorded: new Date().toISOString().slice(0, 10),
      why: "See docs/RELEASE.md §The baseline. Every field is measured by scripts/release.mjs.",
      ...measured,
    };
    writeFileSync(path, `${JSON.stringify(recorded, null, 2)}\n`);
    console.log(`baseline: recorded ${FIELDS.length} measurements in ${BASELINE_FILE} — commit it`);
    return true;
  }
  if (!existsSync(path)) {
    console.error(`${BASELINE_FILE} is missing. Record it: node scripts/release.mjs baseline --update`);
    return false;
  }
  const baseline = JSON.parse(read(BASELINE_FILE));
  const { lines, failures, drift } = compareBaseline(measured, baseline);
  console.log(`security baseline (recorded ${baseline.recorded}):`);
  for (const line of lines) console.log(line);
  for (const note of drift) console.log(`  DRIFT  ${note}`);
  for (const failure of failures) console.error(`  EXPANDED  ${failure}`);
  if (failures.length) {
    console.error(
      `\n${failures.length} baseline finding(s): the security surface of this commit is wider than the ` +
        "recorded one. Fix it, or record the new baseline in this commit and say why in the message.",
    );
  }
  return failures.length === 0;
}

function main() {
  const args = process.argv.slice(2);
  if (args[0] === "baseline") process.exit(baselineMode(args.includes("--update")) ? 0 : 1);

  const outcome = new Map();
  outcome.set("check", run("check", "npm", ["run", "check"]));
  outcome.set("test", run("test", "npm", ["test"]));
  outcome.set("audit", run("audit", "npm", ["run", "audit"]));

  console.log("");
  const statics = staticChecks();
  for (const result of statics) {
    console.log(`  ${result.ok ? "ok  " : "FAIL"}  ${result.name} — ${result.detail}`);
  }
  outcome.set("static", statics.every((result) => result.ok));

  console.log("");
  outcome.set("baseline", baselineMode(false));

  if (args.includes("--clean-clone")) {
    outcome.set("clean-clone", run("clean-clone", process.execPath, ["scripts/clean-clone.mjs"]));
  }

  console.log("\nrelease checklist (point 138)");
  for (const [item, from, evidence] of CHECKLIST) {
    const state = outcome.has(from) ? (outcome.get(from) ? "ok  " : "FAIL") : "NOT RUN";
    console.log(`  ${state}  ${item} — ${evidence}`);
  }

  console.log("\nfinal release gate (point 140)");
  let failed = 0;
  let notRun = 0;
  for (const [category, from, evidence] of GATE) {
    const state = outcome.has(from) ? (outcome.get(from) ? "PASS" : "FAIL") : "NOT RUN";
    if (state === "FAIL") failed += 1;
    if (state === "NOT RUN") notRun += 1;
    console.log(`  ${state.padEnd(8)}${category.padEnd(14)}${evidence}`);
  }

  console.log("");
  if (failed || notRun) {
    console.error(
      `NOT production-ready: ${failed} category failed, ${notRun} did not run. ` +
        "A check that did not run is not a pass — run the missing one (--clean-clone) or fix the failure.",
    );
    process.exit(1);
  }
  console.log(`production-ready: ${GATE.length} categories, every one with evidence from this run.`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
