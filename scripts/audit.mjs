/**
 * Two audits that cost nothing and catch the two mistakes that would quietly break the
 * project's promises:
 *
 *   node scripts/audit.mjs bundle      — the client the browser gets talks to no one but
 *                                        us, and the build that produced it repeats
 *   node scripts/audit.mjs secrets     — no key material or credential is committed
 *   node scripts/audit.mjs deployment <origin>
 *                                      — a running deployment serves exactly the bytes
 *                                        this source tree builds
 *   node scripts/audit.mjs history     — no secret was ever committed, in any commit
 *   node scripts/audit.mjs migrations  — migrations are ordered, and released ones are
 *                                        byte-for-byte what they were when released
 *   node scripts/audit.mjs supply      — lockfile, pinning and install-script policy
 *   node scripts/audit.mjs cost        — the core deployment needs no paid service, no
 *                                        API key and nothing hosted by anybody else
 *   node scripts/audit.mjs dependencies
 *                                      — every production dependency is justified in
 *                                        docs/DEPENDENCIES.md, licensed acceptably, and
 *                                        the tree stays inside its budget
 *   node scripts/audit.mjs egress      — every place the *server* can reach out is a
 *                                        known one, no host is written into the source,
 *                                        and no telemetry package is in the tree
 *   node scripts/audit.mjs inventory   — the generated dependency inventory still describes
 *                                        this tree: nothing changed version without review
 *                                        (`--update` regenerates it)
 *
 * Both are grep with a threat model attached. They do not replace review; they replace
 * *forgetting*. A line may opt out with an `audit:allow` comment on it, which is
 * deliberately visible in review.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// The egress audit lives next door; `audit.mjs` was past the 700-line ceiling.
import { egress } from "./audit-egress.mjs";
export { egress, isTelemetryPackage, scanEgress } from "./audit-egress.mjs";
// Same seam, same reason: the inventory generator is a document, not a grep.
import { inventory } from "./audit-inventory.mjs";
export { collect, INVENTORY_DOC, inventory, render } from "./audit-inventory.mjs";

/** Anything that would make the browser reach a host we do not operate. */
const EXTERNAL = [
  // The path is part of the match so that a report is actionable and so that an XML
  // namespace can be told apart from a request to the same domain.
  ["remote URL", /\b(?:https?|wss?|ftp):\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s"'`<>)\]]*)?/gi],
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
  // A URL with `user:TOKEN@` in front of the host — what npm writes into `package-lock.json`
  // when a registry was given with credentials in its URL, and what a lockfile-blind scanner used to miss
  // (SEC-2026-021). The captured value is the userinfo, so a placeholder still passes.
  ["credential in URL", /\bhttps?:\/\/([^\s"'`/@:]+:[^\s"'`/@]+)@[a-z0-9.-]+/gi],
  // npm's own way of writing a registry token into a config or lock file.
  ["npm auth token", /\b_authToken\s*[=:]\s*["']?([^\s"'\n]{16,})/gi],
];

/**
 * Files that *are* a secret, whatever their content looks like. The content rules above read
 * text; a PKCS#12 bundle, a Tor onion service's `hs_ed25519_secret_key`, a Monero wallet's
 * `.keys` file or a SQLite database committed by mistake are binary, carry no `-----BEGIN`
 * header and would pass them. The Solaris takeover (2023) began with keys lifted from the
 * operator's repository and servers, so this rule is by path: a key file is a finding the
 * moment it is tracked, before anybody reads it. `.env.example` is documentation and stays;
 * the migrations are `.sql`, not `.sql.gz`, and stay.
 */
const KEY_MATERIAL_PATH =
  /(?:^|\/)(?:\.env(?:\.[^/]+)?|\.netrc|\.pgpass|id_(?:rsa|dsa|ecdsa|ed25519)|hs_ed25519_secret_key|[^/]+\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk|keys|sqlite3?|db|dump|sql\.gz|tar|tar\.gz|tgz|zip))$/i;

/** `true` when a tracked path is key material or a database by name alone. */
export const isKeyMaterialPath = (path) => KEY_MATERIAL_PATH.test(path) && !/(?:^|\/)\.env\.example$/.test(path);

/** The lockfile is JSON npm writes; the credential-literal heuristic would drown in it. */
const LOCKFILE_RULES = SECRETS.filter(([rule]) => rule !== "credential literal");

/**
 * XML namespace URIs are identifiers, not endpoints: no browser ever fetches them, and
 * `<svg xmlns="http://www.w3.org/2000/svg">` is the only way to write a standalone SVG.
 * Nothing else on w3.org is exempt.
 */
const NAMESPACES = /^https?:\/\/www\.w3\.org\/(?:2000\/svg|1999\/xhtml|1999\/xlink)$/;

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
      if (NAMESPACES.test(m[0])) continue;
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
  scan(
    text,
    path.startsWith("test/") || path === "package-lock.json" || path.endsWith(".lock") ? LOCKFILE_RULES : SECRETS,
  );

export function report(findings) {
  for (const { file, rule, line, match } of findings) {
    console.error(`  ${file}:${line}  ${rule}: ${match}`);
  }
  console.error(`\n${findings.length} finding(s). Fix them, or mark the line 'audit:allow' with a reason.`);
  process.exit(1);
}

/** Builds the production client. Returns `public/BUILD.txt`, the digests it produced. */
function buildProduction() {
  execFileSync(process.execPath, [join(root, "scripts/build-client.mjs")], {
    env: { ...process.env, NODE_ENV: "production" },
    stdio: "inherit",
  });
  return readFileSync(join(root, "public/BUILD.txt"), "utf8");
}

function sha256(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
}

function bundle() {
  // Audit what production actually serves: minified, no inline source map, no comments.
  const first = buildProduction();
  // Reproducibility is a property that rots silently — a plugin that embeds a timestamp,
  // a path, or a hash-map iteration order breaks it and nothing else notices. So build
  // twice and compare, which is the cheapest possible regression test for OPS-1.
  if (buildProduction() !== first) {
    console.error("\nbuild is not reproducible: two identical builds produced different digests");
    console.error("expected:\n" + first);
    process.exit(1);
  }
  // Every file the build produced, whatever this build's content hashes turned out to be.
  const files = readFileSync(join(root, "public/BUILD.txt"), "utf8")
    .trim()
    .split("\n")
    .map((line) => `public/${line.split("  ")[1]}`)
    .filter((file) => /\.(js|css|html)$/.test(file));
  const findings = [];
  for (const file of files) {
    const path = join(root, file);
    if (!existsSync(path)) throw new Error(`${file} missing — the build did not produce it`);
    findings.push(...scanBundle(readFileSync(path, "utf8")).map((f) => ({ ...f, file })));
  }
  if (findings.length) report(findings);
  console.log(`bundle audit: ${files.length} files, no external references, no secrets`);
  console.log(`build is reproducible; digests:\n${first.trimEnd()}`);
}

/**
 * Compares a deployment with this source tree. It hashes the bytes the server actually
 * sends — the server's own BUILD.txt is fetched for information, never trusted as the
 * answer, since an operator who swaps the bundle can rewrite that file too.
 */
async function deployment(origin) {
  const expected = new Map(
    buildProduction()
      .trim()
      .split("\n")
      .map((line) => line.split("  "))
      .map(([hash, file]) => [file, hash]),
  );
  // Names are content-addressed, so the local build decides which URLs to compare; a
  // deployment serving a *different* set of names is itself the finding.
  const routes = [
    ...[...expected.keys()]
      .filter((file) => file.startsWith("assets/"))
      .map((file) => [file, `/${file}`]),
    ["favicon.svg", "/favicon.svg"],
    ["index.html", "/"],
  ];
  let mismatched = 0;
  for (const [file, path] of routes) {
    const url = new URL(path, origin);
    // `identity`: compare the bytes the build produced, not a compressed transfer form.
    const response = await fetch(url, { redirect: "error", headers: { "accept-encoding": "identity" } });
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
    const actual = sha256(new Uint8Array(await response.arrayBuffer()));
    const ok = actual === expected.get(file);
    if (!ok) mismatched += 1;
    console.log(`${ok ? "ok  " : "DIFF"}  ${path}  ${actual}${ok ? "" : `\n      expected ${expected.get(file)}`}`);
  }
  if (mismatched) {
    console.error(
      `\n${mismatched} file(s) differ. Either the deployment runs different source, was built ` +
        "with different dependency versions (use `npm ci`), or is serving something you did not write.",
    );
    process.exit(1);
  }
  console.log(`\n${origin} serves exactly what this source tree builds.`);
}

/**
 * Point 31 asks that the *history* contain no secrets, which is a different claim from
 * "the working tree contains no secrets": a key committed and then deleted is still in
 * every clone, forever. This walks every blob that has ever been committed. It is the one
 * audit that cannot be fixed by editing a file — a finding here means rotating the secret
 * and rewriting history.
 */
function history() {
  const revisions = execFileSync("git", ["rev-list", "--all"], { cwd: root, encoding: "utf8" })
    .split("\n")
    .filter(Boolean);
  // Every (path, blob) pair that has ever existed, deduplicated by blob hash: a file
  // unchanged across 200 commits is scanned once.
  const blobs = new Map();
  const keyFiles = new Map();
  for (const rev of revisions) {
    const listing = execFileSync("git", ["ls-tree", "-r", "-z", rev], { cwd: root, encoding: "utf8" });
    for (const entry of listing.split("\0").filter(Boolean)) {
      const [meta, path] = entry.split("\t");
      const [, type, hash] = meta.split(/\s+/);
      if (type !== "blob") continue;
      // A key file is a finding by name in any revision, binary or not (see KEY_MATERIAL_PATH).
      if (isKeyMaterialPath(path) && !keyFiles.has(path)) keyFiles.set(path, hash);
      if (/\.(png|jpg|jpeg|gif|svg|ico|woff2?|pdf)$/i.test(path)) continue;
      if (!blobs.has(hash)) blobs.set(hash, path);
    }
  }
  const allowPath = join(root, "scripts/history-allow.json");
  const allowed = new Map(
    (existsSync(allowPath) ? JSON.parse(readFileSync(allowPath, "utf8")) : []).map((entry) => [
      entry.blob,
      entry,
    ]),
  );
  const findings = [];
  const unreviewed = [];
  for (const [path, hash] of keyFiles) {
    if (allowed.has(hash)) continue;
    unreviewed.push({ blob: hash, path });
    findings.push({ file: `${path}@${hash.slice(0, 8)}`, rule: "key material by path", line: 0, match: "a key, wallet, database or archive file was committed" });
  }
  for (const [hash, path] of blobs) {
    if (allowed.has(hash)) continue;
    const text = execFileSync("git", ["cat-file", "blob", hash], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    const hits = scanSource(text, path);
    if (hits.length) {
      unreviewed.push({ blob: hash, path });
      findings.push(...hits.map((f) => ({ ...f, file: `${path}@${hash.slice(0, 8)}` })));
    }
  }
  if (findings.length) {
    console.error("Something that looks like a secret is in git history.");
    console.error("If it is real: rotate it, then rewrite history — a deleted file is still in every clone.");
    console.error("If it is a fixture (the scanner's own test data), add these to scripts/history-allow.json");
    console.error("with a reason, after reading the blob:\n");
    console.error(JSON.stringify(unreviewed.map((u) => ({ ...u, reason: "" })), null, 2));
    console.error("");
    report(findings);
  }
  console.log(
    `history audit: ${revisions.length} commits, ${blobs.size} distinct blobs ` +
      `(${allowed.size} reviewed fixtures allowed), no credential and no key file ever committed`,
  );
}

/**
 * Migrations are the one part of the system where a mistake is not fixable by deploying
 * again: an edited migration means development and production diverge silently, and the
 * divergence is discovered by a constraint violation months later. So released migrations
 * are checksummed, and the checksums are committed.
 *
 *   node scripts/audit.mjs migrations --update   after adding a new migration
 */
function migrations(update = false) {
  const dir = join(root, "src/server/db/migrations");
  const files = readdirSync(dir).filter((name) => name.endsWith(".sql")).sort();
  const problems = [];
  const manifestPath = join(dir, "CHECKSUMS.txt");
  const recorded = existsSync(manifestPath) ? readFileSync(manifestPath, "utf8") : "";
  // Released migrations are never edited, so the reversibility rule can only apply to the
  // ones that have not shipped yet — which is the only moment the answer is still cheap.
  const released = new Set(
    recorded.split("\n").filter(Boolean).map((line) => line.split("  ")[1]),
  );

  files.forEach((name, index) => {
    // `NNN_name.sql` runs on both drivers; `NNN_name.postgres.sql` and `NNN_name.sqlite.sql`
    // run on one (src/server/db/migrate.ts).
    if (!/^\d{3}_[a-z0-9_]+(\.(sqlite|postgres))?\.sql$/.test(name)) {
      problems.push(`${name}: name must be NNN_lower_snake_case[.sqlite|.postgres].sql`);
    }
    const expected = String(index + 1).padStart(3, "0");
    if (name.slice(0, 3) !== expected) {
      problems.push(`${name}: out of sequence, expected ${expected}_*.sql (no gaps, no duplicates)`);
    }
    const sql = readFileSync(join(dir, name), "utf8");
    // Destructive statements are sometimes right, but never accidental.
    const destructive = sql.match(/\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE|DELETE\s+FROM)\b/i);
    if (destructive && !/--\s*destructive:/i.test(sql)) {
      problems.push(
        `${name}: contains ${destructive[0].toUpperCase()} — say why in a '-- destructive: …' comment`,
      );
    }
    // Point 90: a migration says whether it can be undone, while the author still knows.
    // "no" is a valid answer — the point is that the rollback plan is decided before the
    // deployment that needs it, not discovered during one (docs/DATABASE.md).
    if (!released.has(name) && !/--\s*reversible:\s*(yes|no)\b/i.test(sql)) {
      problems.push(
        `${name}: declare '-- reversible: yes — <the statements that undo it>' or '-- reversible: no — <why>'`,
      );
    }
  });

  const current = files
    .map((name) => `${sha256(readFileSync(join(dir, name)))}  ${name}`)
    .join("\n") + "\n";

  if (update) {
    writeFileSync(manifestPath, current);
    console.log(`migrations: wrote checksums for ${files.length} migration(s) — commit CHECKSUMS.txt`);
    return;
  }

  if (recorded !== current) {
    const recordedLines = new Map(
      recorded.split("\n").filter(Boolean).map((line) => line.split("  ")).map(([h, n]) => [n, h]),
    );
    for (const line of current.split("\n").filter(Boolean)) {
      const [hash, name] = line.split("  ");
      const was = recordedLines.get(name);
      if (was === undefined) problems.push(`${name}: new migration — run 'npm run migrate:checksums'`);
      else if (was !== hash) {
        problems.push(
          `${name}: CHANGED after release. Deployments that already applied it will not see the edit. ` +
            "Write a new migration instead.",
        );
      }
      recordedLines.delete(name);
    }
    for (const name of recordedLines.keys()) problems.push(`${name}: recorded but missing from disk`);
  }

  if (problems.length) {
    for (const problem of problems) console.error(`  ${problem}`);
    console.error(`\n${problems.length} migration problem(s).`);
    process.exit(1);
  }
  console.log(`migration audit: ${files.length} migrations, ordered, unmodified since release`);
}

/**
 * Supply chain (point 34). The threat is not a vulnerability in a dependency — that is
 * `audit:deps` — but a package that runs code on `npm install`, a floating version that
 * resolves to something new on the build machine, or a lockfile that is not the one the
 * build used.
 */
function supply() {
  const problems = [];
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

  const npmrc = existsSync(join(root, ".npmrc")) ? readFileSync(join(root, ".npmrc"), "utf8") : "";
  if (!/^ignore-scripts\s*=\s*true/m.test(npmrc)) {
    problems.push(".npmrc must set ignore-scripts=true: install scripts are arbitrary code execution");
  }
  if (!existsSync(join(root, "package-lock.json"))) {
    problems.push("package-lock.json must be committed; without it 'npm ci' cannot pin anything");
  }

  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  const withInstallScripts = [];
  if (lock.lockfileVersion < 3) problems.push("lockfile version must be >= 3 (integrity hashes per package)");
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (!path || entry.link) continue;
    if (entry.resolved && !entry.integrity) problems.push(`${path}: no integrity hash in the lockfile`);
    // audit:allow — the registry is where dependencies are installed from at build time, not a service the deployment calls.
    if (entry.resolved && !entry.resolved.startsWith("https://registry.npmjs.org/")) {
      problems.push(`${path}: resolved from ${entry.resolved} — only the public registry is expected`);
    }
    // A resolved URL with `user:token@` before the registry host passes the prefix test above
    // only if the prefix is wrong anyway, but a lockfile from a private mirror would carry the credential in every
    // clone; the userinfo is refused by shape, not by host (SEC-2026-021).
    if (entry.resolved && /^[a-z]+:\/\/[^/]*@/i.test(entry.resolved)) {
      problems.push(`${path}: resolved URL carries credentials — rotate them and re-resolve`);
    }
    // Not a failure by itself — esbuild ships one to link its platform binary, and with
    // ignore-scripts it simply never runs (verified: `npm ci` then a build still works).
    // Worth counting, because the number going up is worth a look.
    if (entry.hasInstallScript) withInstallScripts.push(path.replace("node_modules/", ""));
  }

  // The build tool decides what the browser runs, so it is pinned exactly rather than by
  // range: a caret on esbuild is a caret on the bytes we ship.
  for (const name of ["esbuild"]) {
    const range = pkg.devDependencies?.[name];
    if (range && !/^\d/.test(range)) problems.push(`${name} must be pinned exactly, got ${range}`);
  }

  const installScripts = Object.keys(pkg.scripts ?? {}).filter((name) =>
    ["preinstall", "install", "postinstall", "prepare"].includes(name),
  );
  if (installScripts.length) {
    problems.push(`package.json defines ${installScripts.join(", ")} — this project runs no install hooks`);
  }

  if (problems.length) {
    for (const problem of problems) console.error(`  ${problem}`);
    console.error(`\n${problems.length} supply-chain problem(s).`);
    process.exit(1);
  }
  const count = Object.keys(lock.packages ?? {}).length - 1;
  console.log(
    `supply-chain audit: ${count} locked packages, all from the public registry with integrity hashes`,
  );
  console.log(
    withInstallScripts.length
      ? `  ${withInstallScripts.length} ship an install script (${withInstallScripts.join(", ")}) — none run: ignore-scripts=true`
      : "  no package ships an install script",
  );
  // The workflow GitHub runs is a copy a human makes (AGENTS.md). A notice, not a failure:
  // the copy cannot be made from here, and a red build over it would train people to ignore
  // red builds. Until the two agree, the PostgreSQL job in the source is not running in CI
  // (SEC-2026-022).
  const live = join(root, ".github/workflows/ci.yml");
  const source = join(root, "deploy/github-ci.yml");
  if (existsSync(live) && existsSync(source) && readFileSync(live, "utf8") !== readFileSync(source, "utf8")) {
    console.log(
      "  NOTICE: .github/workflows/ci.yml differs from deploy/github-ci.yml — copy the source over it " +
        "so that CI runs what the repository says it runs (SEC-2026-022)",
    );
  }
}

/**
 * Licences we can ship in a closed-source product. Copyleft that reaches the application
 * (GPL, AGPL) is absent on purpose; LGPL is present because openpgp.js is used unmodified
 * as a separate module, which is the condition the LGPL attaches (see THIRD_PARTY.md).
 */
const LICENCES = /^(MIT|ISC|0BSD|BSD-2-Clause|BSD-3-Clause|Apache-2\.0|Unlicense|CC0-1\.0|LGPL-3\.0(-or-later|\+)?|BlueOak-1\.0\.0|Python-2\.0)$/;

/**
 * Point 33: every dependency is attack surface. The rule this enforces is not "few
 * dependencies" — it is "no dependency without a written reason", which is the version a
 * machine can check. The budget is a ratchet: it goes up only when someone edits it in a
 * commit that also explains why.
 */
function dependencies() {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  const doc = existsSync(join(root, "docs/DEPENDENCIES.md"))
    ? readFileSync(join(root, "docs/DEPENDENCIES.md"), "utf8")
    : "";
  const problems = [];

  const direct = Object.keys(pkg.dependencies ?? {});
  for (const name of direct) {
    if (!new RegExp(`^###\\s+\`?${name.replace(/[/\\-]/g, "\\$&")}\`?`, "m").test(doc)) {
      problems.push(`${name}: no '### ${name}' section in docs/DEPENDENCIES.md justifying it`);
    }
  }

  // The production tree, as npm would install it with --omit=dev.
  const production = Object.entries(lock.packages ?? {}).filter(
    ([path, entry]) => path.startsWith("node_modules/") && !entry.dev && !entry.link,
  );
  for (const [path, entry] of production) {
    const name = path.replace(/^node_modules\//, "");
    const manifest = join(root, path, "package.json");
    const licence =
      entry.license ?? (existsSync(manifest) ? JSON.parse(readFileSync(manifest, "utf8")).license : null);
    const text = typeof licence === "string" ? licence : licence?.type;
    if (!text) problems.push(`${name}: no licence declared`);
    else if (!text.split(/\s+OR\s+/i).some((part) => LICENCES.test(part.replace(/[()]/g, "")))) {
      problems.push(`${name}: licence ${text} is not on the allowlist for a closed-source product`);
    }
  }

  const budget = Number(readFileSync(join(root, "docs/DEPENDENCIES.md"), "utf8").match(/budget:\s*(\d+)/i)?.[1]);
  if (!Number.isFinite(budget)) {
    problems.push("docs/DEPENDENCIES.md must state a 'budget: N' for the production tree");
  } else if (production.length > budget) {
    problems.push(
      `production tree is ${production.length} packages, budget is ${budget}. ` +
        "Remove something, or raise the budget in the same commit that explains why.",
    );
  }

  if (problems.length) {
    for (const problem of problems) console.error(`  ${problem}`);
    console.error(`\n${problems.length} dependency problem(s).`);
    process.exit(1);
  }
  console.log(
    `dependency audit: ${direct.length} direct, ${production.length} in the production tree ` +
      `(budget ${budget}), every one justified, every licence allowed`,
  );
}

function secrets() {
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter(Boolean)
    // Binary and vendored word lists have no credentials and produce noise.
    .filter((f) => !/\.(png|jpg|jpeg|gif|svg|ico|woff2?|pdf)$/i.test(f));
  const findings = [];
  for (const file of tracked) {
    if (isKeyMaterialPath(file)) {
      findings.push({ file, rule: "key material by path", line: 0, match: "a key, wallet, database or archive file is tracked" });
      continue;
    }
    findings.push(...scanSource(readFileSync(join(root, file), "utf8"), file).map((f) => ({ ...f, file })));
  }
  if (findings.length) report(findings);
  console.log(`secret audit: ${tracked.length} tracked files, nothing that looks like a credential or a key file`);
}

/**
 * Point 99: the cost audit. The promise is that a core deployment costs nothing but the
 * VPS it runs on — no SaaS, no API key, no hosted database, no object store, no analytics
 * — and a promise nobody checks is a promise until the first commit that quietly adds a
 * client library for one.
 *
 * Three greps with that threat model attached: a dependency that is an SDK for somebody's
 * service, a request in the code to a host we do not operate, and a configuration variable
 * that is a credential for one. Anything the *operator* chooses to run themselves — their
 * own PostgreSQL, their own Monero node, their own reverse proxy — is not a cost of the
 * software and is listed rather than counted.
 */
const HOSTED_SERVICE_SDK =
  /^(?:@aws-sdk\/|aws-sdk$|@google-cloud\/|@azure\/|firebase|@sentry\/|@datadog\/|dd-trace$|newrelic$|@segment\/|analytics-node$|mixpanel|amplitude|posthog|stripe$|@stripe\/|braintree|paypal|@sendgrid\/|nodemailer-sendgrid|mailgun|postmark|resend$|twilio|@twilio\/|@supabase\/|@clerk\/|auth0|@auth0\/|algolia|cloudinary|pusher|openai$|@anthropic-ai\/|@vercel\/|@planetscale\/|@upstash\/|@neondatabase\/|mongodb\+srv|contentful|recaptcha|hcaptcha)/i;

/** Configuration that would be a credential for somebody else's service. */
const HOSTED_SERVICE_ENV =
  /\b(?:STRIPE|SENDGRID|MAILGUN|POSTMARK|TWILIO|SENTRY|DATADOG|NEWRELIC|SEGMENT|MIXPANEL|AMPLITUDE|POSTHOG|GOOGLE|GCP|AWS|AZURE|CLOUDFLARE|OPENAI|ANTHROPIC|RECAPTCHA|HCAPTCHA|AUTH0|CLERK|SUPABASE|ALGOLIA|CLOUDINARY|SMTP)_[A-Z0-9_]+/;

/** Hosts the running software may name. Everything here is the operator's own machine. */
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|app|db|proxy|monerod|wallet)(?::\d+)?$/;

/** Comments cite specifications by URL; only code that *runs* is evidence of a dependency. */
function withoutComments(text) {
  // Blanked, not deleted: the line numbers have to keep matching the file on disk, both for
  // the report and for the `audit:allow` marker that is read from the original line.
  const blank = (match) => match.replace(/[^\n]/g, " ");
  return text.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/(^|[^:])(\/\/[^\n]*)/g, (_, before, comment) => before + blank(comment));
}

function cost() {
  const problems = [];
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

  for (const name of Object.keys(pkg.dependencies ?? {})) {
    if (HOSTED_SERVICE_SDK.test(name)) {
      problems.push(`${name}: a client for a hosted service — the core deployment may not require one`);
    }
  }

  const tracked = execFileSync("git", ["ls-files", "-z", "src", "scripts", "deploy", ".env.example"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\0")
    .filter(Boolean);

  for (const file of tracked) {
    const text = readFileSync(join(root, file), "utf8");
    if (file.endsWith(".env.example") || file === ".env.example") {
      for (const match of text.matchAll(/^([A-Z][A-Z0-9_]*)=/gm)) {
        if (HOSTED_SERVICE_ENV.test(match[1])) {
          problems.push(`${file}: ${match[1]} configures a third-party service`);
        }
      }
      continue;
    }
    const code = withoutComments(text);
    for (const match of code.matchAll(/\b(?:https?|wss?):\/\/([a-z0-9.-]+)(?::[\d$][^\s"'`]*)?(?:\/[^\s"'`]*)?/gi)) {
      const host = match[1];
      if (LOCAL_HOST.test(host) || NAMESPACES.test(match[0])) continue;
      const line = code.slice(0, match.index).split("\n").length;
      const lines = text.split("\n");
      // The waiver may sit on the line or in the comment directly above it, as everywhere else.
      if (`${lines[line - 2] ?? ""}${lines[line - 1] ?? ""}`.includes("audit:allow")) continue;
      problems.push(`${file}:${line}: names ${host}, a host this deployment does not operate`);
    }
    for (const match of text.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) {
      if (HOSTED_SERVICE_ENV.test(match[1])) problems.push(`${file}: reads ${match[1]}`);
    }
  }

  if (problems.length) {
    for (const problem of problems) console.error(`  ${problem}`);
    console.error(`\n${problems.length} finding(s): the zero-cost promise (docs/AUDIT.md) is broken.`);
    process.exit(1);
  }

  console.log("cost audit:");
  for (const line of [
    "MANDATORY EXTERNAL SERVICES: 0",
    "MANDATORY PAID APIS: 0",
    "MANDATORY API KEYS: 0",
    "MANDATORY CLOUD SERVICES: 0",
    "MANDATORY THIRD-PARTY TRACKERS: 0",
    "MANDATORY EXTERNAL DATABASES: 0",
    "MANDATORY EXTERNAL STORAGE: 0",
  ]) {
    console.log(`  ${line}`);
  }
  console.log(
    "  optional, and run by the operator on their own hardware: PostgreSQL, a Monero node\n" +
      "  and wallet RPC, a reverse proxy. Infrastructure the operator chooses, not a fee.",
  );
}

// Only when run as a command; the tests import the scanners.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  if (mode === "bundle") bundle();
  else if (mode === "secrets") secrets();
  else if (mode === "history") history();
  else if (mode === "migrations") migrations(process.argv.includes("--update"));
  else if (mode === "supply") supply();
  else if (mode === "dependencies") dependencies();
  else if (mode === "cost") cost();
  else if (mode === "egress") egress();
  else if (mode === "inventory") inventory(process.argv.includes("--update"));
  else if (mode === "deployment") {
    const origin = process.argv[3];
    // audit:allow — a usage string; the origin is the operator's own deployment, supplied on the command line.
    if (!origin) throw new Error("usage: node scripts/audit.mjs deployment https://host");
    await deployment(origin);
  } else {
    throw new Error(
      "usage: node scripts/audit.mjs bundle|secrets|history|migrations|supply|dependencies|cost|" +
        `egress|inventory|deployment (got '${mode ?? ""}')`,
    );
  }
}
