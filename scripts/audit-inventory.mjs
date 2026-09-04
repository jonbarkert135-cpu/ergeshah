/**
 * `node scripts/audit.mjs inventory` — the dependency inventory, generated, and the freeze
 * that turns a dependency change into a reviewed act (points 111, 112).
 *
 * `audit dependencies` already answers "is every direct dependency justified, licensed and
 * inside the budget". Two questions it does not answer:
 *
 *   1. *What is actually in the tree today* — transitive included, with the licence of each
 *      package and which of them are only development tools. That list is too long to keep by
 *      hand and rots the moment it is written, so it is generated into
 *      `docs/DEPENDENCY_INVENTORY.md` and committed.
 *   2. *Did anything change without anybody looking?* A caret range, a `npm install` that
 *      updated a transitive package, a lockfile refresh in an unrelated commit — none of it
 *      shows up in review today. The generated document is the freeze: if the tree no longer
 *      matches the committed inventory, this audit fails and names the four reviews a
 *      dependency change owes (security, licence, privacy, regression).
 *
 * It is not a vulnerability scanner (`audit:deps`) and not a policy check
 * (`audit:dependencies`). It is the record, and the record is machine-compared.
 *
 *   node scripts/audit.mjs inventory            check the committed inventory against the tree
 *   node scripts/audit.mjs inventory --update   regenerate it (then commit it, with reasons)
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export const INVENTORY_DOC = "docs/DEPENDENCY_INVENTORY.md";

/**
 * The part of the inventory a script cannot derive, for the packages where it matters: the
 * ones whose behaviour the threat model depends on. Every direct dependency — production and
 * development — must have a row here, and the audit fails if one arrives without it, because
 * "what does this package do on the network" is the question a generated table cannot answer.
 *
 * `purpose` and `replacement` are the two that decide whether a dependency stays: a package
 * with no purpose we can state is deleted, and a package with no replacement path is a
 * single point of failure worth knowing about before it has a CVE.
 */
const REVIEWED = new Map([
  [
    "fastify",
    {
      purpose: "the HTTP server: routing, body parsing, lifecycle hooks",
      security: "high — it is the trust boundary; every request reaches the application through it",
      network: "inbound only; it accepts connections and never initiates one, and has no telemetry",
      replacement: "node:http plus ~400 lines of routing, validation and lifecycle we would then own",
    },
  ],
  [
    "libsodium-wrappers-sumo",
    {
      purpose: "X25519, XChaCha20-Poly1305, Argon2id, Ed25519 — the primitive set the protocol needs",
      security: "critical — a defect here is a defect in every cryptographic property this project claims",
      network: "none: WASM and arithmetic, no I/O of any kind",
      replacement: "none acceptable. WebCrypto lacks XChaCha20-Poly1305 and Argon2id, and hand-writing either is the mistake this project exists not to make",
    },
  ],
  [
    "openpgp",
    {
      purpose: "verifying OpenPGP signatures for the optional PGP second factor (RFC 4880 packet parsing)",
      security: "high, and server-side only — it decides whether a signature over a login challenge is valid",
      network: "none in this codebase: it is handed bytes already in memory, never a key-server URL",
      replacement: "shelling out to `gpg`, which trades a dependency for a subprocess and a parser of its output",
    },
  ],
  [
    "pg",
    {
      purpose: "the PostgreSQL driver, for deployments that set DB_DIALECT=postgres",
      security: "high — it carries every query, and the parameter binding that keeps SQL injection out",
      network: "outbound to the host in DATABASE_URL, and nowhere else",
      replacement: "the SQLite dialect, which is the default and needs no driver at all (node:sqlite)",
    },
  ],
  [
    "esbuild",
    {
      purpose: "bundling and minifying the client (build time only)",
      security: "high despite being a dev tool: it decides the bytes the browser executes, which is why it is pinned exactly",
      network: "none during a build; it ships a platform binary that `ignore-scripts=true` never links by script",
      replacement: "no bundler at all — plain ES modules served unbundled, at the cost of many round trips over Tor",
    },
  ],
  [
    "typescript",
    {
      purpose: "type checking (`npm run typecheck`); nothing is compiled, the runtime strips types itself",
      security: "medium — the type checker is a large part of what the linter deliberately does not duplicate",
      network: "none",
      replacement: "none wanted; without it `strict` mode stops catching holes",
    },
  ],
  [
    "vitest",
    {
      purpose: "the test runner for every suite under test/",
      security: "medium — it runs in development and CI only, and never in the production image",
      network: "none in this configuration: no reporter, no coverage service, no watch server in CI",
      replacement: "node:test, which would work and would cost a rewrite of every suite",
    },
  ],
  [
    "@scure/bip39",
    {
      purpose: "test-only cross-check of the recovery phrase implementation against an independent one",
      security: "medium: it is the second opinion that would notice a wordlist or checksum mistake in ours",
      network: "none",
      replacement: "the BIP-39 test vectors alone, which is weaker: they check the cases we chose",
    },
  ],
  [
    "jsqr",
    {
      purpose: "test-only decoding of the device-linking QR code the client renders",
      security: "low — it never ships, and it proves the code we draw is readable by a real decoder",
      network: "none",
      replacement: "dropping the assertion, which would leave the QR renderer unverified",
    },
  ],
  [
    "@types/node",
    { purpose: "Node type definitions", security: "none: types are erased", network: "none", replacement: "none" },
  ],
  [
    "@types/pg",
    { purpose: "type definitions for the PostgreSQL driver", security: "none: types are erased", network: "none", replacement: "none" },
  ],
  [
    "@types/libsodium-wrappers-sumo",
    { purpose: "type definitions for libsodium", security: "none: types are erased", network: "none", replacement: "none" },
  ],
]);

function sha256(text) {
  return `sha256-${createHash("sha256").update(text).digest("base64")}`;
}

/** The licence a package declares, from the lockfile when it says, from its manifest when it does not. */
function licenceOf(path, entry) {
  const manifest = join(root, path, "package.json");
  const declared =
    entry.license ?? (existsSync(manifest) ? JSON.parse(readFileSync(manifest, "utf8")).license : null);
  const text = typeof declared === "string" ? declared : declared?.type;
  return text ?? "UNDECLARED";
}

/**
 * Reads the tree as npm sees it. Throws rather than guessing when `node_modules` is absent:
 * a licence column filled with "unknown" would be worse than a failure, because it would be
 * committed and believed.
 */
export function collect() {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  const direct = {
    production: Object.keys(pkg.dependencies ?? {}).sort(),
    development: Object.keys(pkg.devDependencies ?? {}).sort(),
  };

  const packages = [];
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (!path.startsWith("node_modules/") || entry.link) continue;
    const name = path.replace(/^node_modules\//, "");
    packages.push({
      name,
      version: entry.version ?? "unversioned",
      licence: licenceOf(path, entry),
      dev: Boolean(entry.dev),
      direct: direct.production.includes(name) || direct.development.includes(name),
      installScript: Boolean(entry.hasInstallScript),
      integrity: entry.integrity ?? "",
      resolved: entry.resolved ?? "",
    });
  }
  packages.sort((a, b) => a.name.localeCompare(b.name));
  const undeclared = packages.filter((entry) => entry.licence === "UNDECLARED" && !existsSync(join(root, "node_modules", entry.name)));
  if (undeclared.length) {
    throw new Error(
      `node_modules is missing ${undeclared.length} package(s) (${undeclared[0].name} …): run 'npm ci' before generating the inventory`,
    );
  }
  return { direct, packages, lockfileVersion: lock.lockfileVersion };
}

/** One line per package, which is what the freeze digest is taken over. */
function freezeLines(packages) {
  return packages.map((entry) => `${entry.name}@${entry.version} ${entry.integrity}`).join("\n");
}

const row = (cells) => `| ${cells.join(" | ")} |`;

function reviewedSection(name, version, tier, facts) {
  return [
    `### \`${name}\` ${version} — ${tier}`,
    "",
    row(["", ""]),
    row(["---", "---"]),
    row(["Purpose", facts.purpose]),
    row(["Security relevance", facts.security]),
    row(["Network behaviour", facts.network]),
    row(["Replacement possibility", facts.replacement]),
    "",
  ].join("\n");
}

/** The generated document. Deterministic: same lockfile and same tree, same bytes. */
export function render(tree) {
  const { direct, packages } = tree;
  const production = packages.filter((entry) => !entry.dev);
  const development = packages.filter((entry) => entry.dev);
  const runtime = production.filter((entry) => entry.direct);
  const installScripts = packages.filter((entry) => entry.installScript);
  const missingReview = [...direct.production, ...direct.development].filter((name) => !REVIEWED.has(name));

  const lines = [
    "<!-- Generated by `npm run inventory:update`. Do not edit by hand: `npm run audit:inventory`",
    "     compares this file with the tree and fails when they differ. -->",
    "",
    "# Dependency inventory",
    "",
    "Points 111 and 112. `docs/DEPENDENCIES.md` is the argument for each direct dependency, written",
    "by a person. This page is the *inventory*, generated from `package.json`,",
    "`package-lock.json` and the installed tree, and it is the freeze: `npm run audit:inventory`",
    "regenerates it and fails if the result differs from what is committed, so no dependency —",
    "direct or transitive — changes version without a diff somebody has to approve.",
    "",
    "When it fails, the change is not wrong; it is unreviewed. What it owes, in this order:",
    "",
    "1. **Security review** — advisories (`npm run audit:deps`), what the package can reach, what it",
    "   would gain from being compromised.",
    "2. **Licence review** — on the allowlist in `scripts/audit.mjs`, and shippable in a closed-source",
    "   product (`THIRD_PARTY.md`).",
    "3. **Privacy review** — does it open a connection, and does it send anything anywhere",
    "   (`npm run audit:egress`, `docs/DEPENDENCIES.md` §What each one does on the network).",
    "4. **Regression test** — `npm run check && npm test && npm run audit` on the new tree.",
    "",
    "Then `npm run inventory:update`, and commit this file with the reason in the message.",
    "",
    "## Totals",
    "",
    row(["", "Count"]),
    row(["---", "---"]),
    row(["Direct production dependencies", String(direct.production.length)]),
    row(["Production tree, transitive included", String(production.length)]),
    row(["Direct development dependencies", String(direct.development.length)]),
    row(["Development-only packages", String(development.length)]),
    row(["Packages that ship an install script", String(installScripts.length)]),
    "",
    "No package in this tree runs code at install time: `.npmrc` sets `ignore-scripts=true`, which",
    `is why the ${installScripts.length === 1 ? "one that ships a script is" : "ones that ship a script are"} counted rather than refused (\`npm run audit:supply\`).`,
    "",
    "## Freeze",
    "",
    "The digest below is taken over every `name@version` and integrity hash in the lockfile,",
    "production and development together. Quote it in a commit that changes a dependency.",
    "",
    "```",
    `FREEZE ${sha256(freezeLines(packages))}`,
    `PACKAGES ${packages.length}`,
    "```",
    "",
    "## Runtime dependencies",
    "",
    "The packages the production process can load. Everything else in the production tree below is",
    "reached through one of these four, or not at all.",
    "",
    row(["Package", "Version", "Licence", "Loaded"]),
    row(["---", "---", "---", "---"]),
  ];

  const loading = new Map([
    ["fastify", "at boot"],
    ["libsodium-wrappers-sumo", "at boot (server) and lazily in the client's crypto chunk"],
    ["openpgp", "dynamically, only when a PGP factor is used; never in the client"],
    ["pg", "dynamically, only when DB_DIALECT=postgres"],
  ]);
  for (const entry of runtime) {
    lines.push(row([`\`${entry.name}\``, entry.version, entry.licence, loading.get(entry.name) ?? "direct dependency"]));
  }

  lines.push("", "## Critical dependencies, reviewed", "");
  lines.push(
    "Every *direct* dependency, production and development, with the four things a generated table",
    "cannot derive. A direct dependency without a row here fails the audit.",
    "",
  );
  for (const name of [...direct.production, ...direct.development]) {
    const facts = REVIEWED.get(name);
    if (!facts) continue;
    const entry = packages.find((candidate) => candidate.name === name);
    const tier = direct.production.includes(name) ? "production" : "development only";
    lines.push(reviewedSection(name, entry?.version ?? "unversioned", tier, facts));
  }

  lines.push("## Production tree", "", "Transitive included. This is what `npm ci --omit=dev` installs.", "");
  lines.push(row(["Package", "Version", "Licence", "Depth"]));
  lines.push(row(["---", "---", "---", "---"]));
  for (const entry of production) {
    lines.push(
      row([`\`${entry.name}\``, entry.version, entry.licence, entry.direct ? "direct" : "transitive"]),
    );
  }

  lines.push("", "## Development-only packages", "", "Not installed by the production image (`npm prune --omit=dev` in `deploy/Dockerfile`).", "");
  lines.push(row(["Package", "Version", "Licence", "Depth"]));
  lines.push(row(["---", "---", "---", "---"]));
  for (const entry of development) {
    lines.push(
      row([`\`${entry.name}\``, entry.version, entry.licence, entry.direct ? "direct" : "transitive"]),
    );
  }

  if (missingReview.length) {
    lines.push("", `<!-- unreviewed direct dependencies: ${missingReview.join(", ")} -->`);
  }
  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}

export function inventory(update = false) {
  const tree = collect();
  const generated = render(tree);
  const path = join(root, INVENTORY_DOC);
  const missingReview = [...tree.direct.production, ...tree.direct.development].filter(
    (name) => !REVIEWED.has(name),
  );

  if (update) {
    writeFileSync(path, generated);
    console.log(`inventory: wrote ${INVENTORY_DOC} for ${tree.packages.length} packages — commit it`);
    if (missingReview.length) {
      console.error(
        `\n${missingReview.length} direct dependency without a reviewed row: ${missingReview.join(", ")}\n` +
          "Add it to REVIEWED in scripts/audit-inventory.mjs: purpose, security relevance, network behaviour, replacement.",
      );
      process.exit(1);
    }
    return;
  }

  const problems = [];
  if (missingReview.length) {
    problems.push(
      `${missingReview.join(", ")}: direct dependency with no purpose, network behaviour or replacement ` +
        "recorded (REVIEWED in scripts/audit-inventory.mjs)",
    );
  }
  if (!existsSync(path)) {
    problems.push(`${INVENTORY_DOC} is missing — run 'npm run inventory:update'`);
  } else {
    const committed = readFileSync(path, "utf8");
    if (committed !== generated) {
      const was = committed.match(/^FREEZE (\S+)$/m)?.[1] ?? "none";
      const now = generated.match(/^FREEZE (\S+)$/m)?.[1] ?? "none";
      problems.push(
        `${INVENTORY_DOC} does not describe this tree.\n` +
          `    committed freeze: ${was}\n` +
          `    this tree:        ${now}\n` +
          "    A dependency changed. Before regenerating it, do the four reviews the document lists:\n" +
          "    SECURITY REVIEW -> LICENCE REVIEW -> PRIVACY REVIEW -> REGRESSION TEST.\n" +
          "    Then: npm run inventory:update, and commit with the reason.",
      );
    }
  }

  if (problems.length) {
    for (const problem of problems) console.error(`  ${problem}`);
    console.error(`\n${problems.length} inventory problem(s).`);
    process.exit(1);
  }
  const production = tree.packages.filter((entry) => !entry.dev).length;
  console.log(
    `inventory audit: ${tree.packages.length} packages (${production} production, ` +
      `${tree.packages.length - production} development), frozen and matching ${INVENTORY_DOC}`,
  );
}
