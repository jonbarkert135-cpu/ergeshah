/**
 * A machine-readable Software Bill of Materials, generated from the lockfile and frozen.
 *
 * `docs/DEPENDENCY_INVENTORY.md` already answers "what is in the tree today" for a human
 * reviewer, and `audit:supply` already proves every package is pinned to the public
 * registry with an integrity hash. Neither is a format a scanner can read. A CycloneDX
 * document is: OSV-Scanner, Trivy, Dependency-Track and `grype` all consume it, so the
 * question "does a transitive dependency have a known CVE" can be asked against this file
 * offline and against a registry that never touched this build. This is the SBOM half of
 * OPS-3 (`docs/ROADMAP.md`); container image signing is the other half and needs a key.
 *
 * The document is deterministic — no wall-clock timestamp, a serial number derived from the
 * component set itself — so the committed copy is also the freeze: `sbom` (the default,
 * `check`) regenerates it in memory and fails if the tree has drifted from the committed
 * `docs/sbom.cdx.json`, which is how a lockfile change that skipped review is caught. It
 * reuses `collect()` from the inventory generator, so the two documents describe one tree.
 *
 *   node scripts/sbom.mjs            check the committed SBOM against the tree (CI, `npm run sbom`)
 *   node scripts/sbom.mjs --update   regenerate it (then commit it, `npm run sbom:update`)
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { collect } from "./audit-inventory.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SBOM_DOC = "docs/sbom.cdx.json";

/** SPDX identifiers the tree actually declares; anything else stays a free-text name. */
const KNOWN_LICENCES = new Set([
  "MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD",
  "CC0-1.0", "Unlicense", "BlueOak-1.0.0", "Python-2.0", "MPL-2.0",
]);

/** A Package URL for an npm package: the scope is its own namespace segment, per the spec. */
function purl(name, version) {
  const encoded = name.startsWith("@")
    ? `${encodeURIComponent(name.slice(0, name.indexOf("/")))}/${name.slice(name.indexOf("/") + 1)}`
    : name;
  return `pkg:npm/${encoded}@${version}`;
}

/** `sha512-<base64>` (the lockfile's integrity) becomes a CycloneDX hash: an alg and hex. */
function hashesOf(integrity) {
  if (!integrity) return undefined;
  const out = [];
  for (const token of integrity.split(/\s+/).filter(Boolean)) {
    const dash = token.indexOf("-");
    if (dash < 0) continue;
    const alg = { sha512: "SHA-512", sha384: "SHA-384", sha256: "SHA-256", sha1: "SHA-1" }[
      token.slice(0, dash)
    ];
    if (!alg) continue;
    out.push({ alg, content: Buffer.from(token.slice(dash + 1), "base64").toString("hex") });
  }
  return out.length ? out : undefined;
}

function licenceNode(licence) {
  if (!licence || licence === "UNDECLARED") return undefined;
  return [KNOWN_LICENCES.has(licence) ? { license: { id: licence } } : { license: { name: licence } }];
}

function componentOf(entry) {
  const component = {
    type: "library",
    "bom-ref": purl(entry.name, entry.version),
    name: entry.name,
    version: entry.version,
    scope: entry.dev ? "optional" : "required",
    purl: purl(entry.name, entry.version),
  };
  const licenses = licenceNode(entry.licence);
  if (licenses) component.licenses = licenses;
  const hashes = hashesOf(entry.integrity);
  if (hashes) component.hashes = hashes;
  return component;
}

/**
 * A UUID-shaped urn derived from the component digest, so the serial number is stable across
 * runs and changes only when the tree does. The version and variant nibbles are pinned so a
 * strict validator sees a well-formed UUID, not so it implies randomness that is not there.
 */
function serialNumber(components) {
  const digest = createHash("sha256")
    .update(components.map((c) => `${c.purl}`).join("\n"))
    .digest("hex");
  const h = digest.slice(0, 32).split("");
  h[12] = "4";
  h[16] = "8";
  const s = h.join("");
  return `urn:uuid:${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

/** The CycloneDX 1.5 document for the current tree. Deterministic: no timestamp. */
export function generate() {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const { packages } = collect();
  const components = packages
    .map(componentOf)
    .sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"]));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: serialNumber(components),
    version: 1,
    metadata: {
      tools: [{ name: "symvolon-sbom", version: "1" }],
      component: {
        type: "application",
        "bom-ref": purl(pkg.name ?? "symvolon", pkg.version ?? "0.0.0"),
        name: pkg.name ?? "symvolon",
        version: pkg.version ?? "0.0.0",
      },
    },
    components,
  };
}

/** One canonical serialisation, so the committed file and the generated one compare as text. */
export function serialise(document) {
  return `${JSON.stringify(document, null, 2)}\n`;
}

function main(update) {
  const expected = serialise(generate());
  const path = join(root, SBOM_DOC);
  if (update) {
    writeFileSync(path, expected);
    console.log(`wrote ${SBOM_DOC} (${generate().components.length} components)`);
    return;
  }
  let committed;
  try {
    committed = readFileSync(path, "utf8");
  } catch {
    console.error(`${SBOM_DOC} is missing. Run 'npm run sbom:update' and commit it.`);
    process.exit(1);
  }
  if (committed !== expected) {
    console.error(
      `${SBOM_DOC} is out of date: the dependency tree has changed since it was generated.\n` +
        `Run 'npm run sbom:update', review the diff, and commit it with the reason.`,
    );
    process.exit(1);
  }
  console.log(`${SBOM_DOC} is in step with the lockfile (${generate().components.length} components).`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.includes("--update"));
}
