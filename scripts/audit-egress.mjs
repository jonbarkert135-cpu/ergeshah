/**
 * `node scripts/audit.mjs egress` — every place the server can reach out.
 *
 * Its own file for the reason the `giant-file` rule exists: `scripts/audit.mjs` had grown past
 * 700 lines, and this is a clean seam — the other modes read the repository's *contents*
 * (bundles, secrets, lockfiles, migrations), this one reads what the code would *do at runtime*.
 * `scripts/audit.mjs` re-exports the two scanners so `test/audit.test.ts` keeps one import.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { report, scan } from "./audit.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Server-side egress (points 51, 52, 53).
 *
 * The client's outbound behaviour is audited by `bundle` and constrained by the CSP. The
 * server's was audited by reading, which is another way of saying it was not audited: the
 * application container has no route to the internet (`docs/NETWORK.md`), and that is a
 * property of the deployment file, not of this code — a developer running it outside Docker
 * has full egress and so does a compromised dependency.
 *
 * So: every call site that can leave this process must be in a file this list names, with the
 * reason it exists. A new one is a finding, not a review note. The inventory it prints is the
 * short version of the table in `docs/NETWORK.md`.
 */
const EGRESS_ALLOWED = new Map([
  [
    "src/server/lib/monero.ts",
    "view-only Monero wallet RPC, host from MONERO_WALLET_RPC_URL, three methods only (ADR-0070); optional — absent unless a deployment has a wallet tier",
  ],
  [
    "scripts/payout-worker.mjs",
    "the payout worker, on its own host: this platform's payout queue and its own wallet, both from its environment; optional",
  ],
  [
    "scripts/backup.mjs",
    "the restore drill fetches the throwaway server it just started on localhost; operator tool, never the running service",
  ],
  [
    "scripts/audit.mjs",
    "the deployment audit fetches the origin an operator names on the command line; operator tool",
  ],
]);

/**
 * Anything that can open a connection from this process. Deliberately specific: `db.get(` and
 * `app.get(` are not egress, and a rule that cannot tell them apart is a rule that gets
 * switched off.
 */
const OUTBOUND = [
  ["outbound request", /\bfetch\s*\(|\b(?:https?|undici|axios|superagent|node-fetch)\s*\.\s*(?:request|get|post)\s*\(|\bgot\s*\(/g],
  ["raw socket", /\bnet\s*\.\s*(?:connect|createConnection)\b|\bnew\s+WebSocket\b|\bnode:dgram\b/g],
  ["name resolution", /\bnode:dns\b/g],
];

/** A host written into the source is a host nobody configured and nobody can turn off. */
const LITERAL_HOST = [
  ["hard-coded remote host", /["'`](?:https?|wss?):\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\$\{)[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi],
];

/**
 * Two hosts that appear in the source and are not endpoints anything reaches: the XML
 * namespace every standalone SVG has to carry, and the registry name `audit supply` compares
 * the lockfile against.
 */
const NOT_AN_ENDPOINT = /www\.w3\.org|registry\.npmjs\.org/i;

/**
 * Packages whose entire purpose is to send somebody else data about your users. None of these
 * is in the tree; the check exists so that adding one is a failed build rather than a
 * dependency review nobody does (point 52).
 */
const TELEMETRY = /(?:^|\/)(?:@sentry|@datadog|dd-trace|newrelic|@newrelic|bugsnag|@bugsnag|rollbar|posthog-|mixpanel|amplitude-|@segment|analytics-node|@amplitude|logrocket|fullstory|@elastic\/apm|@opentelemetry|appsignal|raygun|instabug)/i;

export const scanEgress = (text) => scan(text, OUTBOUND);
export const isTelemetryPackage = (name) => TELEMETRY.test(name);

export function egress() {
  const tracked = execFileSync("git", ["ls-files", "-z", "src", "scripts"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter(Boolean)
    .filter((file) => /\.(ts|mjs|js)$/.test(file));

  const findings = [];
  const inventory = [];
  for (const file of tracked) {
    const text = readFileSync(join(root, file), "utf8");
    // The client talks to its own origin through `api.ts`, which is what a web page does; the
    // rule is about the server and the operator tools that run beside it.
    const serverSide = file.startsWith("src/server/") || file.startsWith("scripts/");
    const calls = serverSide ? scan(text, OUTBOUND) : [];
    for (const call of calls) {
      const reason = EGRESS_ALLOWED.get(file);
      if (reason) inventory.push({ file, line: call.line, reason });
      else findings.push({ ...call, file });
    }
    for (const literal of scan(text, LITERAL_HOST)) {
      if (NOT_AN_ENDPOINT.test(literal.match)) continue;
      findings.push({ ...literal, file });
    }
  }

  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  const packages = Object.keys(lock.packages ?? {});
  for (const name of packages.filter((name) => TELEMETRY.test(name))) {
    findings.push({ file: "package-lock.json", line: 1, rule: "telemetry package", match: name });
  }

  if (findings.length) report(findings);
  for (const { file, line, reason } of inventory) console.log(`  ${file}:${line}  ${reason}`);
  console.log(
    `egress audit: ${inventory.length} outbound call site(s), all accounted for; ` +
      `${packages.length} packages, no telemetry, no host written into the source`,
  );
}
