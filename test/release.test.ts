/**
 * The release gate, the security baseline and the dependency freeze — checked the way every
 * other machine-readable document here is checked: against the thing it describes.
 *
 * The failure this file exists to prevent is a gate that passes while describing a system
 * that no longer exists: a category resting on a suite somebody renamed, a checklist item
 * naming an npm script that was deleted, a baseline recorded once and never compared again.
 * Each of those is green in a pipeline and worthless in a review.
 */
import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
// @ts-expect-error - plain ESM scripts; two pure functions and three tables
import { collect, INVENTORY_DOC, render } from "../scripts/audit.mjs";
// @ts-expect-error - same
import { BASELINE_FILE, CHECKLIST, compareBaseline, FIELDS, GATE, measure, staticChecks } from "../scripts/release.mjs";
// @ts-expect-error - same
import { STEPS } from "../scripts/clean-clone.mjs";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const pkg = JSON.parse(read("package.json")) as {
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

describe("the dependency inventory and the freeze (points 111, 112)", () => {
  it("is generated from the tree, deterministically", () => {
    const tree = collect();
    expect(render(tree)).toBe(render(collect()));
  });

  it("is committed, and describes this tree", () => {
    // The same comparison `npm run audit:inventory` makes, so a stale inventory fails the
    // test suite too and not only the audit.
    expect(read(INVENTORY_DOC)).toBe(render(collect()));
  });

  it("records purpose, security relevance, network behaviour and replacement for every direct dependency", () => {
    const doc = read(INVENTORY_DOC);
    for (const name of [...Object.keys(pkg.dependencies), ...Object.keys(pkg.devDependencies)]) {
      const section = doc.slice(doc.indexOf(`### \`${name}\``));
      expect(section.length, `${name} has no reviewed section`).toBeGreaterThan(0);
      const body = section.slice(0, section.indexOf("###", 3));
      for (const field of ["Purpose", "Security relevance", "Network behaviour", "Replacement possibility"]) {
        expect(body, `${name}: ${field}`).toContain(`| ${field} |`);
      }
    }
  });

  it("changes its freeze digest when any version changes, transitive included", () => {
    const tree = collect();
    const before = render(tree).match(/^FREEZE (\S+)$/m)?.[1];
    const transitive = tree.packages.findIndex((entry: { direct: boolean }) => !entry.direct);
    expect(transitive).toBeGreaterThan(-1);
    tree.packages[transitive].version = "0.0.0-not-the-version-we-locked";
    const after = render(tree).match(/^FREEZE (\S+)$/m)?.[1];
    expect(after).not.toBe(before);
  });

  it("runs on every push, folded into the audit nobody has to remember", () => {
    expect(pkg.scripts.audit).toContain("audit:inventory");
    expect(pkg.scripts["audit:inventory"]).toBe("node scripts/audit.mjs inventory");
    expect(pkg.scripts["inventory:update"]).toContain("--update");
  });
});

describe("the security baseline (point 139)", () => {
  const baseline = JSON.parse(read(BASELINE_FILE)) as Record<string, unknown>;

  it("records every field the gate measures, and a date", () => {
    expect(baseline.recorded).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    for (const field of FIELDS as Array<{ key: string }>) {
      expect(baseline[field.key], `${field.key} is not recorded`).toBeDefined();
    }
  });

  it("still matches this tree", () => {
    const { failures } = compareBaseline(measure(), baseline);
    expect(failures, "the security surface of this commit is wider than the recorded baseline").toEqual([]);
  });

  it("fails on an expansion and merely notes a contraction", () => {
    const measured = measure();
    const grown = { ...measured, productionPackages: measured.productionPackages - 1 };
    expect(compareBaseline(measured, grown).failures.join()).toContain("productionPackages");
    const shrunk = { ...measured, productionPackages: measured.productionPackages + 1 };
    expect(compareBaseline(measured, shrunk).failures).toEqual([]);
    expect(compareBaseline(measured, shrunk).drift.join()).toContain("productionPackages");
  });

  it("fails when a port appears, and when a header disappears", () => {
    const measured = measure();
    const withoutPort = { ...measured, publishedPorts: [] };
    expect(compareBaseline(measured, withoutPort).failures.join()).toContain("publishedPorts");

    const extraHeader = {
      ...measured,
      securityHeaders: [...measured.securityHeaders, "x-a-header-we-used-to-send"],
    };
    expect(compareBaseline(measured, extraHeader).failures.join()).toContain("securityHeaders");
  });

  it("measures the real values, not remembered ones", () => {
    const measured = measure();
    // Spot-checks against the files themselves: if either of these stops being true, the
    // measurement is reading the wrong thing and the whole comparison is theatre.
    expect(measured.directProductionDependencies).toBe(Object.keys(pkg.dependencies).length);
    expect(measured.publishedPorts.every((entry: string) => entry.startsWith("proxy "))).toBe(true);
    expect(measured.securityHeaders).toContain("content-security-policy");
    expect(measured.storageLimits).toContain("bucket:upload_bytes");
    expect(measured.loggingRedactions).toContain("shape:secret");
  });

  it("is compared on every push, not only by hand", () => {
    expect(pkg.scripts.audit).toContain("audit:baseline");
  });
});

describe("the release gate (points 138, 140)", () => {
  it("covers every area the final gate names", () => {
    const areas = (GATE as Array<[string, string, string]>).map(([area]) => area);
    expect(areas).toEqual([
      "ARCHITECTURE",
      "SECURITY",
      "PRIVACY",
      "AUTH",
      "CRYPTO",
      "DATABASE",
      "STORAGE",
      "NETWORK",
      "CONTAINER",
      "BACKUP",
      "DEPENDENCY",
      "CLEAN-CLONE",
      "COST",
      "REGRESSION",
    ]);
  });

  it("names evidence that exists: every suite and every npm script", () => {
    const missing: string[] = [];
    for (const [label, , evidence] of [...GATE, ...CHECKLIST] as Array<[string, string, string]>) {
      for (const suite of evidence.match(/test\/[a-z_]+\.test\.ts/g) ?? []) {
        if (!existsSync(new URL(`../${suite}`, import.meta.url))) missing.push(`${label}: ${suite}`);
      }
      for (const script of evidence.match(/\baudit:[a-z]+\b|\bbackup:drill\b/g) ?? []) {
        if (!pkg.scripts[script]) missing.push(`${label}: npm run ${script}`);
      }
    }
    expect(missing, "the gate points at things that do not exist").toEqual([]);
  });

  it("has a command, and a documented procedure", () => {
    expect(pkg.scripts.release).toBe("node scripts/release.mjs");
    expect(pkg.scripts["verify:clean-clone"]).toBe("node scripts/clean-clone.mjs");
    const doc = read("docs/RELEASE.md");
    for (const [item] of CHECKLIST as Array<[string, string, string]>) {
      expect(doc, `docs/RELEASE.md does not mention "${item}"`).toContain(item);
    }
    for (const [area] of GATE as Array<[string, string, string]>) {
      expect(doc, `docs/RELEASE.md does not mention ${area}`).toContain(area);
    }
  });

  it("passes its own static checks on this tree", () => {
    const failed = (staticChecks() as Array<{ name: string; ok: boolean; detail: string }>)
      .filter((check) => !check.ok)
      .map((check) => `${check.name}: ${check.detail}`);
    expect(failed).toEqual([]);
  });

  it("has a static check for the things point 134 forbids", () => {
    const names = (staticChecks() as Array<{ name: string }>).map((check) => check.name).join(" | ");
    expect(names).toContain("master credential");
    expect(names).toContain("break-glass");
    expect(names).toContain("development or debug route");
    expect(names).toContain("credential in a file an operator deploys");
  });
});

describe("the clean-clone gate (point 109)", () => {
  it("runs install, checks, build, tests and audits, in that order", () => {
    const labels = (STEPS as Array<[string, unknown]>).map(([label]) => label);
    expect(labels).toEqual(["npm ci", "lint and types", "build", "tests", "audits"]);
  });

  it("takes the remote from git rather than from a host written into the source", () => {
    const script = read("scripts/clean-clone.mjs");
    expect(script).toContain("remote");
    // The same rule `audit:cost` and `audit:egress` enforce over src/ and scripts/: no
    // literal host. Asserted here too, because this is the one script whose whole job is
    // to talk to a remote.
    const literalHost = /["'`](?:https?|ssh|git):\/\/(?!localhost|127\.0\.0\.1)[a-z0-9-]+\.[a-z]/i;
    expect(literalHost.test(script)).toBe(false);
  });

  it("is not counted as passed when it did not run", () => {
    const script = read("scripts/release.mjs");
    expect(script).toContain("NOT RUN");
    // The gate exits non-zero on a category that did not run, which is the whole point.
    expect(script).toContain("NOT production-ready");
  });
});
