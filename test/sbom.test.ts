/**
 * OPS-3 (the SBOM half): a machine-readable bill of materials, generated from the lockfile
 * and frozen. These tests are the freeze — the committed `docs/sbom.cdx.json` must describe
 * the same tree the lockfile does, in a shape a scanner (OSV-Scanner, Trivy, Dependency-Track)
 * will accept — so a dependency that arrives without regenerating the SBOM fails here.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
// @ts-expect-error - plain ESM script, no types
import { generate, serialise, SBOM_DOC } from "../scripts/sbom.mjs";
// @ts-expect-error - same
import { collect } from "../scripts/audit-inventory.mjs";

const committed = () => readFileSync(new URL(`../${SBOM_DOC}`, import.meta.url), "utf8");

describe("the SBOM is a valid CycloneDX document", () => {
  const doc = JSON.parse(committed());

  it("declares the format the scanners read", () => {
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.5");
    expect(doc.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });

  it("names this application as the subject, not a dependency", () => {
    expect(doc.metadata.component.name).toBe("symvolon");
    expect(doc.metadata.component.type).toBe("application");
  });

  it("gives every component a purl and a scope", () => {
    expect(doc.components.length).toBeGreaterThan(20);
    for (const component of doc.components) {
      expect(component.purl, `${component.name} has no purl`).toMatch(/^pkg:npm\//);
      expect(["required", "optional"]).toContain(component.scope);
    }
  });

  it("scopes a development-only package as optional", () => {
    const esbuild = doc.components.find((c: { name: string }) => c.name === "esbuild");
    expect(esbuild?.scope).toBe("optional");
  });
});

describe("the SBOM describes the tree the lockfile describes", () => {
  it("has one component per lockfile package, at the same version", () => {
    const doc = JSON.parse(committed());
    const inTree = new Set(collect().packages.map((p: { name: string; version: string }) => `${p.name}@${p.version}`));
    const inSbom = new Set(doc.components.map((c: { name: string; version: string }) => `${c.name}@${c.version}`));
    expect([...inTree].filter((entry) => !inSbom.has(entry)), "missing from the SBOM").toEqual([]);
    expect([...inSbom].filter((entry) => !inTree.has(entry)), "in the SBOM but not the tree").toEqual([]);
  });

  it("is frozen: the committed file matches what the lockfile generates today", () => {
    expect(committed()).toBe(serialise(generate()));
  });
});
