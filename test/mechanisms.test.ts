/**
 * Points 96, 97 and 98: no mechanism without a threat, no security technology because it
 * sounds impressive, and a bar the architecture has to clear.
 *
 * `docs/MECHANISMS.md` is the register; this file is what stops it becoming a wish list.
 * The free-space floor is here too, because it is the one mechanism whose row would
 * otherwise name no test of its own.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { requireSpaceFor, resetStorageCache } from "../src/server/lib/storage.ts";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (path: string) => readFileSync(`${root}${path}`, "utf8");

interface Row {
  mechanism: string;
  threat: string;
  property: string;
  implementation: string;
  test: string;
  failureMode: string;
}

function register(): Row[] {
  const table = read("docs/MECHANISMS.md")
    .split("\n")
    .filter((line) => line.startsWith("| ") && !line.startsWith("| ---") && !line.startsWith("| Mechanism"));
  return table.map((line) => {
    const cells = line.replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim());
    const [mechanism, threat, property, implementation, test, failureMode] = cells;
    return {
      mechanism: mechanism ?? "",
      threat: threat ?? "",
      property: property ?? "",
      implementation: (implementation ?? "").replace(/`/g, ""),
      test: (test ?? "").replace(/`/g, ""),
      failureMode: failureMode ?? "",
    };
  });
}

describe("every mechanism answers the six questions (point 97)", () => {
  const rows = register();

  it("has a register with substance", () => {
    expect(rows.length).toBeGreaterThanOrEqual(20);
  });

  it("fills in all six columns for every one", () => {
    for (const row of rows) {
      for (const [name, value] of Object.entries(row)) {
        expect(value.length, `${row.mechanism}: ${name} is empty`).toBeGreaterThan(3);
      }
    }
  });

  it("names an implementation and a test that exist", () => {
    for (const row of rows) {
      expect(existsSync(`${root}${row.implementation}`), `${row.mechanism} → ${row.implementation}`).toBe(true);
      expect(existsSync(`${root}${row.test}`), `${row.mechanism} → ${row.test}`).toBe(true);
    }
  });

  it("covers the mechanisms that carry the most weight", () => {
    const all = rows.map((row) => row.mechanism.toLowerCase()).join(" | ");
    for (const expected of ["ratchet", "argon2id", "csrf", "content-security-policy", "token buckets", "proof of work"]) {
      expect(all, expected).toContain(expected);
    }
  });
});

describe("the quality bar (point 98)", () => {
  it("maps every prohibition to the check that enforces it", () => {
    const doc = read("docs/CHANGE_REVIEW.md");
    const section = doc.slice(doc.indexOf("## 5. The bar"));
    for (const prohibition of [
      "hardcoded secrets",
      "plaintext passwords",
      "plaintext private messages",
      "unnecessary telemetry",
      "insecure defaults",
      "giant",
      "undocumented cryptographic assumptions",
      "fake privacy claims",
      "dependency chaos",
      "security theatre",
    ]) {
      expect(section.toLowerCase(), prohibition).toContain(prohibition);
    }
  });

  it("says which solution to pick when two are on the table (point 96)", () => {
    const doc = read("docs/CHANGE_REVIEW.md").toLowerCase();
    const section = doc.slice(doc.indexOf("## 4."));
    expect(section).toContain("audited");
    expect(section).toContain("homemade");
    expect(section).toContain("vps");
  });

  it("carries the cycle, in order (point 100)", () => {
    const doc = read("docs/CHANGE_REVIEW.md").toLowerCase();
    const section = doc.slice(doc.indexOf("## 6."));
    const stages = [
      "research",
      "threat model",
      "architecture",
      "plan",
      "implement",
      "test",
      "security review",
      "privacy review",
      "performance review",
      "code review",
      "document",
      "reassess",
      "improve",
    ];
    const positions = stages.map((stage) => section.indexOf(`**${stage}**`));
    for (const [index, position] of positions.entries()) {
      expect(position, `${stages[index]} is missing from the cycle`).toBeGreaterThan(-1);
    }
    expect(positions, "the cycle is out of order").toEqual([...positions].sort((a, b) => a - b));
  });
});

describe("the free-space floor", () => {
  it("refuses a write that would land on a nearly full filesystem", async () => {
    resetStorageCache();
    // The floor is larger than any disk this runs on, so the check must refuse.
    await expect(requireSpaceFor(root, 1_000, Number.MAX_SAFE_INTEGER - 1)).rejects.toMatchObject({
      statusCode: 503,
      code: "storage_full",
    });
  });

  it("allows a write with room to spare, and is disabled by a floor of zero", async () => {
    resetStorageCache();
    await expect(requireSpaceFor(root, 1_000, 1)).resolves.toBeUndefined();
    resetStorageCache();
    await expect(requireSpaceFor("/nonexistent-path-for-a-test", 1_000, 0)).resolves.toBeUndefined();
  });

  it("does not refuse writes just because the filesystem cannot be read", async () => {
    resetStorageCache();
    // A missing path is not evidence of a full disk: the floor is a safety margin, not an
    // authorisation decision, and failing closed here would take the service down.
    await expect(
      requireSpaceFor("/nonexistent-path-for-a-test", 1_000, 1024),
    ).resolves.toBeUndefined();
  });
});

describe("self-criticism is written down (point 99)", () => {
  const doc = read("docs/SELF_CRITIQUE.md");

  it("uses the seven headings the brief asks for, for every finding", () => {
    const findings = doc.split(/^## /m).slice(2);
    expect(findings.length).toBeGreaterThanOrEqual(5);
    for (const finding of findings) {
      for (const heading of [
        "**Why it matters.**",
        "**Severity:**",
        "**Attack scenario.**",
        "**Proposed fix.**",
        "**Implementation.**",
        "**Verification.**",
      ]) {
        expect(finding, `${finding.split("\n")[0]} is missing ${heading}`).toContain(heading);
      }
    }
  });

  it("grades severity from a fixed vocabulary", () => {
    for (const [, severity] of doc.matchAll(/\*\*Severity:\*\*\s*([a-z]+)/g)) {
      expect(["low", "medium", "high", "critical"]).toContain(severity);
    }
  });
});
