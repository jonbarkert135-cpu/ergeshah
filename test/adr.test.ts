/**
 * Points 92, 93, 94 and 95: the process documents, checked the way every other document
 * here is checked — against the thing they describe, so that "we keep ADRs" and "we ask
 * whether a change reduced security" are properties of the repository rather than of
 * somebody's memory.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

/** GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens. */
function anchor(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\w\- ]/gu, "")
    .replace(/ /g, "-");
}

interface Record_ {
  number: number;
  heading: string;
  body: string;
}

function records(): Record_[] {
  const doc = read("docs/DECISIONS.md");
  const parts = doc.split(/^## (ADR-\d{4}[^\n]*)$/m).slice(1);
  const found: Record_[] = [];
  for (let i = 0; i < parts.length; i += 2) {
    const heading = (parts[i] as string).trim();
    found.push({
      number: Number(heading.slice(4, 8)),
      heading,
      body: parts[i + 1] as string,
    });
  }
  return found;
}

function indexedNumbers(): Map<number, string> {
  const index = read("docs/adr/README.md");
  const rows = new Map<number, string>();
  for (const row of index.matchAll(/\[ADR-(\d{4})\]\(\.\.\/DECISIONS\.md#([a-z0-9_-]+)\)/g)) {
    rows.set(Number(row[1]), row[2] as string);
  }
  return rows;
}

describe("the ADR index (point 94)", () => {
  it("lists every record exactly once", () => {
    const all = records();
    expect(all.length).toBeGreaterThan(40);
    const indexed = indexedNumbers();
    const missing = all.filter((record) => !indexed.has(record.number)).map((r) => r.number);
    expect(missing, "add these to docs/adr/README.md").toEqual([]);

    const index = read("docs/adr/README.md");
    for (const record of all) {
      const occurrences = index.split(`[ADR-${String(record.number).padStart(4, "0")}]`).length - 1;
      expect(occurrences, `ADR-${record.number} appears ${occurrences} times`).toBe(1);
    }
  });

  it("links to records that exist, with anchors that resolve", () => {
    const byAnchor = new Map(records().map((record) => [anchor(record.heading), record.number]));
    for (const [number, target] of indexedNumbers()) {
      expect(byAnchor.get(target), `docs/adr/README.md links to #${target}`).toBe(number);
    }
  });

  it("keeps the template every record since ADR-0011 uses", () => {
    for (const record of records().filter((entry) => entry.number >= 11)) {
      for (const section of ["**Status:**", "**Context", "**Decision"]) {
        expect(record.body, `ADR-${record.number} has no ${section}`).toContain(section);
      }
      // The closing section says what the decision costs. ADR-0022 spells that out as
      // "What it costs, stated rather than hidden", which is the same obligation met with
      // a better sentence, so the check accepts either heading.
      expect(record.body, `ADR-${record.number} does not say what it costs`).toMatch(
        /\*\*(Consequences|What it costs)/,
      );
    }
  });

  it("never removes a superseded record, it marks it", () => {
    const superseded = records().find((record) => record.number === 2);
    expect(superseded?.heading).toMatch(/superseded/i);
    expect(records().find((record) => record.number === 22)?.body).toMatch(/supersed/i);
  });
});

describe("the two questions every change answers (points 92, 93, 95)", () => {
  const doc = read("docs/CHANGE_REVIEW.md");

  it("asks both, in the words the brief uses", () => {
    expect(doc).toMatch(/did this change reduce security\?/i);
    expect(doc).toMatch(/did this change create a performance regression\?/i);
    // And says what to do about a yes, which is the half that is usually missing.
    expect(doc).toMatch(/redesign/i);
    expect(doc).toMatch(/optimise without weakening security/i);
  });

  it("carries the priority order, in order", () => {
    const ladder = [
      "cryptographic correctness",
      "security",
      "privacy",
      "data integrity",
      "authorization",
      "reliability",
      "performance",
      "maintainability",
      "user experience",
      "visual effects",
    ];
    // Only inside the ladder itself: "security" appears all over the two questions above it.
    const section = doc.slice(doc.indexOf("## 3. When two requirements conflict")).toLowerCase();
    const positions = ladder.map((item) => section.indexOf(`**${item}**`));
    for (const [index, position] of positions.entries()) {
      expect(position, `${ladder[index]} is missing from the ladder`).toBeGreaterThan(-1);
    }
    expect(positions, "the ladder is out of order").toEqual([...positions].sort((a, b) => a - b));
  });

  it("is where the working documents point", () => {
    for (const path of ["AGENTS.md", "CONTRIBUTING.md", "docs/README.md"]) {
      expect(read(path), path).toContain("CHANGE_REVIEW.md");
    }
  });
});
