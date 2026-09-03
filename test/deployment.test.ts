/**
 * The deployment, checked instead of described.
 *
 * Points 63–67 are mostly prose in `docs/DEPLOYMENT.md`, `docs/HARDENING.md` and
 * `docs/NETWORK.md` — and prose is exactly the kind of security control that decays. Every
 * property those documents claim about the shipped configuration is asserted here, so the
 * failure mode of "someone removed the capability drop while debugging" is a red test
 * rather than a paragraph that is no longer true.
 *
 * This is deliberately a text-level check with a very small YAML reader rather than a
 * dependency: the file it reads is forty lines of our own configuration, and adding a
 * parser to the supply chain to inspect it would be a poor trade (ADR-0040).
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const compose = read("deploy/docker-compose.yml");
const dockerfile = read("deploy/Dockerfile");
const caddyfile = read("deploy/Caddyfile");

/** Lines of one top-level `services:` entry, comments and commented-out services excluded. */
function service(name: string): string[] {
  const lines = compose.split("\n");
  const start = lines.findIndex((line) => line.startsWith(`  ${name}:`));
  expect(start, `service ${name} is missing`).toBeGreaterThan(-1);
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^ {0,2}\S/.test(line)) break; // next service, or a top-level key
    if (!line.trim().startsWith("#") && line.trim()) body.push(line);
  }
  return body;
}

const app = service("app");
const proxy = service("proxy");
const has = (body: string[], pattern: RegExp) => body.some((line) => pattern.test(line));

describe("the application container (point 64)", () => {
  it("runs unprivileged, read-only, and cannot regain privileges", () => {
    expect(dockerfile, "the image must drop to the unprivileged node user").toContain("USER node");
    expect(has(app, /read_only:\s*true/)).toBe(true);
    expect(has(app, /cap_drop:\s*\[ALL\]/)).toBe(true);
    expect(has(app, /no-new-privileges:true/)).toBe(true);
    // Read-only means the process needs somewhere to put a temporary file, and a tmpfs is
    // that somewhere: in memory, gone on restart, never on the image.
    expect(has(app, /tmpfs:/)).toBe(true);
  });

  it("has a limit on memory, CPU and processes", () => {
    for (const key of [/mem_limit:/, /cpus:/, /pids_limit:/]) {
      expect(has(app, key), `app is missing ${key}`).toBe(true);
      expect(has(proxy, key), `proxy is missing ${key}`).toBe(true);
    }
  });

  it("declares a health check", () => {
    expect(has(app, /healthcheck:/)).toBe(true);
    expect(has(proxy, /healthcheck:/)).toBe(true);
    expect(dockerfile).toContain("HEALTHCHECK");
    expect(caddyfile, "the proxy health check needs something to answer it").toContain("/healthz");
  });

  it("builds from a base image pinned by digest, not by a tag that moves", () => {
    const froms = [...dockerfile.matchAll(/^FROM (\S+)/gm)].map((match) => match[1]!);
    expect(froms.length).toBeGreaterThanOrEqual(2);
    for (const image of froms) {
      expect(image, `${image} must be pinned by digest`).toMatch(/@sha256:[0-9a-f]{64}$/);
    }
    // Every uncommented `image:` in compose, same rule.
    for (const [, image] of compose.matchAll(/^\s{4}image:\s*(\S+)/gm)) {
      expect(image, `${image} must be pinned by digest`).toMatch(/@sha256:[0-9a-f]{64}$/);
    }
  });
});

describe("network tiers (point 66)", () => {
  it("keeps the application off the public network and gives it no egress", () => {
    // The bug this test was written for: `app` used to be on `[edge, internal]`, which
    // gave it a default gateway and therefore the internet, while its own comment and
    // docs/THREAT_MODEL.md both said it had none.
    const networks = app.find((line) => line.includes("networks:"));
    expect(networks).toContain("internal");
    expect(networks, "the application must not sit on the public-facing network").not.toContain(
      "edge",
    );
    expect(has(app, /^\s*ports:/), "the application must not publish a port").toBe(false);
  });

  it("makes the internal network internal", () => {
    expect(compose).toMatch(/internal:\s*\n\s*internal:\s*true/);
  });

  it("puts the reverse proxy on both sides, because it is the only bridge", () => {
    const networks = proxy.find((line) => line.includes("networks:"));
    expect(networks).toContain("edge");
    expect(networks).toContain("internal");
  });

  it("never publishes a database port, even in the commented-out example", () => {
    // A database reachable from the internet is the single most expensive mistake in this
    // file, so the example is not allowed to demonstrate it.
    const db = compose.slice(compose.indexOf("# db:"), compose.indexOf("# tor:"));
    expect(db).not.toMatch(/^\s*#\s*ports:/m);
    expect(db).not.toContain("5432:");
  });
});

describe("TLS (point 67)", () => {
  it("sets a modern floor explicitly", () => {
    expect(caddyfile).toMatch(/protocols\s+tls1\.2\s+tls1\.3/);
    for (const legacy of ["tls1.0", "tls1.1", "ssl3"]) {
      expect(caddyfile, `${legacy} must not be enabled`).not.toContain(legacy);
    }
  });

  it("terminates TLS at the proxy and publishes only 80 and 443", () => {
    const ports = proxy.find((line) => line.includes("ports:")) ?? "";
    expect(ports).toContain("80:80");
    expect(ports).toContain("443:443");
    // Nothing else. 8081 is the health port and must stay unpublished.
    expect(ports).not.toContain("8081");
    expect(ports).not.toContain("2019");
  });

  it("keeps the admin API off", () => {
    expect(caddyfile).toMatch(/^\s*admin off/m);
  });
});

describe("the documents that describe all this (points 63, 65, 66)", () => {
  it("exist, and say something", () => {
    for (const [path, minimumLines] of [
      ["docs/DEPLOYMENT.md", 100],
      ["docs/HARDENING.md", 80],
      ["docs/NETWORK.md", 40],
    ] as const) {
      expect(read(path).split("\n").length, path).toBeGreaterThanOrEqual(minimumLines);
    }
  });

  it("walks a fresh VPS through every step the brief lists (point 63)", () => {
    const deployment = read("docs/DEPLOYMENT.md").toLowerCase();
    for (const step of [
      "install",
      "clone",
      "configure",
      "migration",
      "start",
      "tls",
      "verify",
    ]) {
      expect(deployment, `docs/DEPLOYMENT.md does not cover "${step}"`).toContain(step);
    }
  });

  it("covers each hardening topic the brief lists (point 65)", () => {
    const hardening = read("docs/HARDENING.md").toLowerCase();
    for (const topic of [
      "ssh",
      "firewall",
      "unattended-upgrades",
      "tls",
      "backup",
      "monitor",
      "intrusion",
      "isolation",
    ]) {
      expect(hardening, `docs/HARDENING.md does not cover "${topic}"`).toContain(topic);
    }
  });
});
