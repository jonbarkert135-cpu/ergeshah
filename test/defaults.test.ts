/**
 * Privacy by default (point 35).
 *
 * The claim this file defends is narrow and checkable: **a deployment that sets nothing,
 * and a user who changes nothing, get the private behaviour.** Not "privacy mode: off",
 * not a checkbox in a settings page nobody opens. If a future change makes a protection
 * conditional, one of these fails.
 */
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { loadConfig } from "../src/server/config.ts";
import { cookiesAreSecure } from "../src/server/app.ts";
import { pad, unpad, paddedLength } from "../src/shared/crypto/padding.ts";
import { register, startTestServer } from "./helpers.ts";
import { listTables } from "./database.ts";

/** A config as a fresh deployment gets it: NODE_ENV set, nothing else. */
function defaultConfig() {
  const saved = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (/^(HOST|PORT|DB_|SQLITE_|DATABASE_|TRUST_|SESSION_|ENVELOPE_|MAX_|DELIVERY_|AUDIT_|RATE_|ONION_|BEHIND_)/.test(key)) {
      delete process.env[key];
    }
  }
  try {
    return loadConfig();
  } finally {
    Object.assign(process.env, saved);
  }
}

describe("the defaults are the private ones", () => {
  const config = defaultConfig();

  it("assumes TLS, so cookies are Secure unless someone says otherwise", () => {
    expect(config.behindTls).toBe(true);
    // The single exception is documented and narrow: a .onion origin, where there is no
    // TLS to be secure about and the transport is already authenticated and encrypted.
    const onion = { ...config, onionHostname: "a".repeat(56) + ".onion" };
    expect(cookiesAreSecure(config, { headers: { host: "example.com" } } as never)).toBe(true);
    expect(cookiesAreSecure(onion, { headers: { host: onion.onionHostname } } as never)).toBe(false);
  });

  it("does not trust proxy headers unless configured to", () => {
    // A trusted X-Forwarded-For from an untrusted proxy is a rate-limit bypass and a way
    // to write an attacker-chosen address into logs.
    expect(config.trustProxy).toBe(false);
  });

  it("binds to localhost, not to every interface", () => {
    expect(config.host).toBe("127.0.0.1");
  });

  it("expires everything it stores", () => {
    expect(config.sessionTtlMs).toBeGreaterThan(0);
    expect(config.envelopeTtlMs).toBeLessThanOrEqual(31 * 24 * 60 * 60 * 1000);
    expect(config.deliveryTtlMs).toBeLessThanOrEqual(31 * 24 * 60 * 60 * 1000);
    expect(config.auditRetentionMs).toBeLessThanOrEqual(366 * 24 * 60 * 60 * 1000);
  });

  it("rate-limits every operation class out of the box", () => {
    for (const scope of Object.values(config.rateLimits)) {
      expect(scope.burst).toBeGreaterThan(0);
      expect(scope.perMinute).toBeGreaterThan(0);
    }
  });
});

describe("protections are not settings", () => {
  it("pads every message, with no way to ask for a shorter envelope", () => {
    // Padding is applied inside the encryption path, not chosen by a caller. The exported
    // surface is pad/unpad — there is no `pad(plaintext, { enabled })`.
    expect(pad.length).toBe(1);
    for (const size of [0, 1, 63, 64, 200, 5000]) {
      const padded = pad(new Uint8Array(size));
      expect(padded.length).toBe(paddedLength(size));
      expect(unpad(padded).length).toBe(size);
    }
  });

  it("has no user-facing switch that turns a protection off", () => {
    // A grep, deliberately: the point of this rule is that nobody adds one later.
    // `git grep` exits 1 when it finds nothing, which is the outcome we want.
    let source = "";
    try {
      source = execFileSync(
        "git",
        ["grep", "-ril", "-e", "privacy mode", "-e", "incognito", "-e", "enableEncryption", "--", "src"],
        { encoding: "utf8" },
      ).trim();
    } catch (error) {
      expect((error as { status?: number }).status).toBe(1);
    }
    expect(source).toBe("");
  });

  it("gives a brand-new account the same protections as a configured one", async () => {
    const server = await startTestServer();
    try {
      const user = await register(server, "fresh-account");
      const me = await user.get<{ role: string; seller: unknown; recoveryConfigured: boolean }>(
        "/api/auth/me",
      );
      expect(me.status).toBe(200);
      // The first account bootstraps as administrator; nothing else is granted anything.
      expect(["user", "moderator", "admin"]).toContain(me.body.role);
      expect(me.body.seller).toBeNull();

      // A fresh account is not a seller, and cannot list, without an approved application.
      const listing = await user.post("/api/market/listings", {
        kind: "digital",
        title: "anything",
        description: "anything at all",
        category: "misc",
        priceMinor: 100,
      });
      expect([401, 403]).toContain(listing.status);
    } finally {
      await server.close();
    }
  });

  it("stores no address anywhere, even for the accounts it limits", async () => {
    const server = await startTestServer();
    try {
      const user = await register(server, "no-address");
      await user.get("/api/market/listings?q=x");
      const tables = await listTables(server.db);
      const dump: string[] = [];
      for (const name of tables) {
        // audit:allow — table names come from the schema itself; this test dumps it whole
        dump.push(JSON.stringify(await server.db.all(`SELECT * FROM ${name}`)));
      }
      const everything = dump.join();
      expect(everything).not.toContain("127.0.0.1");
      expect(everything).not.toContain("::1");
    } finally {
      await server.close();
    }
  });
});
