/**
 * Migration verification (point 32). The static half — ordering, naming, checksums of
 * released migrations — is `npm run audit:migrations`. This is the half that needs a
 * database: that the files actually apply to an empty one, that applying them twice is a
 * no-op, and that the schema they produce is the schema the code expects.
 */
import { describe, expect, it } from "vitest";
import { createSqliteDb } from "../src/server/db/sqlite.ts";
import { migrate } from "../src/server/db/migrate.ts";

async function freshDatabase() {
  const db = createSqliteDb(":memory:");
  const applied = await migrate(db);
  return { db, applied };
}

describe("migrations apply to an empty database", () => {
  it("creates every table the application reads", async () => {
    const { db, applied } = await freshDatabase();
    expect(applied.length).toBeGreaterThan(0);

    const tables = (
      await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")
    ).map((row) => row.name);

    for (const table of [
      "users",
      "sessions",
      "devices",
      "vaults",
      "one_time_prekeys",
      "deliveries",
      "rate_limits",
      "envelopes",
      "listings",
      "orders",
      "reviews",
      "reports",
      "seller_applications",
      "audit_log",
      "schema_migrations",
    ]) {
      expect(tables, table).toContain(table);
    }
    await db.close();
  });

  it("is idempotent: a second run applies nothing and changes nothing", async () => {
    const db = createSqliteDb(":memory:");
    const first = await migrate(db);
    const schemaAfterFirst = await db.all("SELECT type, name, sql FROM sqlite_master ORDER BY name");

    const second = await migrate(db);
    expect(second).toEqual([]);
    expect(first.length).toBeGreaterThan(0);

    const schemaAfterSecond = await db.all("SELECT type, name, sql FROM sqlite_master ORDER BY name");
    expect(schemaAfterSecond).toEqual(schemaAfterFirst);
    await db.close();
  });

  it("records what it applied, so a half-finished deploy is visible", async () => {
    const { db, applied } = await freshDatabase();
    const recorded = (
      await db.all<{ name: string }>("SELECT name FROM schema_migrations ORDER BY name")
    ).map((row) => row.name);
    expect(recorded).toEqual([...applied].sort());
    await db.close();
  });

  it("indexes the columns every hot query filters on", async () => {
    // Missing indexes are a denial-of-service surface, not only a performance question:
    // an unindexed lookup on a growing table is an expensive operation an attacker can
    // trigger for free (point 27).
    const { db } = await freshDatabase();
    const indexed = (
      await db.all<{ name: string; tbl_name: string; sql: string | null }>(
        "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'index'",
      )
    )
      .map((row) => `${row.tbl_name}:${row.sql ?? ""}`)
      .join("\n");

    for (const [table, column] of [
      ["sessions", "user_id"],
      ["envelopes", "recipient_id"],
      ["orders", "buyer_id"],
      ["listings", "seller_id"],
      ["audit_log", "created_at"],
      ["orders", "listing_id"],
      ["reports", "target_type"],
    ] as const) {
      expect(indexed, `${table}.${column}`).toMatch(new RegExp(`${table}[^\\n]*${column}`, "i"));
    }
    await db.close();
  });
});
