/**
 * Migration runner: applies every `NNN_*.sql` file in order, once, inside a transaction,
 * and records it. Runs automatically on boot so a deployment is `docker compose up`.
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Db } from "./index.ts";

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "migrations");

export async function migrate(db: Db): Promise<string[]> {
  await db.run(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       name TEXT PRIMARY KEY,
       applied_at BIGINT NOT NULL
     )`,
  );
  const applied = new Set(
    (await db.all<{ name: string }>("SELECT name FROM schema_migrations")).map((row) => row.name),
  );
  const pending = readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith(".sql"))
    .filter((name) => appliesTo(name, db.dialect))
    .sort()
    .filter((name) => !applied.has(name));

  for (const name of pending) {
    const sql = readFileSync(join(MIGRATIONS_DIR, name), "utf8");
    await db.transaction(async (tx) => {
      for (const statement of splitStatements(sql)) await tx.run(statement);
      await tx.run("INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)", [
        name,
        Date.now(),
      ]);
    });
  }
  return pending;
}

/**
 * A migration named `NNN_thing.postgres.sql` or `NNN_thing.sqlite.sql` runs on that driver
 * only; anything else runs on both. The escape hatch exists because the two databases
 * disagree about types, not about the schema: `INTEGER` is 64-bit in SQLite and 32-bit in
 * PostgreSQL, so the millisecond timestamps this application stores need `BIGINT` there and
 * nowhere else (ADR-0059). Portable SQL stays the rule — this is the exception, and a
 * dialect-scoped migration that is not about a dialect difference is a bug.
 */
function appliesTo(name: string, dialect: Db["dialect"]): boolean {
  const scoped = /\.(sqlite|postgres)\.sql$/.exec(name);
  return scoped === null || scoped[1] === dialect;
}

/** Splits on `;` at statement level. Our migrations deliberately contain no procedures. */
function splitStatements(sql: string): string[] {
  return sql
    .split("\n")
    .filter((line) => !line.trim().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}
