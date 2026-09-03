/**
 * Which database the suite runs against.
 *
 * By default: SQLite in memory — no server, no cleanup, fast enough that nobody skips the
 * tests. Set `TEST_DATABASE_URL` and the same 468 tests run against a real PostgreSQL
 * instead. Both drivers are shipped, so both are tested; a driver that is only exercised
 * by hand is a driver that works until the day somebody deploys it (`docs/SELF_CRITIQUE.md`,
 * finding 5).
 *
 * Isolation on PostgreSQL is a schema per server, not a database per server: `CREATE
 * DATABASE` cannot run inside a transaction, takes a lock on the template and costs
 * hundreds of milliseconds, while a schema costs one statement. Every test server gets its
 * own `search_path`, so two servers in the same file see two empty schemas, exactly as two
 * `:memory:` files do — which is what `test/environments.test.ts` asserts.
 */
import { randomUUID } from "node:crypto";
import type { Db } from "../src/server/db/index.ts";
import { createSqliteDb } from "../src/server/db/sqlite.ts";

const url = process.env.TEST_DATABASE_URL ?? "";

export const TEST_DIALECT: "sqlite" | "postgres" = url ? "postgres" : "sqlite";

export interface TestDatabase {
  db: Db;
  /** Releases the schema. A no-op on SQLite, where closing the handle frees everything. */
  drop(): Promise<void>;
}

export async function createTestDatabase(): Promise<TestDatabase> {
  if (!url) return { db: createSqliteDb(":memory:"), drop: async () => {} };

  const schema = `test_${randomUUID().replaceAll("-", "")}`;
  const pg = (await import("pg")).default;
  const admin = new pg.Client(url);
  await admin.connect();
  // The name is generated here from a UUID, never from test input, and PostgreSQL has no
  // placeholder for an identifier — hence the interpolation, with the shape asserted.
  if (!/^test_[0-9a-f]{32}$/.test(schema)) throw new Error("generated schema name is not safe");
  await admin.query(`CREATE SCHEMA ${schema}`);
  await admin.end();

  const { createPostgresDb } = await import("../src/server/db/postgres.ts");
  const db = createPostgresDb(withSchema(url, schema));
  return {
    db,
    async drop() {
      const cleaner = new pg.Client(url);
      await cleaner.connect();
      await cleaner.query(`DROP SCHEMA ${schema} CASCADE`);
      await cleaner.end();
    },
  };
}

/**
 * `options=-c search_path=…` is how libpq carries a startup parameter, and `pg` passes the
 * query string through. Every connection the pool opens lands in the right schema,
 * including the ones it opens later to replace an idle one.
 */
function withSchema(connectionString: string, schema: string): string {
  const parsed = new URL(connectionString);
  parsed.searchParams.set("options", `-c search_path=${schema}`);
  return parsed.toString();
}

/**
 * Schema introspection that works on both drivers.
 *
 * Several tests read the schema rather than the data — "no table has a column that could
 * hold an address", "every table is documented" — and `sqlite_master` and `PRAGMA
 * table_info` are SQLite-only. These two helpers ask the same question in whichever
 * dialect is running.
 */
export async function listTables(db: Db): Promise<string[]> {
  const rows =
    db.dialect === "postgres"
      ? await db.all<{ name: string }>(
          "SELECT tablename AS name FROM pg_tables WHERE schemaname = current_schema()",
        )
      : await db.all<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        );
  return rows.map((row) => row.name).sort();
}

export async function listColumns(db: Db, table: string): Promise<string[]> {
  if (!/^[a-z_][a-z0-9_]*$/.test(table)) throw new Error(`not a table name: ${table}`);
  const rows =
    db.dialect === "postgres"
      ? await db.all<{ name: string }>(
          "SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? ORDER BY ordinal_position",
          [table],
        )
      : // audit:allow — the name is validated above and comes from listTables, never from input.
        await db.all<{ name: string }>(`PRAGMA table_info(${table})`);
  return rows.map((row) => row.name);
}
