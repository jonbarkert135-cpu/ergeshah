/**
 * A deliberately small database interface.
 *
 * Two drivers implement it: SQLite (single-file, zero-dependency, good for a small VPS
 * or an onion service) and PostgreSQL (for anything larger). Application code writes
 * portable SQL with `?` placeholders; the Postgres driver rewrites them to `$n`.
 * No ORM, no query builder, no vendor lock-in — and no string interpolation of values,
 * ever: every driver call is parameterised.
 */
import type { Config } from "../config.ts";

export interface Db {
  readonly dialect: "sqlite" | "postgres";
  all<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;
  get<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T | null>;
  run(sql: string, params?: unknown[]): Promise<void>;
  transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export async function createDb(config: Config): Promise<Db> {
  if (config.dialect === "postgres") {
    if (!config.postgresUrl) throw new Error("DATABASE_URL is required for the postgres dialect");
    const { createPostgresDb } = await import("./postgres.ts");
    return createPostgresDb(config.postgresUrl, config.dbStatementTimeoutMs);
  }
  const { createSqliteDb } = await import("./sqlite.ts");
  return createSqliteDb(config.sqlitePath);
}

export function toPostgresPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/g, () => `$${(index += 1)}`);
}
