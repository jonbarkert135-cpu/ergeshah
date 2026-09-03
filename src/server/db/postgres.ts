import pg from "pg";
import { toPostgresPlaceholders, type Db } from "./index.ts";

/**
 * Ceilings the database enforces itself (point 86). A query that runs for a minute is a
 * bug or an attack either way, and the request that started it is long gone; the same is
 * true of a transaction left open, which holds a connection and blocks vacuum. Both are
 * cheaper to stop here than to notice on a graph.
 */
export function poolOptions(connectionString: string, statementTimeoutMs: number): pg.PoolConfig {
  return {
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    /** Waiting for a free connection is bounded too, so a burst fails fast instead of piling up. */
    connectionTimeoutMillis: 5_000,
    statement_timeout: statementTimeoutMs,
    idle_in_transaction_session_timeout: statementTimeoutMs,
  };
}

/** PostgreSQL driver. Same SQL as SQLite; only placeholders differ. */
export function createPostgresDb(connectionString: string, statementTimeoutMs = 5_000): Db {
  const pool = new pg.Pool(poolOptions(connectionString, statementTimeoutMs));
  return fromExecutor(
    async (sql, params) => (await pool.query(toPostgresPlaceholders(sql), params)).rows,
    async () => {
      const client = await pool.connect();
      return {
        exec: async (sql: string, params: unknown[]) =>
          (await client.query(toPostgresPlaceholders(sql), params)).rows,
        release: () => client.release(),
      };
    },
    async () => {
      await pool.end();
    },
  );
}

type Executor = (sql: string, params: unknown[]) => Promise<Record<string, unknown>[]>;

function fromExecutor(
  exec: Executor,
  checkout: () => Promise<{ exec: Executor; release: () => void }>,
  close: () => Promise<void>,
): Db {
  const build = (run: Executor, transactional: boolean): Db => ({
    dialect: "postgres",
    async all<T>(sql: string, params: unknown[] = []): Promise<T[]> {
      return (await run(sql, params)) as T[];
    },
    async get<T>(sql: string, params: unknown[] = []): Promise<T | null> {
      const rows = await run(sql, params);
      return (rows[0] as T | undefined) ?? null;
    },
    async run(sql: string, params: unknown[] = []): Promise<void> {
      await run(sql, params);
    },
    async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      if (transactional) return fn(build(run, true));
      const client = await checkout();
      try {
        await client.exec("BEGIN", []);
        const result = await fn(build(client.exec, true));
        await client.exec("COMMIT", []);
        return result;
      } catch (error) {
        await client.exec("ROLLBACK", []).catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
    close,
  });
  return build(exec, false);
}
