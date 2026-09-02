import pg from "pg";
import { toPostgresPlaceholders, type Db } from "./index.ts";

/** PostgreSQL driver. Same SQL as SQLite; only placeholders differ. */
export function createPostgresDb(connectionString: string): Db {
  const pool = new pg.Pool({ connectionString, max: 10, idleTimeoutMillis: 30_000 });
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
