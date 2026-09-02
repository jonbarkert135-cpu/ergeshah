import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Db } from "./index.ts";

/** SQLite driver built on Node's bundled `node:sqlite` — no native build step on the VPS. */
export function createSqliteDb(path: string): Db {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const handle = new DatabaseSync(path);
  handle.exec("PRAGMA journal_mode = WAL");
  handle.exec("PRAGMA foreign_keys = ON");
  handle.exec("PRAGMA busy_timeout = 5000");
  return wrap(handle, false);
}

function normalise(params: unknown[]): unknown[] {
  return params.map((value) => {
    if (typeof value === "boolean") return value ? 1 : 0;
    if (value === undefined) return null;
    return value;
  });
}

/**
 * One writer at a time, per connection.
 *
 * `node:sqlite` is synchronous, but the handlers around it are not: a transaction body
 * that awaits anything gives the event loop a chance to run another request, and that
 * request's `BEGIN IMMEDIATE` lands inside the first transaction. SQLite answers
 * "cannot start a transaction within a transaction" (a 500 under concurrency) and, worse,
 * the interleaved statements that *do* run share one transaction — a rollback in one
 * request would discard another request's writes. PostgreSQL does not have this problem
 * because each transaction checks out its own pooled client; SQLite has one handle, so
 * transactions are queued on it instead. Nested calls do not queue: they reuse the open
 * transaction, which is what `inTransaction` already means.
 */
function wrap(handle: DatabaseSync, inTransaction: boolean): Db {
  let queue: Promise<unknown> = Promise.resolve();
  const db: Db = {
    dialect: "sqlite",
    async all<T>(sql: string, params: unknown[] = []): Promise<T[]> {
      return handle.prepare(sql).all(...(normalise(params) as never[])) as T[];
    },
    async get<T>(sql: string, params: unknown[] = []): Promise<T | null> {
      const row = handle.prepare(sql).get(...(normalise(params) as never[]));
      return (row as T | undefined) ?? null;
    },
    async run(sql: string, params: unknown[] = []): Promise<void> {
      handle.prepare(sql).run(...(normalise(params) as never[]));
    },
    async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
      if (inTransaction) return fn(db);
      const attempt = queue.then(async () => {
        handle.exec("BEGIN IMMEDIATE");
        try {
          const result = await fn(wrap(handle, true));
          handle.exec("COMMIT");
          return result;
        } catch (error) {
          handle.exec("ROLLBACK");
          throw error;
        }
      });
      // The queue must survive a failed transaction, so it tracks completion, not success.
      queue = attempt.catch(() => undefined);
      return attempt;
    },
    async close(): Promise<void> {
      handle.close();
    },
  };
  return db;
}
