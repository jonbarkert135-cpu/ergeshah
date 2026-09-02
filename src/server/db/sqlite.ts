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

function wrap(handle: DatabaseSync, inTransaction: boolean): Db {
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
      handle.exec("BEGIN IMMEDIATE");
      try {
        const result = await fn(wrap(handle, true));
        handle.exec("COMMIT");
        return result;
      } catch (error) {
        handle.exec("ROLLBACK");
        throw error;
      }
    },
    async close(): Promise<void> {
      handle.close();
    },
  };
  return db;
}
