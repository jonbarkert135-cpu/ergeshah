/**
 * OPS-9: the PostgreSQL backup is a command and a drill, not a paragraph.
 *
 * Runs only against a real PostgreSQL (`TEST_DATABASE_URL`) with `pg_dump` / `pg_restore` at
 * least as new as the server, because that is the only place the failure modes live: a
 * client too old to dump, an archive that lists no tables, a restore over a database that is
 * not empty, a service that cannot find the restored schema. Skipped elsewhere, and says so.
 *
 * The source database mirrors a real deployment (`deploy/postgres-roles.sql`): the tables
 * live in a schema named `symvolon`, not in `public`, so the drill has to carry the
 * `search_path` or boot on an empty schema — which is the bug this test would catch.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { migrate } from "../src/server/db/migrate.ts";
import { TEST_DIALECT } from "./database.ts";

const script = new URL("../scripts/backup-postgres.mjs", import.meta.url).pathname;
const adminUrl = process.env.TEST_DATABASE_URL ?? "";

/** `pg_dump --version` → major, or 0 when the tool is missing. */
function clientMajor(): number {
  const result = spawnSync(process.env.PG_DUMP ?? "pg_dump", ["--version"], { encoding: "utf8" });
  const match = /\(PostgreSQL\) (\d+)/.exec(result.stdout ?? "");
  return match ? Number(match[1]) : 0;
}

async function serverMajor(): Promise<number> {
  const pg = (await import("pg")).default;
  const client = new pg.Client(adminUrl);
  await client.connect();
  try {
    const { rows } = await client.query("SHOW server_version");
    return Number(String(rows[0]!.server_version).split(".")[0]);
  } finally {
    await client.end();
  }
}

let usable = TEST_DIALECT === "postgres";
let reason = "TEST_DATABASE_URL is not set";
if (usable) {
  const client = clientMajor();
  const server = await serverMajor();
  if (client === 0) {
    usable = false;
    reason = "pg_dump is not installed (set PG_DUMP to point at it)";
  } else if (client < server) {
    usable = false;
    reason = `pg_dump ${client} is older than the server (${server}) and would refuse to dump it`;
  }
}
if (TEST_DIALECT === "postgres" && !usable) {
  // Loud, because on PostgreSQL this suite is the only proof the backup path works.
  console.warn(`backup_postgres: SKIPPED — ${reason}`);
}

function withDatabase(name: string, options?: string): string {
  const url = new URL(adminUrl);
  url.pathname = `/${name}`;
  if (options) url.searchParams.set("options", options);
  else url.searchParams.delete("options");
  return url.toString();
}

async function adminQuery(sql: string): Promise<void> {
  const pg = (await import("pg")).default;
  const client = new pg.Client(adminUrl);
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

function run(args: string[], env: Record<string, string> = {}): string {
  return execFileSync(process.execPath, [script, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

describe.skipIf(!usable)("PostgreSQL backups", () => {
  const suffix = randomBytes(6).toString("hex");
  const sourceDb = `symvolon_bk_src_${suffix}`;
  const targetDb = `symvolon_bk_dst_${suffix}`;
  let workspace = "";
  let keyPath = "";
  let sourceUrlFile = "";
  let adminUrlFile = "";

  beforeAll(async () => {
    workspace = mkdtempSync(join(tmpdir(), "symvolon-pgbackup-"));
    keyPath = join(workspace, "backup.key");
    writeFileSync(keyPath, randomBytes(32).toString("base64"));

    // A source that looks like production: its own database, tables in schema `symvolon`.
    await adminQuery(`CREATE DATABASE ${sourceDb} TEMPLATE template0`);
    const sourceUrl = withDatabase(sourceDb, "-c search_path=symvolon");
    const pg = (await import("pg")).default;
    const setup = new pg.Client(withDatabase(sourceDb));
    await setup.connect();
    await setup.query("CREATE SCHEMA symvolon");
    await setup.end();
    const { createPostgresDb } = await import("../src/server/db/postgres.ts");
    const db = createPostgresDb(sourceUrl);
    await migrate(db);
    await db.run(
      "INSERT INTO users (id, username, password_hash, role, status, created_day) VALUES ('pgbackupuser1', 'pgbackupuser', 'hash', 'user', 'active', 1)",
    );
    await db.close();

    sourceUrlFile = join(workspace, "source.url");
    writeFileSync(sourceUrlFile, sourceUrl);
    adminUrlFile = join(workspace, "admin.url");
    writeFileSync(adminUrlFile, adminUrl);
  }, 60_000);

  afterAll(async () => {
    rmSync(workspace, { recursive: true, force: true });
    await adminQuery(`DROP DATABASE IF EXISTS ${sourceDb} WITH (FORCE)`);
    await adminQuery(`DROP DATABASE IF EXISTS ${targetDb} WITH (FORCE)`);
  });

  it("writes an encrypted, verified, timestamped archive and no plaintext", () => {
    const out = join(workspace, "backups");
    const output = run(["create", "--key", keyPath, "--url-file", sourceUrlFile, "--out", out]);
    expect(output).toMatch(/verified before writing: archive lists \d+ tables in schema symvolon/);
    expect(output).toMatch(/1 accounts/);
    const files = readdirSync(out);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^symvolon-\d{4}-\d{2}-\d{2}T\d{6}Z\.pgdump\.enc$/);
    const bytes = readFileSync(join(out, files[0]!));
    expect(bytes.subarray(0, 8).toString()).toBe("SYMVPG1\n");
    // Neither the archive's own magic nor a username is in the file in the clear.
    expect(bytes.toString("binary")).not.toContain("PGDMP");
    expect(bytes.toString("binary")).not.toContain("pgbackupuser");
    expect(run(["verify", join(out, files[0]!), "--key", keyPath])).toMatch(/decrypts, archive lists/);
  }, 60_000);

  it("never takes a connection string from the command line", () => {
    const source = readFileSync(script, "utf8");
    expect(source).not.toMatch(/--dbname=\$\{|"--dbname", (source|connection|url)\b/);
    expect(source).toMatch(/PGPASSWORD/);
    expect(() => run(["create", "--key", keyPath, "--out", join(workspace, "nourl")], { DATABASE_URL: "" })).toThrow(
      /--url-file/,
    );
  });

  it("refuses a wrong key, a tampered file and a SQLite backup", () => {
    const out = join(workspace, "tamper");
    run(["create", "--key", keyPath, "--url-file", sourceUrlFile, "--out", out]);
    const file = join(out, readdirSync(out)[0]!);
    const wrongKey = join(workspace, "wrong.key");
    writeFileSync(wrongKey, randomBytes(32).toString("base64"));
    expect(() => run(["verify", file, "--key", wrongKey])).toThrow();

    const bytes = readFileSync(file);
    bytes[bytes.length - 40] = (bytes[bytes.length - 40] ?? 0) ^ 0xff;
    const edited = join(workspace, "edited.enc");
    writeFileSync(edited, bytes);
    expect(() => run(["verify", edited, "--key", keyPath])).toThrow();

    // The other tool's header: authenticated, so the wrong tool cannot open it by accident.
    const sqliteHeader = Buffer.concat([Buffer.from("SYMVBK1\n"), bytes.subarray(8)]);
    const swapped = join(workspace, "swapped.enc");
    writeFileSync(swapped, sqliteHeader);
    expect(() => run(["verify", swapped, "--key", keyPath])).toThrow(/bad header/);
  }, 60_000);

  it("restores into an empty database and refuses one that is not", async () => {
    const out = join(workspace, "restore");
    run(["create", "--key", keyPath, "--url-file", sourceUrlFile, "--out", out]);
    const file = join(out, readdirSync(out)[0]!);
    await adminQuery(`CREATE DATABASE ${targetDb} TEMPLATE template0`);
    const targetUrlFile = join(workspace, "target.url");
    writeFileSync(targetUrlFile, withDatabase(targetDb));

    const output = run(["restore", file, "--key", keyPath, "--target-url-file", targetUrlFile]);
    expect(output).toMatch(/schema symvolon/);
    expect(output).toMatch(/1 accounts/);

    const pg = (await import("pg")).default;
    const check = new pg.Client(withDatabase(targetDb));
    await check.connect();
    try {
      const { rows } = await check.query("SELECT username FROM symvolon.users");
      expect(rows.map((row) => row.username)).toEqual(["pgbackupuser"]);
    } finally {
      await check.end();
    }
    // Restoring twice would be restoring over data. `wx`, for a database.
    expect(() => run(["restore", file, "--key", keyPath, "--target-url-file", targetUrlFile])).toThrow(
      /already holds \d+ tables/,
    );
  }, 60_000);

  it("drills: restores the newest backup into a throwaway database and boots a real service on it", async () => {
    const out = join(workspace, "drill");
    run(["create", "--key", keyPath, "--url-file", sourceUrlFile, "--out", out]);
    const output = run(["drill", "--key", keyPath, "--out", out, "--admin-url-file", adminUrlFile]);
    expect(output).toMatch(/\/healthz ok, page ok/);
    expect(output).toMatch(/1 accounts/);
    expect(output).toMatch(/the copy is dropped/);
    // Nothing left on the server.
    const pg = (await import("pg")).default;
    const client = new pg.Client(adminUrl);
    await client.connect();
    try {
      const { rows } = await client.query("SELECT datname FROM pg_database WHERE datname LIKE 'symvolon_drill_%'");
      expect(rows).toEqual([]);
    } finally {
      await client.end();
    }
  }, 90_000);

  it("drops the throwaway database even when the drill fails", async () => {
    const out = join(workspace, "drill-failing");
    run(["create", "--key", keyPath, "--url-file", sourceUrlFile, "--out", out]);
    // A restore tool that always fails stands in for any mid-drill failure: the copy has been
    // created by then, and a `process.exit` in the wrong place would leave it on the server.
    expect(() =>
      run(["drill", "--key", keyPath, "--out", out, "--admin-url-file", adminUrlFile], { PG_RESTORE: "/bin/false" }),
    ).toThrow(/exited 1/);
    const pg = (await import("pg")).default;
    const client = new pg.Client(adminUrl);
    await client.connect();
    try {
      const { rows } = await client.query("SELECT datname FROM pg_database WHERE datname LIKE 'symvolon_drill_%'");
      expect(rows).toEqual([]);
    } finally {
      await client.end();
    }
  }, 60_000);

  it("says so loudly when there is nothing to drill", () => {
    const empty = mkdtempSync(join(tmpdir(), "symvolon-empty-"));
    try {
      expect(() => run(["drill", "--key", keyPath, "--out", empty, "--admin-url-file", adminUrlFile])).toThrow(
        /no backup to drill/,
      );
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it("prunes on the same window as the SQLite tool", () => {
    const out = join(workspace, "retention");
    run(["create", "--key", keyPath, "--url-file", sourceUrlFile, "--out", out]);
    const template = join(out, readdirSync(out)[0]!);
    for (let i = 1; i <= 3; i += 1) {
      const copy = join(out, `symvolon-2026-08-0${i}T010203Z.pgdump.enc`);
      writeFileSync(copy, readFileSync(template));
      const age = (Date.now() - (i + 40) * 24 * 60 * 60 * 1000) / 1000;
      utimesSync(copy, age, age);
    }
    const before = readdirSync(out).length;
    expect(run(["prune", "--out", out, "--days", "35", "--keep", String(before)])).toMatch(/0 removed/);
    expect(readdirSync(out).length).toBe(before);
    expect(run(["prune", "--out", out, "--days", "35", "--keep", "1"])).toMatch(/3 removed/);
    expect(readdirSync(out)).toEqual([template.split("/").at(-1)]);
  }, 60_000);
});

describe("the PostgreSQL backup tool, on any driver", () => {
  it("is documented beside the SQLite one", () => {
    const doc = readFileSync(new URL("../docs/BACKUPS.md", import.meta.url), "utf8");
    for (const claim of ["backup-postgres.mjs", "pg_dump", "pgdump.enc", "backup:pg:drill"]) {
      expect(doc, claim).toContain(claim);
    }
  });

  it("shares the envelope with the SQLite tool rather than a second copy of the crypto", () => {
    const source = readFileSync(script, "utf8");
    expect(source).toContain('from "./backup-envelope.mjs"');
    expect(source).not.toMatch(/createCipheriv|createDecipheriv/);
  });
});
