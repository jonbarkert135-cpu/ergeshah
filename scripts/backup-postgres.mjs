/**
 * Backups for the PostgreSQL tier: the same envelope, the same rules, a different snapshot.
 *
 * `scripts/backup.mjs` is the SQLite tool. A deployment on PostgreSQL (`DATABASE_URL`) had
 * `docs/BACKUPS.md` telling it to "use pg_dump and the same rules" — prose where the other
 * driver has a command and a drill in CI (OPS-9). This is the command. The snapshot is a
 * `pg_dump` custom-format archive, encrypted before it is written, verified before it is
 * reported, versioned by name, pruned on the same 35-day window, and drilled by restoring it
 * into a throwaway database and booting a real server on it.
 *
 *   node scripts/backup-postgres.mjs create --key … --out /var/backups/symvolon
 *   node scripts/backup-postgres.mjs verify <file> --key …
 *   node scripts/backup-postgres.mjs restore <file> --key … --target-url-file <file>
 *   node scripts/backup-postgres.mjs prune --out /var/backups/symvolon --days 35 --keep 7
 *   node scripts/backup-postgres.mjs drill --out … --key … --admin-url-file <file>   # quarterly
 *
 * Connection strings are read from a file or from the environment, never from an argument:
 * `pg_dump` and `pg_restore` get them as `PG*` variables, so no password ever appears in `ps`
 * or in shell history. The dump connects as whoever the URL names — on a deployment set up by
 * `deploy/postgres-roles.sql` that is `symvolon_backup`, which can SELECT and nothing else.
 *
 * Requires `pg_dump` and `pg_restore` on the PATH (or `PG_DUMP` / `PG_RESTORE`) at least as
 * new as the server: `pg_dump` refuses an older client, and says so.
 */
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";
import {
  backupsIn as backupsMatching,
  decrypt as unseal,
  driveDrillServer,
  encrypt as seal,
  fail,
  parseArgs,
  pruneBackups,
  readKey,
  stamp,
} from "./backup-envelope.mjs";

const MAGIC = Buffer.from("SYMVPG1\n");
const NAME_RE = /^symvolon-(\d{4}-\d{2}-\d{2}T\d{6}Z)(-\d+)?\.pgdump\.enc$/;
const PG_DUMP = process.env.PG_DUMP ?? "pg_dump";
const PG_RESTORE = process.env.PG_RESTORE ?? "pg_restore";
/** Schemas that are the server's, not the deployment's. */
const SYSTEM_SCHEMAS = new Set(["pg_catalog", "information_schema", "pg_toast"]);
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

const encrypt = (plaintext, key) => seal(plaintext, key, MAGIC);
const decrypt = (file, key) => unseal(file, key, MAGIC);
const backupsIn = (directory) => backupsMatching(directory, NAME_RE);

/**
 * A connection string, from `--<name>-file <file>` or from the named environment variables,
 * in that order. Never from an argument: an argument is visible to every process on the host.
 */
function connectionString(flags, name, envNames) {
  const file = flags[`${name}-file`];
  if (file && file !== true) return readFileSync(file, "utf8").trim();
  for (const env of envNames) if (process.env[env]) return process.env[env];
  fail(`--${name}-file <file> (or ${envNames.join(" / ")}) is required`);
}

/**
 * The URL, as libpq variables for a child process. The URL is not passed through as an
 * argument so that the password stays out of `ps`; `options` (how the roles file and the
 * test-suite carry a `search_path`) and `sslmode` survive the translation.
 */
function libpqEnvironment(connection) {
  const url = new URL(connection);
  const env = {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: decodeURIComponent(url.pathname.replace(/^\//, "")),
  };
  const sslmode = url.searchParams.get("sslmode");
  if (sslmode) env.PGSSLMODE = sslmode;
  const options = url.searchParams.get("options");
  if (options) env.PGOPTIONS = options;
  return env;
}

/** Runs a PostgreSQL client tool with `input` on stdin; resolves with stdout, fails loudly. */
function tool(binary, args, env, input) {
  // Rejects rather than exits, so a drill's `finally` still drops the throwaway database.
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    const out = [];
    let err = "";
    child.stdout.on("data", (chunk) => out.push(chunk));
    child.stderr.on("data", (chunk) => (err += chunk));
    child.on("error", (error) =>
      reject(new Error(`${binary}: ${error.message} — install the PostgreSQL client tools, or point PG_DUMP / PG_RESTORE at them`)),
    );
    child.on("close", (code) => {
      if (code !== 0) reject(new Error(`${binary} exited ${code}\n${err.trim()}`));
      else resolve(Buffer.concat(out));
    });
    if (input) child.stdin.end(input);
    else child.stdin.end();
  });
}

/**
 * What an archive holds, from its own table of contents (`pg_restore --list`): the tables and
 * the schema they live in. Reading the archive is what proves it is an archive — a truncated
 * or foreign file has no table of contents.
 */
async function inspect(archive) {
  const toc = (await tool(PG_RESTORE, ["--list"], process.env, archive)).toString("utf8");
  const tables = [];
  for (const line of toc.split("\n")) {
    // `1234; 1259 16385 TABLE symvolon users postgres` — the definition; `TABLE DATA` lines
    // repeat every table once more and are skipped.
    const match = /^\d+; \d+ \d+ TABLE (?!DATA )(\S+) (\S+) /.exec(line);
    if (match && !SYSTEM_SCHEMAS.has(match[1])) tables.push({ schema: match[1], name: match[2] });
  }
  if (tables.length === 0) fail("the archive lists no tables: not a Symvolon database");
  const schemas = [...new Set(tables.map((table) => table.schema))].sort();
  if (schemas.length !== 1) fail(`the archive spans ${schemas.length} schemas (${schemas.join(", ")}); expected one`);
  if (!tables.some((table) => table.name === "schema_migrations")) fail("the archive has no schema_migrations table");
  if (!tables.some((table) => table.name === "users")) fail("the archive has no users table");
  return { tables: tables.length, schema: schemas[0] };
}

/** One connection, one question, closed. */
async function query(connection, sql, params = []) {
  const client = new pg.Client({ connectionString: connection });
  await client.connect();
  try {
    return (await client.query(sql, params)).rows;
  } finally {
    await client.end();
  }
}

/** Row counts an operator recognises, read from the database the URL points at. */
async function counts(connection, schema) {
  if (!IDENTIFIER.test(schema)) fail(`refusing to use schema name ${JSON.stringify(schema)}`);
  // PostgreSQL has no placeholder for an identifier; the schema comes from the archive's own
  // table of contents and its shape is asserted one line above.
  const sql = `SELECT (SELECT COUNT(*) FROM "${schema}".schema_migrations) AS migrations, (SELECT COUNT(*) FROM "${schema}".users) AS users`; // audit:allow — identifier validated above
  const [row] = await query(connection, sql);
  return { migrations: Number(row.migrations), users: Number(row.users) };
}

async function create({ flags }) {
  const key = readKey(flags);
  const source = connectionString(flags, "url", ["BACKUP_DATABASE_URL", "DATABASE_URL"]);
  const directory = flags.out ?? "backups";
  mkdirSync(directory, { recursive: true });
  // Custom format: compressed, restorable table by table, and the only format `pg_restore`
  // can list from a pipe — the archive never touches the disk in the clear.
  const archive = await tool(
    PG_DUMP,
    ["--format=custom", "--no-owner", "--no-privileges", "--no-subscriptions", "--no-publications"],
    libpqEnvironment(source),
  );
  const summary = await inspect(archive);
  const live = await counts(source, summary.schema);
  let path = join(directory, `symvolon-${stamp()}.pgdump.enc`);
  for (let n = 1; existsSync(path); n += 1) {
    path = join(directory, `symvolon-${stamp()}-${n}.pgdump.enc`);
  }
  const sealed = encrypt(archive, key);
  writeFileSync(path, sealed, { mode: 0o600, flag: "wx" });
  process.stdout.write(
    `${path}\n  ${sealed.length} bytes encrypted (archive ${archive.length})\n` +
      `  sha256 ${createHash("sha256").update(sealed).digest("hex")}\n` +
      `  verified before writing: archive lists ${summary.tables} tables in schema ${summary.schema}; ` +
      `source has ${live.migrations} migrations, ${live.users} accounts\n`,
  );
  return path;
}

async function verify({ flags, positional }) {
  const [path] = positional;
  if (!path) fail("usage: backup-postgres.mjs verify <file> --key <file>");
  const summary = await inspect(decrypt(readFileSync(path), readKey(flags)));
  process.stdout.write(`${path}: decrypts, archive lists ${summary.tables} tables in schema ${summary.schema}\n`);
}

/** `--exit-on-error` in one transaction: the target is either the backup or untouched. */
async function restoreInto(archive, target) {
  await tool(
    PG_RESTORE,
    ["--no-owner", "--no-privileges", "--exit-on-error", "--single-transaction", "--dbname", new URL(target).pathname.slice(1)],
    libpqEnvironment(target),
    archive,
  );
}

/** The service's URL for a restored copy: same server, the restored database, its schema. */
function serviceUrl(connection, database, schema) {
  const url = new URL(connection);
  url.pathname = `/${database}`;
  url.searchParams.set("options", `-c search_path=${schema}`);
  return url.toString();
}

/**
 * Restore into a database the operator has created and left empty. Empty is checked, not
 * assumed: `wx` for a database. A restore over a live database is the one mistake this tool
 * must make impossible.
 */
async function restore({ flags, positional }) {
  const [path] = positional;
  if (!path) fail("usage: backup-postgres.mjs restore <file> --key <file> --target-url-file <file>");
  const target = connectionString(flags, "target-url", ["RESTORE_DATABASE_URL"]);
  const archive = decrypt(readFileSync(path), readKey(flags));
  const summary = await inspect(archive);
  const [{ n }] = await query(
    target,
    "SELECT COUNT(*)::int AS n FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')",
  );
  if (n !== 0) fail(`refusing to restore: the target database already holds ${n} tables`);
  await restoreInto(archive, target);
  const database = new URL(target).pathname.slice(1);
  const restored = await counts(serviceUrl(target, database, summary.schema), summary.schema);
  process.stdout.write(
    `restored ${path} -> ${database} (schema ${summary.schema}, ${summary.tables} tables, ` +
      `${restored.migrations} migrations, ${restored.users} accounts)\n`,
  );
}

function prune(parsed) {
  return pruneBackups(parsed, NAME_RE);
}

/**
 * The restore drill (docs/BACKUPS.md, quarterly in docs/HARDENING.md).
 *
 * `verify` proves a backup decrypts and that `pg_restore` can read its table of contents.
 * The operator's question at 3am is whether the *service* comes up on it. So: create a
 * throwaway database on the server the admin URL names, restore the newest backup into it,
 * start a real server against it in production mode with a throwaway pepper, wait for
 * `/healthz`, ask for the page, then drop the database. The live database is never named.
 *
 * The admin URL is the one used for `deploy/postgres-roles.sql`: the application role may
 * not create databases (ADR-0095), and a drill should not need it to.
 */
async function drill({ flags, positional }) {
  const key = readKey(flags);
  const admin = connectionString(flags, "admin-url", ["BACKUP_ADMIN_URL"]);
  const [given] = positional;
  const directory = flags.out ?? "backups";
  const chosen = given ?? backupsIn(directory).at(-1)?.path;
  if (!chosen) fail(`no backup to drill: nothing named symvolon-*.pgdump.enc in ${directory}`);

  const archive = decrypt(readFileSync(chosen), key);
  const summary = await inspect(archive);
  // Generated here from random bytes, never from input; the shape is asserted before it is
  // interpolated, because PostgreSQL has no placeholder for an identifier.
  const database = `symvolon_drill_${randomBytes(6).toString("hex")}`;
  if (!/^symvolon_drill_[0-9a-f]{12}$/.test(database)) fail("generated database name is not safe");
  await query(admin, `CREATE DATABASE ${database} TEMPLATE template0`);
  try {
    const url = serviceUrl(admin, database, summary.schema);
    await restoreInto(archive, url);
    const restored = await counts(url, summary.schema);
    await driveDrillServer({ DATABASE_URL: url, DB_DIALECT: "postgres" });
    process.stdout.write(
      `drill: ${chosen}\n  restored into a throwaway database, service started in production mode, ` +
        `/healthz ok, page ok\n  ${summary.tables} tables, ${restored.migrations} migrations, ` +
        `${restored.users} accounts\n  the live database was not touched; the copy is dropped\n`,
    );
  } finally {
    await query(admin, `DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  }
}

const [command, ...rest] = process.argv.slice(2);
const parsed = parseArgs(rest);
const commands = { create, verify, restore, prune, drill };
if (!command || !Object.hasOwn(commands, command)) {
  fail(`usage: backup-postgres.mjs <${Object.keys(commands).join("|")}> [...]  (see docs/BACKUPS.md)`);
}
// A thrown error (a drill that did not come up, a database that refused) is reported the way
// every other refusal is: one line on stderr, exit 1, no stack trace, after every `finally`.
try {
  await commands[command](parsed);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
