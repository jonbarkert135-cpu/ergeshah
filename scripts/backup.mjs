/**
 * Backups: encrypted, versioned, verified, and forgetful (point 50).
 *
 * A backup of this database is the most valuable single artefact the operator holds: no
 * plaintext messages, but password hashes, marketplace records, public keys and every
 * timestamp. So it is never written unencrypted, and — the part backup tooling usually gets
 * wrong — it does not live forever. A retention window is what stops the backup set from
 * becoming a permanent copy of data users asked to have deleted (docs/BACKUPS.md).
 *
 *   node scripts/backup.mjs keygen > /etc/symvolon/backup.key   # once, offline
 *   node scripts/backup.mjs create --key /etc/symvolon/backup.key --out /var/backups/symvolon
 *   node scripts/backup.mjs verify <file> --key …               # decrypt + integrity check
 *   node scripts/backup.mjs restore <file> <target.sqlite> --key …
 *   node scripts/backup.mjs prune --out /var/backups/symvolon --days 35 --keep 7
 *   node scripts/backup.mjs drill --out /var/backups/symvolon --key …          # quarterly
 *
 * Encryption is AES-256-GCM from `node:crypto`: no dependency, no external binary to have
 * installed on the host at 3am, and an authentication tag that makes a truncated or edited
 * backup fail loudly instead of restoring quietly.
 */
import { createHash, randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  backupsIn as backupsMatching,
  decrypt as unseal,
  driveDrillServer,
  encrypt as seal,
  fail,
  parseArgs,
  privateScratchDir,
  pruneBackups,
  readKey,
  stamp,
} from "./backup-envelope.mjs";

// The header names the format; the envelope (key handling, AES-256-GCM, the pinned tag
// length, the private scratch directory) lives in scripts/backup-envelope.mjs and is shared
// with the PostgreSQL tool, so the two cannot drift.
const MAGIC = Buffer.from("SYMVBK1\n");
const NAME_RE = /^symvolon-(\d{4}-\d{2}-\d{2}T\d{6}Z)(-\d+)?\.sqlite\.enc$/;

const encrypt = (plaintext, key) => seal(plaintext, key, MAGIC);
const decrypt = (file, key) => unseal(file, key, MAGIC);
const backupsIn = (directory) => backupsMatching(directory, NAME_RE);

/**
 * A consistent snapshot of a live database. `VACUUM INTO` is the supported way — `cp` on a
 * WAL database copies a file that no longer matches its write-ahead log.
 */
function snapshot(sourcePath) {
  const dir = privateScratchDir();
  const scratch = join(dir, "snapshot.sqlite");
  try {
    const db = new DatabaseSync(sourcePath, { readOnly: true });
    try {
      db.prepare("VACUUM INTO ?").run(scratch);
    } finally {
      db.close();
    }
    chmodSync(scratch, 0o600);
    return readFileSync(scratch);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Opens a snapshot and asks SQLite whether it is intact, then counts what is inside. */
function inspect(bytes) {
  const dir = privateScratchDir();
  const scratch = join(dir, "verify.sqlite");
  writeFileSync(scratch, bytes, { mode: 0o600 });
  const db = new DatabaseSync(scratch, { readOnly: true });
  try {
    const integrity = db.prepare("PRAGMA integrity_check").get();
    const result = String(Object.values(integrity ?? {})[0] ?? "unknown");
    if (result !== "ok") fail(`integrity check failed: ${result}`);
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all()
      .map((row) => row.name);
    const migrations = db.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get();
    const users = db.prepare("SELECT COUNT(*) AS n FROM users").get();
    return { tables: tables.length, migrations: Number(migrations.n), users: Number(users.n) };
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function create({ flags }) {
  const key = readKey(flags);
  const source = flags.db ?? process.env.SQLITE_PATH ?? "data/symvolon.sqlite";
  const directory = flags.out ?? "backups";
  mkdirSync(directory, { recursive: true });
  const bytes = snapshot(source);
  const summary = inspect(bytes);
  // Two runs in the same second must not silently overwrite each other: versioned means
  // versioned. `wx` below is what actually guarantees it.
  let path = join(directory, `symvolon-${stamp()}.sqlite.enc`);
  for (let n = 1; existsSync(path); n += 1) {
    path = join(directory, `symvolon-${stamp()}-${n}.sqlite.enc`);
  }
  const sealed = encrypt(bytes, key);
  writeFileSync(path, sealed, { mode: 0o600, flag: "wx" });
  process.stdout.write(
    `${path}\n  ${sealed.length} bytes encrypted (plaintext ${bytes.length})\n` +
      `  sha256 ${createHash("sha256").update(sealed).digest("hex")}\n` +
      `  verified before writing: integrity ok, ${summary.tables} tables, ` +
      `${summary.migrations} migrations, ${summary.users} accounts\n`,
  );
  return path;
}

function verify({ flags, positional }) {
  const [path] = positional;
  if (!path) fail("usage: backup.mjs verify <file> --key <file>");
  const summary = inspect(decrypt(readFileSync(path), readKey(flags)));
  process.stdout.write(
    `${path}: decrypts, integrity ok, ${summary.tables} tables, ${summary.migrations} migrations, ${summary.users} accounts\n`,
  );
}

function restore({ flags, positional }) {
  const [path, target] = positional;
  if (!path || !target) fail("usage: backup.mjs restore <file> <target.sqlite> --key <file>");
  const bytes = decrypt(readFileSync(path), readKey(flags));
  // Verified before it is written: a restore that lands a corrupt file on top of a live
  // database is worse than no restore at all.
  const summary = inspect(bytes);
  writeFileSync(target, bytes, { flag: "wx", mode: 0o600 });
  process.stdout.write(
    `restored ${path} -> ${target} (${summary.tables} tables, ${summary.users} accounts)\n`,
  );
}

/** Retention (docs/BACKUPS.md): older than `--days` goes, never fewer than `--keep` stay. */
function prune(parsed) {
  return pruneBackups(parsed, NAME_RE);
}

/**
 * The restore drill (docs/BACKUPS.md, quarterly in docs/HARDENING.md).
 *
 * `verify` proves a backup decrypts and that SQLite considers it intact. That is not the
 * question an operator has at 3am: the question is whether the *service* comes up on it.
 * So this restores the newest backup to a temporary file, starts a real server against it
 * in production mode with a throwaway pepper, waits for `/healthz`, asks for the page a
 * browser would ask for, and then deletes the copy. Nothing touches the live database, and
 * the drill never runs on the production port.
 *
 * A drill that is only described in a document is a wish, which is why this is a command
 * and why `test/backup.test.ts` runs it.
 */
async function drill({ flags, positional }) {
  const key = readKey(flags);
  const [given] = positional;
  const directory = flags.out ?? "backups";
  const chosen = given ?? backupsIn(directory).at(-1)?.path;
  if (!chosen) fail(`no backup to drill: nothing named symvolon-*.sqlite.enc in ${directory}`);

  // Inside a private directory: the copy is `0600`, but the `-wal` and `-shm` files the
  // restored service creates next to it would take the default mode in a shared /tmp.
  const dir = privateScratchDir();
  const scratch = join(dir, "drill.sqlite");
  const bytes = decrypt(readFileSync(chosen), key);
  const summary = inspect(bytes);
  writeFileSync(scratch, bytes, { flag: "wx", mode: 0o600 });

  try {
    await driveDrillServer({ SQLITE_PATH: scratch });
    process.stdout.write(
      `drill: ${chosen}\n  restored to a temporary copy, service started in production mode, ` +
        `/healthz ok, page ok\n  ${summary.tables} tables, ${summary.migrations} migrations, ` +
        `${summary.users} accounts\n  the live database was not touched; the copy is deleted\n`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function keygen() {
  process.stdout.write(`${randomBytes(32).toString("base64")}\n`);
}

const [command, ...rest] = process.argv.slice(2);
const parsed = parseArgs(rest);
const commands = { create, verify, restore, prune, drill, keygen };
if (!command || !Object.hasOwn(commands, command)) {
  fail(`usage: backup.mjs <${Object.keys(commands).join("|")}> [...]  (see docs/BACKUPS.md)`);
}
// A thrown error (a drill that did not come up, a database that refused) is reported the way
// every other refusal is: one line on stderr, exit 1, no stack trace, after every `finally`.
try {
  await commands[command](parsed);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
