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
import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const MAGIC = Buffer.from("SYMVBK1\n");
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const NAME_RE = /^symvolon-(\d{4}-\d{2}-\d{2}T\d{6}Z)(-\d+)?\.sqlite\.enc$/;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/** Flags, kept deliberately dumb: `--name value` and bare positionals. */
function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) flags[token.slice(2)] = true;
      else {
        flags[token.slice(2)] = next;
        i += 1;
      }
    } else positional.push(token);
  }
  return { flags, positional };
}

/**
 * The key: 32 bytes, base64. Read from a file, never from a command line (a command line is
 * visible in `ps` and in shell history) and never from the application's own configuration —
 * the point of an encrypted backup is that the running service cannot decrypt its own.
 */
function readKey(flags) {
  const path = flags.key ?? process.env.BACKUP_KEY_FILE;
  if (!path || path === true) fail("--key <file> (or BACKUP_KEY_FILE) is required");
  const key = Buffer.from(readFileSync(path, "utf8").trim(), "base64");
  if (key.length !== 32) fail(`${path}: expected 32 bytes of base64 (see: backup.mjs keygen)`);
  return key;
}

function encrypt(plaintext, key) {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  // The header is authenticated: a backup from a future format cannot be silently misread.
  cipher.setAAD(MAGIC);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([MAGIC, nonce, body, cipher.getAuthTag()]);
}

function decrypt(file, key) {
  if (file.length < MAGIC.length + NONCE_BYTES + TAG_BYTES) fail("not a Symvolon backup: too short");
  if (!file.subarray(0, MAGIC.length).equals(MAGIC)) fail("not a Symvolon backup: bad header");
  const nonce = file.subarray(MAGIC.length, MAGIC.length + NONCE_BYTES);
  const body = file.subarray(MAGIC.length + NONCE_BYTES, file.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(MAGIC);
  decipher.setAuthTag(file.subarray(file.length - TAG_BYTES));
  // Throws if the key is wrong or a byte was changed. That is the feature.
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/**
 * A consistent snapshot of a live database. `VACUUM INTO` is the supported way — `cp` on a
 * WAL database copies a file that no longer matches its write-ahead log.
 */
function snapshot(sourcePath) {
  const scratch = join(tmpdir(), `symvolon-snapshot-${randomBytes(6).toString("hex")}.sqlite`);
  const db = new DatabaseSync(sourcePath, { readOnly: true });
  try {
    db.prepare("VACUUM INTO ?").run(scratch);
  } finally {
    db.close();
  }
  try {
    return readFileSync(scratch);
  } finally {
    rmSync(scratch, { force: true });
  }
}

/** Opens a snapshot and asks SQLite whether it is intact, then counts what is inside. */
function inspect(bytes) {
  const scratch = join(tmpdir(), `symvolon-verify-${randomBytes(6).toString("hex")}.sqlite`);
  writeFileSync(scratch, bytes);
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
    rmSync(scratch, { force: true });
  }
}

function stamp(date = new Date()) {
  return date.toISOString().replace(/[:-]/g, "").replace(/^(\d{4})(\d{2})(\d{2})T(\d{6}).*$/, "$1-$2-$3T$4Z");
}

function backupsIn(directory) {
  return readdirSync(directory)
    .filter((name) => NAME_RE.test(name))
    .sort()
    .map((name) => ({ name, path: join(directory, name) }));
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

/**
 * Retention. Deletes backups older than `--days`, but never leaves fewer than `--keep` of
 * them: a retention policy that can empty the directory is a data-loss policy.
 */
function prune({ flags }) {
  const directory = flags.out ?? "backups";
  const days = Number(flags.days ?? 35);
  const keep = Number(flags.keep ?? 7);
  if (!Number.isFinite(days) || days < 1) fail("--days must be a positive number");
  const all = backupsIn(directory);
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const removable = all.slice(0, Math.max(0, all.length - keep));
  let removed = 0;
  for (const backup of removable) {
    if (statSync(backup.path).mtimeMs >= cutoff) continue;
    unlinkSync(backup.path);
    removed += 1;
  }
  process.stdout.write(
    `prune: ${removed} removed, ${all.length - removed} kept (older than ${days} days, ` +
      `never fewer than ${keep})\n`,
  );
  return removed;
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

  const scratch = join(tmpdir(), `symvolon-drill-${randomBytes(6).toString("hex")}.sqlite`);
  const bytes = decrypt(readFileSync(chosen), key);
  const summary = inspect(bytes);
  writeFileSync(scratch, bytes, { flag: "wx", mode: 0o600 });

  // A port, not a secret: the drill binds 127.0.0.1 and lives for a few seconds.
  const port = 20000 + (randomBytes(2).readUInt16BE() % 20000);
  const server = spawn(
    process.execPath,
    ["--experimental-strip-types", "--disable-warning=ExperimentalWarning", "src/server/main.ts"],
    {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        NODE_ENV: "production",
        SQLITE_PATH: scratch,
        // The drill's own secret: never the production one, and gone when it exits.
        RATE_LIMIT_PEPPER: randomBytes(36).toString("base64"),
        BEHIND_TLS: "false",
        HOST: "127.0.0.1",
        PORT: String(port),
        ONION_HOSTNAME: "",
      },
    },
  );
  let output = "";
  server.stdout.on("data", (chunk) => (output += chunk));
  server.stderr.on("data", (chunk) => (output += chunk));

  try {
    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 30_000;
    let health = null;
    while (Date.now() < deadline) {
      if (server.exitCode !== null) break;
      health = await fetch(`${base}/healthz`).catch(() => null);
      if (health?.ok) break;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    if (!health?.ok) fail(`drill FAILED: the service did not come up on the restored copy\n${output}`);
    const page = await fetch(base);
    if (!page.ok) fail(`drill FAILED: the restored service answered ${page.status} for the page`);
    process.stdout.write(
      `drill: ${chosen}\n  restored to a temporary copy, service started in production mode, ` +
        `/healthz ok, page ok\n  ${summary.tables} tables, ${summary.migrations} migrations, ` +
        `${summary.users} accounts\n  the live database was not touched; the copy is deleted\n`,
    );
  } finally {
    server.kill("SIGTERM");
    // Wait for the process to let go before deleting: SQLite in WAL mode keeps two
    // companion files, and removing them under a live handle leaves the litter behind.
    await Promise.race([
      new Promise((resolve) => server.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 5_000)),
    ]);
    for (const suffix of ["", "-wal", "-shm"]) rmSync(`${scratch}${suffix}`, { force: true });
  }
}

function keygen() {
  process.stdout.write(`${randomBytes(32).toString("base64")}\n`);
}

const [command, ...rest] = process.argv.slice(2);
const parsed = parseArgs(rest);
const commands = { create, verify, restore, prune, drill, keygen };
if (!command || !(command in commands)) {
  fail(`usage: backup.mjs <${Object.keys(commands).join("|")}> [...]  (see docs/BACKUPS.md)`);
}
await commands[command](parsed);
