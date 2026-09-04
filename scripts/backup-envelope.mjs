/**
 * The envelope every Symvolon backup is written in, shared by the SQLite tool
 * (`scripts/backup.mjs`) and the PostgreSQL tool (`scripts/backup-postgres.mjs`).
 *
 * One implementation, so that the two cannot drift: the same AES-256-GCM from `node:crypto`,
 * the same 32-byte key read from a file and never from an argument, the same pinned tag
 * length, the same authenticated header. Only the header differs — `SYMVBK1` for a SQLite
 * snapshot, `SYMVPG1` for a `pg_dump` archive — and because the header is the AAD, a file
 * handed to the wrong tool fails on the tag instead of being restored as the wrong thing.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtempSync, readFileSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;

export function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/** Flags, kept deliberately dumb: `--name value` and bare positionals. */
export function parseArgs(argv) {
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
export function readKey(flags) {
  const path = flags.key ?? process.env.BACKUP_KEY_FILE;
  if (!path || path === true) fail("--key <file> (or BACKUP_KEY_FILE) is required");
  const key = Buffer.from(readFileSync(path, "utf8").trim(), "base64");
  if (key.length !== 32) fail(`${path}: expected 32 bytes of base64 (see: backup.mjs keygen)`);
  return key;
}

export function encrypt(plaintext, key, magic) {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  // The header is authenticated: a backup from a future format cannot be silently misread.
  cipher.setAAD(magic);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([magic, nonce, body, cipher.getAuthTag()]);
}

export function decrypt(file, key, magic) {
  if (file.length < magic.length + NONCE_BYTES + TAG_BYTES) fail("not a Symvolon backup: too short");
  if (!file.subarray(0, magic.length).equals(magic)) fail("not a Symvolon backup: bad header");
  const nonce = file.subarray(magic.length, magic.length + NONCE_BYTES);
  const body = file.subarray(magic.length + NONCE_BYTES, file.length - TAG_BYTES);
  // The tag length is pinned rather than left to Node's default set (which also accepts
  // 32-bit tags). The slice above already hands over exactly TAG_BYTES, so this is belt and
  // braces — the cheap kind, flagged by Semgrep's gcm-no-tag-length on 2026-09-04.
  const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(magic);
  decipher.setAuthTag(file.subarray(file.length - TAG_BYTES));
  // Throws if the key is wrong or a byte was changed. That is the feature.
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/**
 * A private place for a plaintext scratch file. `mkdtemp` creates the directory `0700`, so
 * the snapshot inside it is unreadable to every other account on the host for the seconds it
 * exists — a file created straight in `/tmp` is `0644` under the usual umask, and on a host
 * with any other login that is the whole database, in the clear, copyable in a loop
 * (SEC-2026-016). The caller removes the directory in a `finally`.
 */
export function privateScratchDir() {
  return mkdtempSync(join(tmpdir(), "symvolon-"));
}

export function stamp(date = new Date()) {
  return date.toISOString().replace(/[:-]/g, "").replace(/^(\d{4})(\d{2})(\d{2})T(\d{6}).*$/, "$1-$2-$3T$4Z");
}

export function backupsIn(directory, nameRe) {
  return readdirSync(directory)
    .filter((name) => nameRe.test(name))
    .sort()
    .map((name) => ({ name, path: join(directory, name) }));
}

/**
 * Retention. Deletes backups older than `--days`, but never leaves fewer than `--keep` of
 * them: a retention policy that can empty the directory is a data-loss policy.
 */
export function pruneBackups({ flags }, nameRe) {
  const directory = flags.out ?? "backups";
  const days = Number(flags.days ?? 35);
  const keep = Number(flags.keep ?? 7);
  if (!Number.isFinite(days) || days < 1) fail("--days must be a positive number");
  const all = backupsIn(directory, nameRe);
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
 * The half of a restore drill both drivers share: start a real server in production mode on
 * the restored data, on a random loopback port with a throwaway pepper, wait for `/healthz`,
 * ask for the page a browser would ask for, then stop it and wait for it to let go. The
 * caller supplies the database environment (`SQLITE_PATH` or `DATABASE_URL`) and deletes
 * whatever it restored, in its own `finally`.
 */
/**
 * A loopback port nothing is listening on right now. Kept below Linux's ephemeral range
 * (32768+) so an outgoing connection of another process cannot have taken it, and probed by
 * binding, so a port another drill or test holds is skipped instead of crashing the service.
 */
export async function freeLoopbackPort(attempts = 20) {
  const probe = (port) =>
    new Promise((resolve) => {
      const listener = createServer();
      listener.once("error", () => resolve(null));
      listener.listen(port, "127.0.0.1", () => listener.close(() => resolve(port)));
    });
  for (let i = 0; i < attempts; i += 1) {
    const port = await probe(10000 + (randomBytes(2).readUInt16BE() % 20000));
    if (port) return port;
  }
  throw new Error(`drill FAILED: no free loopback port found in ${attempts} attempts`);
}

/**
 * Failures are thrown, not exited: the caller's `finally` must still delete or drop the
 * restored copy, and the top of each tool turns the error into a plain message and exit 1.
 */
export async function driveDrillServer(database) {
  // A port, not a secret: the drill binds 127.0.0.1 and lives for a few seconds.
  const port = await freeLoopbackPort();
  const server = spawn(
    process.execPath,
    ["--experimental-strip-types", "--disable-warning=ExperimentalWarning", "src/server/main.ts"],
    {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        NODE_ENV: "production",
        ...database,
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
      health = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(5_000) }).catch(() => null);
      if (health?.ok) break;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    if (!health?.ok) throw new Error(`drill FAILED: the service did not come up on the restored copy\n${output}`);
    const page = await fetch(base, { signal: AbortSignal.timeout(10_000) });
    if (!page.ok) throw new Error(`drill FAILED: the restored service answered ${page.status} for the page`);
  } finally {
    server.kill("SIGTERM");
    // Wait for the process to let go before the caller deletes anything: SQLite in WAL mode
    // keeps two companion files, and PostgreSQL will not drop a database with a session open.
    await Promise.race([
      new Promise((resolve) => server.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 5_000)),
    ]);
  }
}
