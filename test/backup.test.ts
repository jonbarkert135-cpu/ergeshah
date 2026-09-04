/**
 * Point 50: a backup is only a backup once it has been restored.
 *
 * These tests run the real script against a real database file, because the failure modes
 * that matter — a wrong key, a flipped byte, a snapshot of a WAL database that does not open —
 * only appear when bytes actually move.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { migrate } from "../src/server/db/migrate.ts";
import { createSqliteDb } from "../src/server/db/sqlite.ts";

const script = new URL("../scripts/backup.mjs", import.meta.url).pathname;
let workspace = "";
let keyPath = "";
let dbPath = "";

function run(args: string[]): string {
  return execFileSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

beforeAll(async () => {
  workspace = mkdtempSync(join(tmpdir(), "symvolon-backup-"));
  keyPath = join(workspace, "backup.key");
  writeFileSync(keyPath, run(["keygen"]));
  dbPath = join(workspace, "live.sqlite");
  const db = createSqliteDb(dbPath);
  await migrate(db);
  await db.run(
    "INSERT INTO users (id, username, password_hash, role, status, created_day) VALUES ('backupuser1', 'backupuser', 'hash', 'user', 'active', 1)",
  );
  await db.close();
});

afterAll(() => {
  rmSync(workspace, { recursive: true, force: true });
});

describe("creating", () => {
  it("writes an encrypted, verified, timestamped file and no plaintext", () => {
    const out = join(workspace, "backups");
    const output = run(["create", "--key", keyPath, "--db", dbPath, "--out", out]);
    expect(output).toMatch(/integrity ok/);
    expect(output).toMatch(/1 accounts/);
    const files = readdirSync(out);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^symvolon-\d{4}-\d{2}-\d{2}T\d{6}Z\.sqlite\.enc$/);
    const bytes = readFileSync(join(out, files[0]!));
    // Not a SQLite file, and the username is not sitting in it in the clear.
    expect(bytes.subarray(0, 8).toString()).toBe("SYMVBK1\n");
    expect(bytes.toString("binary")).not.toContain("SQLite format 3");
    expect(bytes.toString("binary")).not.toContain("backupuser");
  });

  it("refuses to run without a key", () => {
    expect(() => run(["create", "--db", dbPath, "--out", join(workspace, "nokey")])).toThrow(
      /--key/,
    );
  });

  it("has no code path that writes an unencrypted snapshot to the backup directory", () => {
    const source = readFileSync(script, "utf8");
    // Every write to the destination goes through encrypt(); the only plaintext on disk is a
    // scratch file in the temp directory — one in `inspect`, one in `snapshot`, one for the
    // drill's copy — and each is deleted in a finally block.
    expect(source).toMatch(/writeFileSync\(path, sealed/);
    expect(source.match(/writeFileSync\(/g)?.length).toBeLessThanOrEqual(4);
  });
});

describe("scratch files", () => {
  // SEC-2026-016: the plaintext snapshot used to be created straight in /tmp, 0644 under the
  // usual umask — the whole database readable by any other account on the host for as long
  // as it existed. Every scratch now lives in a mkdtemp directory (0700) and is 0600 itself.
  it("keeps every plaintext scratch inside a private directory, and leaves none behind", () => {
    const source = readFileSync(script, "utf8");
    expect(source).not.toMatch(/join\(tmpdir\(\), `symvolon-(snapshot|verify|drill)/);
    expect(source.match(/privateScratchDir\(\)/g)?.length).toBeGreaterThanOrEqual(4);
    expect(source).toMatch(/mkdtempSync\(join\(tmpdir\(\), "symvolon-"\)\)/);
    expect(source).toMatch(/chmodSync\(scratch, 0o600\)/);
    expect(source).toMatch(/writeFileSync\(scratch, bytes, \{ mode: 0o600 \}\)/);

    // Empirically: run a create and a verify with TMPDIR pointed at an empty directory.
    const scratchRoot = mkdtempSync(join(tmpdir(), "symvolon-scratch-probe-"));
    try {
      const out = join(workspace, "scratch-probe");
      execFileSync(process.execPath, [script, "create", "--db", dbPath, "--key", keyPath, "--out", out], {
        encoding: "utf8",
        env: { ...process.env, TMPDIR: scratchRoot },
      });
      const [file] = readdirSync(out);
      execFileSync(process.execPath, [script, "verify", join(out, file!), "--key", keyPath], {
        encoding: "utf8",
        env: { ...process.env, TMPDIR: scratchRoot },
      });
      expect(readdirSync(scratchRoot)).toEqual([]);
    } finally {
      rmSync(scratchRoot, { recursive: true, force: true });
    }
  });
});

describe("restoring", () => {
  it("round-trips: the restored database is the database", () => {
    const out = join(workspace, "roundtrip");
    run(["create", "--key", keyPath, "--db", dbPath, "--out", out]);
    const file = join(out, readdirSync(out)[0]!);
    expect(run(["verify", file, "--key", keyPath])).toMatch(/decrypts, integrity ok/);
    const target = join(workspace, "restored.sqlite");
    run(["restore", file, target, "--key", keyPath]);
    const restored = new DatabaseSync(target, { readOnly: true });
    try {
      const row = restored.prepare("SELECT username FROM users").get() as { username: string };
      expect(row.username).toBe("backupuser");
    } finally {
      restored.close();
    }
  });

  it("refuses a wrong key, a tampered file and an overwrite", () => {
    const out = join(workspace, "tamper");
    run(["create", "--key", keyPath, "--db", dbPath, "--out", out]);
    const file = join(out, readdirSync(out)[0]!);

    const wrongKey = join(workspace, "wrong.key");
    writeFileSync(wrongKey, run(["keygen"]));
    expect(() => run(["verify", file, "--key", wrongKey])).toThrow();

    const bytes = readFileSync(file);
    bytes[bytes.length - 40] = (bytes[bytes.length - 40] ?? 0) ^ 0xff;
    const edited = join(workspace, "edited.enc");
    writeFileSync(edited, bytes);
    expect(() => run(["verify", edited, "--key", keyPath])).toThrow();

    const target = join(workspace, "restored-once.sqlite");
    run(["restore", file, target, "--key", keyPath]);
    // A restore never overwrites: pointing it at a live database by mistake must fail.
    expect(() => run(["restore", file, target, "--key", keyPath])).toThrow();
  });

  it("rejects a file that is not a Symvolon backup", () => {
    const alien = join(workspace, "alien.enc");
    writeFileSync(alien, Buffer.alloc(200, 7));
    expect(() => run(["verify", alien, "--key", keyPath])).toThrow(/bad header|too short/);
  });
});

describe("the drill", () => {
  it("restores the newest backup and starts a real service on it", () => {
    const out = join(workspace, "drill-backups");
    run(["create", "--key", keyPath, "--db", dbPath, "--out", out]);
    // The question `verify` cannot answer: does the service come up on this file? The
    // command boots a server in production mode against a temporary copy on a random port.
    const output = run(["drill", "--key", keyPath, "--out", out]);
    expect(output).toMatch(/\/healthz ok, page ok/);
    expect(output).toMatch(/1 accounts/);
    expect(output).toMatch(/the copy is deleted/);
    // Nothing left behind, and the live database untouched.
    expect(readdirSync(tmpdir()).filter((name) => name.startsWith("symvolon-drill-"))).toEqual([]);
  }, 60_000);

  it("says so loudly when there is nothing to drill", () => {
    const empty = mkdtempSync(join(tmpdir(), "symvolon-empty-"));
    try {
      expect(() => run(["drill", "--key", keyPath, "--out", empty])).toThrow(/no backup to drill/);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});

describe("retention", () => {
  it("deletes what is older than the window but never leaves fewer than --keep", () => {
    const out = join(workspace, "retention");
    // Four versions, aged the way a daily cron would age them. `create` twice in one second
    // would only differ by a suffix, so the ages are set explicitly here.
    run(["create", "--key", keyPath, "--db", dbPath, "--out", out]);
    const template = join(out, readdirSync(out)[0]!);
    for (let i = 1; i <= 3; i += 1) {
      const copy = join(out, `symvolon-2026-08-0${i}T010203Z.sqlite.enc`);
      writeFileSync(copy, readFileSync(template));
      const age = (Date.now() - (i + 40) * 24 * 60 * 60 * 1000) / 1000;
      utimesSync(copy, age, age);
    }
    const before = readdirSync(out).length;
    expect(before).toBeGreaterThanOrEqual(2);

    const kept = run(["prune", "--out", out, "--days", "35", "--keep", String(before)]);
    expect(kept).toMatch(/0 removed/);
    expect(readdirSync(out).length).toBe(before);

    const pruned = run(["prune", "--out", out, "--days", "35", "--keep", "1"]);
    expect(pruned).toMatch(/removed/);
    expect(readdirSync(out).length).toBeGreaterThanOrEqual(1);
    expect(readdirSync(out).length).toBeLessThan(before);
  });

  it("states the policy in docs/BACKUPS.md, where an operator will look for it", () => {
    const doc = readFileSync(new URL("../docs/BACKUPS.md", import.meta.url), "utf8");
    for (const claim of ["35 days", "Retention policy", "Restore drills", "AES-256-GCM"]) {
      expect(doc, claim).toContain(claim);
    }
    // The policy this point exists for: no permanent archive tier.
    expect(doc).toMatch(/Weekly \/ monthly \/ yearly archives \| \*\*none\*\*/);
  });
});
