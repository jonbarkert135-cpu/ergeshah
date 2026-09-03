/**
 * Point 52: the incident procedures are only as real as the commands they tell an
 * operator to run. These tests run `scripts/incident.mjs` against a real database file —
 * a procedure that has never been executed is a wish, not a plan.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "../src/server/db/migrate.ts";
import { createSqliteDb } from "../src/server/db/sqlite.ts";
import type { Db } from "../src/server/db/index.ts";

const script = new URL("../scripts/incident.mjs", import.meta.url).pathname;
let workspace = "";
let dbPath = "";
let db: Db;

function run(args: string[]): string {
  return execFileSync(process.execPath, [script, ...args, "--db", dbPath], { encoding: "utf8" });
}

async function seed(): Promise<void> {
  for (const [id, username] of [
    ["u-alice", "alice"],
    ["u-mallory", "mallory"],
  ]) {
    await db.run(
      `INSERT INTO users (id, username, password_hash, role, status, created_day)
       VALUES (?, ?, 'hash', 'user', 'active', 1)`,
      [id, username],
    );
    await db.run(
      `INSERT INTO sessions (id, user_id, token_hash, label, created_at, expires_at, last_seen_day)
       VALUES (?, ?, ?, NULL, 0, ?, 1)`,
      [`s-${id}`, id, `hash-${id}`, Date.now() + 86_400_000],
    );
    await db.run(
      `INSERT INTO devices (id, user_id, label, identity_key, signed_prekey_id, signed_prekey,
                            signed_prekey_signature, created_day, rotated_day)
       VALUES (?, ?, NULL, ?, 1, 'spk', 'sig', 1, 1)`,
      [`d-${id}`, id, `identity-${id}`],
    );
    await db.run(
      "INSERT INTO one_time_prekeys (id, device_id, key_id, public_key) VALUES (?, ?, 1, 'otk')",
      [`otk-${id}`, `d-${id}`],
    );
    await db.run(
      `INSERT INTO envelopes (id, recipient_device_id, channel, payload, invite, created_at, expires_at)
       VALUES (?, ?, 'channel', 'ciphertext', NULL, 0, ?)`,
      [`e-${id}`, `d-${id}`, Date.now() + 86_400_000],
    );
  }
}

beforeEach(async () => {
  workspace = mkdtempSync(join(tmpdir(), "symvolon-incident-"));
  dbPath = join(workspace, "live.sqlite");
  db = createSqliteDb(dbPath);
  await migrate(db);
  await seed();
});

afterEach(async () => {
  await db.close();
  rmSync(workspace, { recursive: true, force: true });
});

describe("before it touches anything", () => {
  it("shows the blast radius", () => {
    const output = run(["status"]);
    expect(output).toMatch(/accounts: *2/);
    expect(output).toMatch(/sessions: *2/);
    expect(output).toMatch(/devices: *2/);
  });

  it("refuses every destructive command without --yes", () => {
    for (const command of [
      ["sessions:revoke-all"],
      ["sessions:revoke", "alice"],
      ["devices:revoke", "alice"],
      ["suspend", "alice"],
      ["reinstate", "alice"],
      ["links:purge"],
    ]) {
      expect(() => run(command), command.join(" ")).toThrow(/--yes/);
    }
    expect(run(["status"])).toMatch(/sessions: *2/);
  });

  it("refuses a database file that does not exist instead of creating an empty one", () => {
    expect(() =>
      execFileSync(process.execPath, [script, "status", "--db", join(workspace, "absent.sqlite")], {
        encoding: "utf8",
      }),
    ).toThrow(/no such database/);
  });

  it("refuses a PostgreSQL deployment loudly, with the SQL to run instead", () => {
    expect(() =>
      execFileSync(process.execPath, [script, "status", "--db", dbPath], {
        encoding: "utf8",
        env: { ...process.env, DATABASE_URL: "postgres://localhost/symvolon" },
      }),
    ).toThrow(/SQLite only[\s\S]*DELETE FROM sessions;/);
  });
});

describe("revoking sessions", () => {
  it("ends every session on the deployment", async () => {
    expect(run(["sessions:revoke-all", "--yes"])).toMatch(/revoked 2 session/);
    expect(await db.all("SELECT id FROM sessions")).toEqual([]);
    // Accounts, devices and undelivered ciphertext survive: this is a logout, not a purge.
    expect((await db.all("SELECT id FROM users")).length).toBe(2);
    expect((await db.all("SELECT id FROM envelopes")).length).toBe(2);
  });

  it("ends one account's sessions and leaves the others signed in", async () => {
    expect(run(["sessions:revoke", "mallory", "--yes"])).toMatch(/revoked 1 session\(s\) of @mallory/);
    const rows = await db.all<{ user_id: string }>("SELECT user_id FROM sessions");
    expect(rows.map((row) => row.user_id)).toEqual(["u-alice"]);
  });

  it("says so instead of guessing when the account does not exist", () => {
    expect(() => run(["sessions:revoke", "nobody", "--yes"])).toThrow(/no account named/);
  });
});

describe("revoking devices", () => {
  it("marks them revoked and deletes what they could no longer read", async () => {
    const output = run(["devices:revoke", "mallory", "--yes"]);
    expect(output).toMatch(/revoked 1 device/);
    expect(output).toMatch(/sessions are separate/);
    const device = await db.get<{ revoked_at: number | null }>(
      "SELECT revoked_at FROM devices WHERE id = 'd-u-mallory'",
    );
    expect(device?.revoked_at).toBeGreaterThan(0);
    expect(await db.all("SELECT id FROM one_time_prekeys WHERE device_id = 'd-u-mallory'")).toEqual(
      [],
    );
    expect(await db.all("SELECT id FROM envelopes WHERE recipient_device_id = 'd-u-mallory'")).toEqual(
      [],
    );
    // Alice's device is untouched.
    expect((await db.all("SELECT id FROM envelopes")).length).toBe(1);
  });
});

describe("suspending an account", () => {
  it("fails its sessions closed and can be undone", async () => {
    run(["suspend", "mallory", "--reason", "under investigation", "--yes"]);
    let row = await db.get<{ status: string; status_reason: string | null }>(
      "SELECT status, status_reason FROM users WHERE username = 'mallory'",
    );
    expect(row?.status).toBe("suspended");
    expect(row?.status_reason).toBe("under investigation");

    run(["reinstate", "mallory", "--yes"]);
    row = await db.get("SELECT status, status_reason FROM users WHERE username = 'mallory'");
    expect(row?.status).toBe("active");
    expect(row?.status_reason).toBeNull();
  });
});

describe("what it refuses to be", () => {
  it("has no command that reads a message, a vault or a password hash", () => {
    const source = readFileSync(script, "utf8");
    // The point of the architecture is that no operator tool can do these. A break-glass
    // script is exactly where that promise erodes, so it is asserted rather than trusted.
    expect(source).not.toMatch(/SELECT[^;]*\bpayload\b/i);
    expect(source).not.toMatch(/\bFROM vaults\b/i);
    expect(source).not.toMatch(/password_hash\s*=/i);
    expect(source).not.toMatch(/INSERT INTO sessions/i);
  });

  it("is the tool docs/INCIDENT_RESPONSE.md tells the operator to run", () => {
    const doc = readFileSync(new URL("../docs/INCIDENT_RESPONSE.md", import.meta.url), "utf8");
    for (const command of [
      "sessions:revoke-all",
      "sessions:revoke",
      "devices:revoke",
      "suspend",
      "links:purge",
      "status",
    ]) {
      expect(doc, `${command} is not in the procedure`).toContain(`incident ${command}`);
    }
  });
});

describe("the freeze (ADR-0080)", () => {
  it("turns every write off, keeps the books, and can be lifted", async () => {
    const engaged = run(["lockdown:on", "--note", "unexplained admin login", "--yes"]);
    expect(engaged).toContain("lockdown ON");
    // What it is *not*: a deletion. The accounts, sessions and history are all still there —
    // the ledger is the record of what this platform owes people.
    expect(await db.all("SELECT id FROM users")).toHaveLength(2);
    expect(await db.all("SELECT id FROM sessions")).toHaveLength(2);
    const row = await db.get<{ note: string }>("SELECT note FROM lockdown WHERE id = 1");
    expect(row?.note).toBe("unexplained admin login");
    // And it is in the audit log with no actor, because nobody was signed in.
    const audited = await db.get<{ action: string; actor_user_id: string | null }>(
      "SELECT action, actor_user_id FROM audit_log ORDER BY created_at DESC",
    );
    expect(audited).toMatchObject({ action: "platform.locked_down", actor_user_id: null });

    expect(run(["status"])).toContain("lockdown:          ON");
    // Throwing it twice is not an error: an operator repeating a command at 3am should not
    // have to think about whether it already worked.
    expect(run(["lockdown:on", "--note", "again", "--yes"])).toContain("lockdown ON");
    expect(await db.all("SELECT id FROM lockdown")).toHaveLength(1);

    expect(run(["lockdown:off", "--yes"])).toContain("writes accepted again");
    expect(await db.all("SELECT id FROM lockdown")).toHaveLength(0);
    expect(run(["lockdown:off", "--yes"])).toContain("was not on");
    expect(run(["status"])).toContain("lockdown:          off");
  });

  it("refuses to freeze without --yes", () => {
    expect(() => run(["lockdown:on"])).toThrow(/--yes/);
  });
});
