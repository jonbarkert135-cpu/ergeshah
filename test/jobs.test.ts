/**
 * Background jobs: ordered, isolated from each other (ADR-0079), idempotent (point 32), and
 * now reporting a state an operator can read (point 64).
 *
 * The runner tests exist because of a bug that produced no error anybody would see. The hourly
 * housekeeping ran six prunes inside one `try`, so a statement timeout on the first was
 * silently also five prunes that never ran — sessions, audit entries and notifications kept
 * forever, and the only symptom a full disk months later.
 *
 * The sweep tests below exist for the opposite reason: the retention promise in
 * `docs/DELETION.md` used to depend on traffic, because expired blobs were only deleted by the
 * requests that touched them.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { lastJobsRun, resetJobsHistory, runJobs } from "../src/server/lib/jobs.ts";
import {
  checkStorageIntegrity,
  pruneBlobs,
  requireBlobHeadroom,
  resetStorageCache,
} from "../src/server/lib/storage.ts";
import { pruneAuditLog } from "../src/server/lib/audit.ts";
import { pruneNotifications } from "../src/server/lib/notify.ts";
import { pruneRateLimits } from "../src/server/lib/rate_limit.ts";
import { pruneSecurityEvents } from "../src/server/lib/security_events.ts";
import { pruneSendTokens } from "../src/server/lib/send_tokens.ts";
import { pruneSessions } from "../src/server/lib/sessions.ts";
import { decaySellerLevels } from "../src/server/lib/reputation.ts";
import { register, startTestServer, type TestServer } from "./helpers.ts";
import { listTables } from "./database.ts";
import { newId } from "../src/server/lib/ids.ts";

describe("runJobs", () => {
  it("runs jobs in the order given, which is what makes the order a priority", async () => {
    const ran: string[] = [];
    const result = await runJobs(
      ["sessions", "buckets", "levels"].map((name) => ({
        name,
        run: async () => {
          ran.push(name);
        },
      })),
    );
    expect(ran).toEqual(["sessions", "buckets", "levels"]);
    expect(result).toEqual({ ran: 3, failed: [] });
  });

  it("keeps going after a failure, and names the job that failed", async () => {
    const ran: string[] = [];
    const result = await runJobs([
      {
        name: "sessions",
        run: () => Promise.reject(new Error("statement timeout")),
      },
      { name: "audit_log", run: async () => void ran.push("audit_log") },
      { name: "notifications", run: async () => void ran.push("notifications") },
    ]);
    // The two later jobs ran: this is the whole point of the module.
    expect(ran).toEqual(["audit_log", "notifications"]);
    expect(result).toEqual({ ran: 2, failed: ["sessions"] });
  });

  it("never throws, because its caller is a timer", async () => {
    await expect(
      runJobs([{ name: "everything", run: () => Promise.reject(new Error("nope")) }]),
    ).resolves.toEqual({ ran: 0, failed: ["everything"] });
  });

  it("remembers the last run as counts, so health can report it without naming anything", async () => {
    resetJobsHistory();
    expect(lastJobsRun()).toBeNull();
    await runJobs([
      { name: "sessions", run: async () => undefined },
      { name: "blobs", run: () => Promise.reject(new Error("gone")) },
    ]);
    const last = lastJobsRun();
    expect(last).toEqual({ ranAgoSeconds: 0, ran: 1, failed: 1 });
  });
});

describe("the sweeps, against a real database", () => {
  let server: TestServer;

  beforeAll(async () => {
    server = await startTestServer();
  });
  afterAll(async () => {
    await server.close();
  });

  /** Every table, and how many rows it holds. The shape of the whole database in one object. */
  async function snapshot(): Promise<Record<string, number>> {
    const counts: Record<string, number> = {};
    for (const table of await listTables(server.db)) {
      // Table names come from `listTables` on the schema this test created, never from a
      // request, and counting every one of them is the point. audit:allow sql-interpolation
      const row = await server.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`);
      counts[table] = Number(row?.n ?? 0);
    }
    return counts;
  }

  /** The list `src/server/main.ts` runs hourly, with the same names and the same order. */
  function housekeeping() {
    const { db, config } = server;
    return [
      { name: "sessions", run: () => pruneSessions(db, config.sessionIdleDays) },
      { name: "rate_limits", run: () => pruneRateLimits(db) },
      { name: "envelopes", run: () => db.run("DELETE FROM envelopes WHERE expires_at < ?", [Date.now()]) },
      { name: "audit_log", run: () => pruneAuditLog(db, config.auditRetentionMs) },
      { name: "security_events", run: () => pruneSecurityEvents(db, config.securityEventRetentionDays) },
      { name: "send_tokens", run: () => pruneSendTokens(db) },
      { name: "blobs", run: () => pruneBlobs(db) },
      { name: "notifications", run: () => pruneNotifications(db, config.notificationRetentionMs) },
      {
        name: "seller_levels",
        run: () => decaySellerLevels(db, { decayDays: config.sellerLevelDecayDays }),
      },
    ];
  }

  it("deletes an expired blob with no request to trigger it (point 77)", async () => {
    const past = Date.now() - 1;
    await server.db.run(
      "INSERT INTO attachments (id, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?)",
      [newId(), "AAAA", past, past],
    );
    const live = newId();
    await server.db.run(
      "INSERT INTO attachments (id, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?)",
      [live, "BBBB", Date.now(), Date.now() + 60_000],
    );

    await pruneBlobs(server.db);

    const rows = await server.db.all<{ id: string }>("SELECT id FROM attachments");
    expect(rows.map((row) => row.id)).toEqual([live]);
  });

  it("changes nothing on a second pass: every sweep is idempotent (point 32)", async () => {
    // Something in most tables, and expired rows in the ones with a retention rule.
    await register(server, "sweeper");
    const past = Date.now() - 1;
    await server.db.run(
      "INSERT INTO attachments (id, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?)",
      [newId(), "CCCC", past, past],
    );
    await server.db.run("INSERT INTO rate_limits (bucket, tokens, updated_at) VALUES (?, ?, ?)", [
      "expired-bucket",
      0,
      past - 48 * 60 * 60 * 1000,
    ]);

    await runJobs(housekeeping());
    const first = await snapshot();
    await runJobs(housekeeping());
    const second = await snapshot();

    expect(second).toEqual(first);
    expect(lastJobsRun()).toMatchObject({ ran: housekeeping().length, failed: 0 });
  });

  it("refuses another blob once the configured ceiling is reached (point 81)", async () => {
    resetStorageCache();
    const held = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM attachments");
    const ceiling = Number(held?.n ?? 0);

    // At the ceiling: refused, with the same code a full disk uses.
    await expect(requireBlobHeadroom(server.db, ceiling)).rejects.toMatchObject({
      statusCode: 503,
      code: "storage_full",
    });
    // Below it: allowed, and a ceiling of zero is no ceiling at all.
    resetStorageCache();
    await expect(requireBlobHeadroom(server.db, ceiling + 5)).resolves.toBeUndefined();
    resetStorageCache();
    await expect(requireBlobHeadroom(server.db, 0)).resolves.toBeUndefined();
  });

  it("finds nothing wrong with a database that is intact (point 68)", async () => {
    await pruneBlobs(server.db);
    expect(await checkStorageIntegrity(server.db)).toBeNull();
  });
});
