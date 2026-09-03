/**
 * Operational health, for the person who runs the machine (point 85).
 *
 * `GET /healthz` (routes/static.ts) answers the proxy: two words, no authentication, and it
 * is all a liveness probe may reveal to the internet. This route is the other half — uptime,
 * CPU, memory, disk, database, error rate and latency — and it is administrator-only,
 * because the same numbers that tell an operator the disk is filling tell an attacker how
 * much traffic the service takes and how close it is to falling over.
 *
 * Everything below is a number the process already has: `process`, `node:os` and one
 * `SELECT 1`. No agent, no exporter, no third party, and nothing derived from a request
 * body — see `docs/OBSERVABILITY.md` and `test/observability.test.ts`, which fails if this
 * response ever grows a field that is not a number, a boolean or a fixed word.
 */
import { statfs } from "node:fs/promises";
import { dirname } from "node:path";
import { freemem, loadavg, totalmem, cpus } from "node:os";
import type { FastifyInstance } from "fastify";
import { requestMetrics } from "../lib/metrics.ts";
import { isLockedDown } from "../lib/lockdown.ts";

/** CPU time this process has used, as a share of one core, since it started. */
function cpuPercent(): number {
  const { user, system } = process.cpuUsage();
  const elapsedMicroseconds = process.uptime() * 1_000_000;
  if (elapsedMicroseconds <= 0) return 0;
  return Math.round(((user + system) / elapsedMicroseconds) * 1000) / 10;
}

/**
 * Free space on the filesystem that holds the data. SQLite lives in a file whose directory
 * is known; PostgreSQL is somebody else's disk, so the answer is the working directory —
 * where the process would still fail first if it filled up.
 */
async function disk(path: string): Promise<{ totalBytes: number; availableBytes: number }> {
  try {
    const stats = await statfs(path);
    return {
      totalBytes: stats.blocks * stats.bsize,
      availableBytes: stats.bavail * stats.bsize,
    };
  } catch {
    // A container can be built without the directory this reads; a missing number is
    // better than a health check that reports the whole service unhealthy because of it.
    return { totalBytes: 0, availableBytes: 0 };
  }
}

export async function registerHealthRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;
  const dataPath = config.dialect === "sqlite" ? dirname(config.sqlitePath) : process.cwd();

  app.get("/api/admin/health", async (request) => {
    await app.requireRole(request, ["admin"]);
    await app.limit(request, "read");

    const startedAt = performance.now();
    let databaseOk = true;
    try {
      await db.get("SELECT 1 AS ok");
    } catch {
      // The reason belongs in the error log, not in an HTTP body: a driver message names
      // hosts, ports and paths.
      databaseOk = false;
    }
    const databaseLatencyMs = Math.round((performance.now() - startedAt) * 1000) / 1000;

    return {
      status: databaseOk ? "ok" : "degraded",
      // Whether the operator's freeze is on (ADR-0080). A boolean, and the first thing to
      // check when every write in the service is answering 503.
      lockdown: await isLockedDown(db),
      uptimeSeconds: Math.round(process.uptime()),
      process: {
        cpuPercent: cpuPercent(),
        rssBytes: process.memoryUsage.rss(),
        heapUsedBytes: process.memoryUsage().heapUsed,
      },
      system: {
        cpuCount: cpus().length,
        loadAverage1: Math.round((loadavg()[0] ?? 0) * 100) / 100,
        memoryTotalBytes: totalmem(),
        memoryFreeBytes: freemem(),
      },
      disk: await disk(dataPath),
      database: { ok: databaseOk, latencyMs: databaseLatencyMs, dialect: db.dialect },
      requests: requestMetrics(),
    };
  });
}
