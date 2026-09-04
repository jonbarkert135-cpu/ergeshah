/**
 * Background work: ordered by importance, isolated from each other (ADR-0079).
 *
 * This is what is left of a proposal for in-memory priority queues (ADR-0075). The durable
 * queues this system needs already exist as tables — an order and its escrow are one
 * transaction, a payout waits in `withdrawals` with an atomic claim — so a queue in memory
 * would only add a way to lose them at a restart. What the proposal did find is a real bug:
 * the hourly housekeeping ran every prune inside a single `try`, so the first failure
 * cancelled everything after it. A statement timeout on the session prune meant audit
 * entries, notifications and rate-limit buckets were never pruned at all, silently, until
 * the disk filled.
 *
 * Two rules, and they are the whole module:
 *
 * 1. **Order is priority.** Jobs run in the order given, highest first, so a slow
 *    low-priority sweep never delays the one that keeps the service correct.
 * 2. **One failure is one failure.** Every job gets its own `try`, its own log line naming
 *    it, and the rest still run. A job that throws is a metric, not an outage.
 *
 * Deliberately not a scheduler: no persistence, no retries, no cron expressions. These are
 * idempotent sweeps that run again on the next tick, and anything that must not be lost
 * belongs in a table instead.
 */
import { log } from "./log.ts";

export interface Job {
  /** A stable name, logged on failure. From this codebase, never from a request. */
  name: string;
  run: () => Promise<unknown>;
}

export interface JobsResult {
  ran: number;
  failed: string[];
}

/**
 * The last result, for the health endpoint (point 64). A queue with no state is a queue an
 * operator finds out about from a user, and the only thing this module knows worth reporting
 * is: did the sweeps run, and did any of them fail. Names stay in the log; the endpoint gets
 * counts, because a health document that grows strings is a health document that eventually
 * grows somebody's data (`docs/OBSERVABILITY.md`).
 */
let lastRun: { at: number; result: JobsResult } | null = null;

export function lastJobsRun(): { ranAgoSeconds: number; ran: number; failed: number } | null {
  if (!lastRun) return null;
  return {
    ranAgoSeconds: Math.round((Date.now() - lastRun.at) / 1000),
    ran: lastRun.result.ran,
    failed: lastRun.result.failed.length,
  };
}

/** Tests run the sweep list more than once in a process; nothing in the server calls this. */
export function resetJobsHistory(): void {
  lastRun = null;
}

/**
 * Runs each job in order, isolating failures. Never throws: the caller is a timer, and a
 * timer that rejects is an unhandled rejection in the logs and no cleanup for an hour.
 */
export async function runJobs(jobs: Job[]): Promise<JobsResult> {
  const result: JobsResult = { ran: 0, failed: [] };
  for (const job of jobs) {
    try {
      await job.run();
      result.ran += 1;
    } catch (error) {
      result.failed.push(job.name);
      // The name and the message from the failure, which is this codebase's or the driver's.
      // No arguments, no rows, no counts of anybody's anything (docs/LOGGING.md).
      log({ level: "error", event: `job.failed.${job.name}`, message: (error as Error).message });
    }
  }
  lastRun = { at: Date.now(), result };
  return result;
}
