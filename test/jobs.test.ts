/**
 * Background jobs: ordered, and isolated from each other (ADR-0079).
 *
 * This exists because of a bug that produced no error anybody would see. The hourly
 * housekeeping ran six prunes inside one `try`, so a statement timeout on the first was
 * silently also five prunes that never ran — sessions, audit entries and notifications kept
 * forever, and the only symptom a full disk months later.
 */
import { describe, expect, it } from "vitest";
import { runJobs } from "../src/server/lib/jobs.ts";

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
});
