import { loadConfig } from "./config.ts";
import { createDb } from "./db/index.ts";
import { migrate } from "./db/migrate.ts";
import { buildApp } from "./app.ts";
import { pruneSessions } from "./lib/sessions.ts";
import { pruneRateLimits } from "./lib/rate_limit.ts";
import { pruneAuditLog } from "./lib/audit.ts";
import { backfillSearchIndex } from "./lib/search.ts";
import { pruneNotifications } from "./lib/notify.ts";
import { log } from "./lib/log.ts";

const config = loadConfig();
const db = await createDb(config);
await migrate(db);
await backfillSearchIndex(db);
const app = await buildApp(config, db);

/** Housekeeping: expired sessions, envelopes, buckets, audit entries and notifications. */
const housekeeping = setInterval(
  () => {
    void (async () => {
      try {
        await pruneSessions(db);
        await pruneRateLimits(db);
        await db.run("DELETE FROM envelopes WHERE expires_at < ?", [Date.now()]);
        await pruneAuditLog(db, config.auditRetentionMs);
        await pruneNotifications(db, config.notificationRetentionMs);
      } catch (error) {
        log({ level: "error", event: "housekeeping.failed", message: (error as Error).message });
      }
    })();
  },
  60 * 60 * 1000,
);
housekeeping.unref();

await app.listen({ host: config.host, port: config.port });
log({
  level: "info",
  event: "listening",
  message: `${config.host}:${config.port} (${config.dialect}, ${config.env})`,
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void (async () => {
      clearInterval(housekeeping);
      await app.close();
      await db.close();
      process.exit(0);
    })();
  });
}
