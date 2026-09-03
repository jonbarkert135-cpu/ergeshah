import { loadConfig } from "./config.ts";
import { createDb } from "./db/index.ts";
import { migrate } from "./db/migrate.ts";
import { buildApp } from "./app.ts";
import { pruneSessions } from "./lib/sessions.ts";
import { pruneRateLimits } from "./lib/rate_limit.ts";
import { pruneAuditLog } from "./lib/audit.ts";
import { backfillSearchIndex } from "./lib/search.ts";
import { pruneNotifications } from "./lib/notify.ts";
import { scanDeposits, solvency } from "./lib/deposits.ts";
import { quietly } from "./lib/monero.ts";
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
        await pruneSessions(db, config.sessionIdleDays);
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

/**
 * The deposit watcher (ADR-0070). Separate from housekeeping because it runs on a different
 * clock: a top-up should appear within a minute of confirming, and pruning sessions should
 * not happen forty times an hour. It is best-effort by construction — a wallet that is down
 * is a scan that runs again in `WALLET_POLL_SECONDS`, never a request that fails — and it
 * exists only when this deployment has a wallet tier.
 */
const watcher = app.wallet
  ? setInterval(() => {
      void (async () => {
        await quietly("wallet.scan_failed", () =>
          scanDeposits(db, app.wallet!, {
            minConfirmations: config.depositConfirmations,
            minPico: config.minDepositPico,
          }),
        );
        // Solvency on the same clock: the comparison is one RPC call and one SUM, and its
        // whole value is that nobody has to remember to look (docs/PAYMENTS.md §Custody).
        await quietly("treasury.solvency_failed", () => solvency(db, app.wallet!));
      })();
    }, config.walletPollMs)
  : null;
watcher?.unref();

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
      if (watcher) clearInterval(watcher);
      await app.close();
      await db.close();
      process.exit(0);
    })();
  });
}
