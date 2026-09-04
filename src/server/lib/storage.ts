/**
 * The last line in front of a full disk — and the sweep, the ceiling and the health state
 * that go with it (points 29, 64, 68, 77, 81).
 *
 * Blob writes — an order delivery, a message attachment — are the only requests that turn
 * megabytes of somebody else's bytes into disk, and the rate limiter cannot see disk: a
 * dozen accounts staying inside the `attachment` bucket still fill a small VPS in a day,
 * and a SQLite database that cannot write is an outage for everything, not just uploads.
 *
 * So an upload asks first, and there are three questions rather than one:
 *
 * 1. **Is there space?** Below the floor the answer is 503 `storage_full`, which is a refusal
 *    a client can retry later and an operator can alert on, rather than a database error at
 *    three in the morning.
 * 2. **Can the filesystem still be read at all?** A `statfs` that fails once is a hiccup and
 *    is ignored; failing repeatedly is a storage layer that has gone away, and a server that
 *    keeps accepting uploads into it is losing them. That is 503 `storage_unavailable`, and it
 *    is deliberately a *degraded* state: reads, messages, orders and deletions carry on
 *    (`docs/OBSERVABILITY.md` §Degraded mode).
 * 3. **Are there already too many objects?** The floor protects bytes, not rows. A million
 *    64-byte blobs cost little disk and a great deal of everything else — index size, sweep
 *    time, backup time. `MAX_BLOB_ROWS` is a ceiling on the count.
 *
 * Reads, deletions and messages are unaffected by all three: the point is to keep the service
 * running while somebody frees space.
 */
import { statfs } from "node:fs/promises";
import type { Db } from "../db/index.ts";
import { HttpError } from "./errors.ts";

/** Cached briefly: a statfs per upload is a syscall per megabyte-sized request, for a number that moves slowly. */
let cached: { at: number; available: number } | null = null;
const CACHE_MS = 5_000;

/**
 * Consecutive `statfs` failures, and whether this path has *ever* answered.
 *
 * Both halves matter. One failure is a hiccup, so it takes a few in a row to count as a
 * fault — and a path that never answered at all is not a fault, it is a deployment where this
 * check cannot run: PostgreSQL on somebody else's disk, a container built without the data
 * directory, a test process. Degrading those would refuse every upload on a perfectly healthy
 * server. So the state means: *this filesystem used to answer and has stopped*.
 */
let consecutiveFailures = 0;
let everAnswered = false;
const FAILURES_BEFORE_UNAVAILABLE = 3;

/** Cached row count for the ceiling below. Same reasoning as the free-space cache. */
let counted: { at: number; rows: number } | null = null;
const COUNT_CACHE_MS = 30_000;

export async function availableBytes(path: string, now = Date.now()): Promise<number> {
  if (cached && now - cached.at < CACHE_MS) return cached.available;
  try {
    const stats = await statfs(path);
    consecutiveFailures = 0;
    everAnswered = true;
    cached = { at: now, available: stats.bavail * stats.bsize };
  } catch {
    // If the filesystem cannot be inspected once, do not invent a reason to refuse writes:
    // the check is a safety margin, not an authorisation decision. Repeatedly is different,
    // and `requireSpaceFor` handles that case rather than this one.
    consecutiveFailures += 1;
    // Not cached: a failure has to be retried on the next request, or three failures in a row
    // would take fifteen seconds of cache windows to notice.
    cached = null;
    return Number.MAX_SAFE_INTEGER;
  }
  return cached.available;
}

/**
 * What the health endpoint reports: `ok` while the data filesystem answers, `false` once it
 * has answered before and then stopped often enough to be a fault rather than a blip. It is
 * not a probe — asking `statfs` from a health check would hide exactly the case this exists to
 * show, which is the state the upload path is actually in.
 */
export function storageOk(): boolean {
  return !everAnswered || consecutiveFailures < FAILURES_BEFORE_UNAVAILABLE;
}

/**
 * Whether the free-space check has ever had an answer on this deployment. `false` means the
 * floor and the state above are saying nothing about this server's disk — worth knowing before
 * trusting either (`docs/OBSERVABILITY.md`).
 */
export function storageChecked(): boolean {
  return everAnswered;
}

/**
 * Refuse a write that would land on a filesystem with less than `floorBytes` free, plus
 * the size of the write itself. `floorBytes` of 0 disables the check.
 */
export async function requireSpaceFor(
  path: string,
  bytes: number,
  floorBytes: number,
  /** Only passed by tests, which need two answers from a cache that holds one for five seconds. */
  now = Date.now(),
): Promise<void> {
  if (floorBytes <= 0) return;
  const available = await availableBytes(path, now);
  if (!storageOk()) {
    throw new HttpError(
      503,
      "storage_unavailable",
      "storage is not answering on this server; nothing was stored",
    );
  }
  if (available - bytes < floorBytes) {
    throw new HttpError(
      503,
      "storage_full",
      "storage is full on this server; try again later",
    );
  }
}

/**
 * Refuse a write once the two blob tables together hold `maxRows` rows. `maxRows` of 0
 * disables the ceiling.
 *
 * The count is cached for half a minute, so the ceiling is approximate — with the
 * `attachment` bucket at a dozen uploads a minute, an instance can cross it by a handful of
 * rows before it notices. That is the trade for not running `COUNT(*)` twice per upload, and
 * it is the right one: this is a ceiling on runaway growth, not an accounting boundary.
 */
export async function requireBlobHeadroom(db: Db, maxRows: number): Promise<void> {
  if (maxRows <= 0) return;
  const now = Date.now();
  if (!counted || now - counted.at >= COUNT_CACHE_MS) {
    const row = await db.get<{ rows: number }>(
      `SELECT (SELECT COUNT(*) FROM attachments) + (SELECT COUNT(*) FROM deliveries) AS rows`,
    );
    counted = { at: now, rows: Number(row?.rows ?? 0) };
  }
  if (counted.rows >= maxRows) {
    // Same code as a full disk on purpose: from the client's side it is the same fact — the
    // server is not taking blobs right now — and the operator's distinction is in the ceiling
    // they configured, not in a new error a client would have to learn.
    throw new HttpError(
      503,
      "storage_full",
      "this server is holding as many files as it is configured to hold; try again later",
    );
  }
  counted.rows += 1;
}

/**
 * Delete expired blobs. Idempotent, cheap, and indexed on `expires_at`.
 *
 * It used to run only inside the two blob request handlers, which meant a quiet instance kept
 * expired ciphertext indefinitely — the retention promise held only for servers with traffic
 * (point 77). It now also runs from housekeeping, and the handlers still call it so that a
 * fetch can never serve a blob that should have gone.
 */
export async function pruneBlobs(db: Db, now = Date.now()): Promise<void> {
  await db.run("DELETE FROM deliveries WHERE expires_at < ?", [now]);
  await db.run("DELETE FROM attachments WHERE expires_at < ?", [now]);
}

/**
 * Ask the database whether what it holds is still intact (point 68).
 *
 * SQLite has a real answer — `PRAGMA quick_check` walks the pages and reports corruption —
 * and this project stores blobs *in* the database, so that check covers stored objects as
 * well as rows. PostgreSQL has no equivalent that is cheap enough to run on a timer (a
 * checksum verification is a full read of the cluster), so the honest answer there is a
 * bounded consistency query rather than a claim: an expired-blob count that must be zero
 * right after a sweep. Anything else is a job that pretends.
 *
 * Returns the problem as a string, or null when there is nothing to report. Deliberately not
 * throwing: the caller is a background sweep, and the finding belongs in a log line.
 */
export async function checkStorageIntegrity(db: Db): Promise<string | null> {
  if (db.dialect === "sqlite") {
    // `quick_check` rather than `integrity_check`: it skips the (expensive) index-versus-table
    // cross-check, which is the part that turns a routine sweep into a load spike.
    const row = await db.get<Record<string, unknown>>("PRAGMA quick_check(1)");
    const answer = row ? String(Object.values(row)[0] ?? "") : "";
    return answer.toLowerCase() === "ok" ? null : "quick_check";
  }
  const row = await db.get<{ stale: number }>(
    `SELECT (SELECT COUNT(*) FROM attachments WHERE expires_at < ?)
          + (SELECT COUNT(*) FROM deliveries WHERE expires_at < ?) AS stale`,
    [Date.now(), Date.now()],
  );
  return Number(row?.stale ?? 0) > 0 ? "expired_blobs_present" : null;
}

/** Tests write and free space in the same second; nothing in the server calls this. */
export function resetStorageCache(): void {
  cached = null;
  counted = null;
  consecutiveFailures = 0;
  everAnswered = false;
}
