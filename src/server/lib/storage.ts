/**
 * The last line in front of a full disk.
 *
 * Blob writes — an order delivery, a message attachment — are the only requests that turn
 * megabytes of somebody else's bytes into disk, and the rate limiter cannot see disk: a
 * dozen accounts staying inside the `attachment` bucket still fill a small VPS in a day,
 * and a SQLite database that cannot write is an outage for everything, not just uploads.
 *
 * So an upload asks first. Below the floor the answer is 503 `storage_full`, which is a
 * refusal a client can retry later and an operator can alert on, rather than a database
 * error at three in the morning. Reads, deletions and messages are unaffected — the point
 * is to keep the service running while somebody frees space.
 */
import { statfs } from "node:fs/promises";
import { HttpError } from "./errors.ts";

/** Cached briefly: a statfs per upload is a syscall per megabyte-sized request, for a number that moves slowly. */
let cached: { at: number; available: number } | null = null;
const CACHE_MS = 5_000;

export async function availableBytes(path: string, now = Date.now()): Promise<number> {
  if (cached && now - cached.at < CACHE_MS) return cached.available;
  try {
    const stats = await statfs(path);
    cached = { at: now, available: stats.bavail * stats.bsize };
  } catch {
    // If the filesystem cannot be inspected, do not invent a reason to refuse writes:
    // the check is a safety margin, not an authorisation decision.
    cached = { at: now, available: Number.MAX_SAFE_INTEGER };
  }
  return cached.available;
}

/**
 * Refuse a write that would land on a filesystem with less than `floorBytes` free, plus
 * the size of the write itself. `floorBytes` of 0 disables the check.
 */
export async function requireSpaceFor(
  path: string,
  bytes: number,
  floorBytes: number,
): Promise<void> {
  if (floorBytes <= 0) return;
  const available = await availableBytes(path);
  if (available - bytes < floorBytes) {
    throw new HttpError(
      503,
      "storage_full",
      "storage is full on this server; try again later",
    );
  }
}

/** Tests write and free space in the same second; nothing in the server calls this. */
export function resetStorageCache(): void {
  cached = null;
}
