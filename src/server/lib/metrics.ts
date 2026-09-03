/**
 * What monitoring is allowed to know (point 85).
 *
 * A production service has to answer "is it up, is it failing, is it slow" without becoming
 * the surveillance it refuses to be elsewhere. So this module counts and times, and that is
 * the whole vocabulary: totals per status class, a ring of recent durations, the slowest
 * one seen. No URL, no route, no account, no address, no body — nothing here can be joined
 * back to a person, because nothing here identifies one.
 *
 * It is deliberately in memory and per process: a restart resets it, which is correct for a
 * gauge whose only reader is `GET /api/admin/health`. Persisting it would create the
 * time series that an access log is, one aggregate at a time.
 */

/** Recent request durations, sampled as a ring so memory is fixed regardless of traffic. */
const SAMPLE_SIZE = 512;
const samples = new Float64Array(SAMPLE_SIZE);

let startedAt = Date.now();
let total = 0;
let written = 0;
let slowestMs = 0;
const byClass = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 };

export interface RequestMetrics {
  total: number;
  byClass: Record<keyof typeof byClass, number>;
  /** Server faults over total requests, since boot. Client errors are not failures. */
  errorRate: number;
  latencyMsP50: number;
  latencyMsP95: number;
  latencyMsMax: number;
  sinceSeconds: number;
}

export function recordRequest(statusCode: number, durationMs: number): void {
  total += 1;
  const group = statusCode >= 500 ? "5xx" : statusCode >= 400 ? "4xx" : statusCode >= 300 ? "3xx" : "2xx";
  byClass[group] += 1;
  samples[written % SAMPLE_SIZE] = durationMs;
  written += 1;
  if (durationMs > slowestMs) slowestMs = durationMs;
}

function percentile(sorted: number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.floor(fraction * sorted.length));
  return round(sorted[index] as number);
}

const round = (value: number) => Math.round(value * 1000) / 1000;

export function requestMetrics(now = Date.now()): RequestMetrics {
  const recent = [...samples.slice(0, Math.min(written, SAMPLE_SIZE))].sort((a, b) => a - b);
  return {
    total,
    byClass: { ...byClass },
    errorRate: total === 0 ? 0 : round(byClass["5xx"] / total),
    latencyMsP50: percentile(recent, 0.5),
    latencyMsP95: percentile(recent, 0.95),
    latencyMsMax: round(slowestMs),
    sinceSeconds: Math.round((now - startedAt) / 1000),
  };
}

/** Tests need a clean counter; nothing in the server calls this. */
export function resetMetrics(now = Date.now()): void {
  samples.fill(0);
  startedAt = now;
  total = 0;
  written = 0;
  slowestMs = 0;
  for (const key of Object.keys(byClass) as (keyof typeof byClass)[]) byClass[key] = 0;
}
