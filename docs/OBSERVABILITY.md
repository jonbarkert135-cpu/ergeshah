# Observability

A service nobody can see the state of is a service that fails silently, and "we care about
privacy" is not an excuse for not knowing whether the disk is full. This page says what this
deployment measures, what it refuses to measure, and how to read the two numbers that matter
at three in the morning (point 85).

## The two endpoints

| | `GET /healthz` | `GET /api/admin/health` |
| --- | --- | --- |
| Who may call it | anyone — the proxy and the container health check | an administrator, with a session |
| What it answers | `{"status":"ok"}`, or `503` when the database does not | uptime, CPU, memory, disk, database latency, request counts, error rate, latency percentiles |
| Why the split | a liveness probe on the public internet may reveal nothing else; load and headroom are exactly what an attacker wants before deciding when to push | the same numbers are what an operator needs, and they are worth one authenticated request |

The administrative document is numbers, booleans and four fixed words (`ok`, `degraded`,
`sqlite`, `postgres`). `test/observability.test.ts` walks the response and fails if any leaf
is anything else — which is how "we should also expose the busiest route" gets caught in
review instead of in production.

```json
{
  "status": "ok",
  "uptimeSeconds": 84213,
  "process":  { "cpuPercent": 1.4, "rssBytes": 96468992, "heapUsedBytes": 41123840 },
  "system":   { "cpuCount": 2, "loadAverage1": 0.11, "memoryTotalBytes": 4127195136, "memoryFreeBytes": 2411945984 },
  "disk":     { "totalBytes": 84140883968, "availableBytes": 61932105728 },
  "database": { "ok": true, "latencyMs": 0.412, "dialect": "sqlite" },
  "requests": { "total": 18422, "byClass": { "2xx": 17994, "3xx": 0, "4xx": 421, "5xx": 7 },
                "errorRate": 0.0004, "latencyMsP50": 3.1, "latencyMsP95": 21.7,
                "latencyMsMax": 812.4, "sinceSeconds": 84213 }
}
```

## What is counted, and what cannot be

`src/server/lib/metrics.ts` takes two arguments: a status code and a duration. That is the
whole interface, and it is the privacy control — there is nowhere to put a route, an account,
an address or a body, so no aggregate here can be joined back to a person. The counters live
in memory and reset on restart, because a persisted time series of per-endpoint volume is an
access log written slowly.

Deliberately absent:

- **No request log.** Not sampled, not "anonymised", not for 24 hours. See `docs/LOGGING.md`.
- **No APM agent, no error-reporting SaaS, no uptime widget in the page.** Each is a third
  party who would learn about your users; `connect-src 'self'` forbids the last one in the
  browser regardless.
- **No per-route or per-user metrics.** "Which endpoint is slow" is answerable from a
  reproduction and a profiler on your own machine; "which user is slow" is not a question
  this service asks.
- **No message content, ever.** Not sizes per conversation, not counts per account.

## Reading it

| Symptom | What it looks like here | First move |
| --- | --- | --- |
| Down | `/healthz` fails, or `status: "degraded"` | `docker compose ps`, then the container logs |
| Database wedged | `database.latencyMs` in the hundreds, `5xx` climbing | check disk, then long transactions; PostgreSQL statements are capped by `DB_STATEMENT_TIMEOUT_MS` |
| Disk filling | `disk.availableBytes` falling steadily | SQLite file and the backup directory are the two that grow (`npm run backup:prune`) |
| Under attack | `4xx` climbing far faster than `2xx` — 429s and 428s — while latency stays flat | tighten one `RATE_LIMITS` scope, raise `POW_BITS`, leave the rest alone |
| Overloaded | `latencyMsP95` climbing with `loadAverage1` above `cpuCount` | fewer `MAX_CONNECTIONS` will not help; this is a bigger machine or a slower query |
| Leaking memory | `process.rssBytes` rising monotonically across days | restart is the mitigation, a heap snapshot on a scratch instance is the fix |

## Alerting

Two alerts that reach a phone beat a dashboard nobody opens:

1. `GET /healthz` from an external checker you trust, every minute.
2. A disk-space alert on the host at 80%.

Everything else is a question you ask the health endpoint when one of those two fires, or
when a user reports something. Polling `/api/admin/health` on a schedule and storing the
result is possible and is your decision — it is also the moment you start keeping a time
series, so keep the retention short and the fields as they are.
