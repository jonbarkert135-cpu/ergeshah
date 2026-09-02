# Logging

Logs are how a service stays alive, and they are also the most common way a private service
betrays its users. An access log alone answers "who was here, when, from where, and what did
they look at" — the questions this project exists not to answer.

So logging here is deliberately small, and point 51's five questions are answered before
production rather than after an incident.

## What we log

Exactly three kinds of line, all JSON on stderr, all written by `src/server/lib/log.ts`:

| Line | Fields | Example |
| --- | --- | --- |
| `request.failed` | `ref`, `method`, route **pattern**, error name, scrubbed message | a 500 — the only request that produces a line at all |
| `housekeeping.failed` | scrubbed message | the retention sweep could not run |
| `listening` | host, port, dialect, environment | one line at boot |

The administrative **audit log** is a different thing and lives in the database, not here:
who approved a seller, who suspended an account, who was refused a privileged route
(`docs/AUDIT.md`, `src/server/lib/audit.ts`). It is deliberately separate because it has a
different audience (moderators, oversight), a different retention window and a different
access rule.

## What we never log

Forbidden outright, and enforced rather than remembered:

- passwords, `authSecret`, password hashes
- private keys, identity keys, prekeys, ratchet state
- session tokens, CSRF tokens, cookies, `Authorization` headers
- plaintext or ciphertext of end-to-end encrypted messages, envelope payloads, sealed vaults
- recovery phrases, master keys, the rate-limit pepper
- request bodies, query strings, concrete URLs (an order id in a log is a marketplace record
  in a log), usernames, account ids
- IP addresses, `User-Agent`, `Referer`
- stack traces (a stack is a filesystem layout and a dependency inventory)
- access logs of any kind: Fastify runs with `logger: false` and
  `disableRequestLogging: true`, and the reverse proxy configuration in
  `deploy/Caddyfile` discards the proxy's own log

How it is enforced:

1. `log()` accepts a fixed set of fields. There is no `extra`, no `context`, no object spread.
2. `scrub()` runs on every string that goes out: anything 40+ characters of base64/hex shape
   becomes `[redacted]`, anything shaped like an IPv4/IPv6 address becomes `[address]`, and a
   message that so much as *names* a forbidden thing (`password`, `token`, `cookie`,
   `ciphertext`…) is replaced wholesale rather than trusted to have quoted it safely.
3. The lint rule `unstructured-log` fails the build if anything under `src/server/` other than
   `lib/log.ts` writes to `stdout` or `stderr`; `console-in-server` already banned `console.*`.
4. `test/logging.test.ts` throws errors containing a password, a session token and a base64
   key from a real route and asserts none of it reaches the line.

## Why we log it

To find bugs and to answer a user who says "it broke". A 500 is a defect: without the route
pattern and the error name, the operator has a support ticket and no way to act on it. The
`ref` is a six-character random string echoed to the user, so a conversation can start with
"error 7f3a2b" instead of a screenshot of internals — it is generated per incident and points
to nothing.

Nothing is logged for analytics, for product metrics, or for "security visibility" in general:
abuse of the marketplace is handled by rate limits (which keep counters, not histories) and by
the audit log, both of which are in the database with retention rules attached.

## How long we retain it

Stderr belongs to the process manager, which is where the window is set — the application
keeps no log file and rotates nothing:

| Deployment | Retention | Set where |
| --- | --- | --- |
| Docker (`deploy/docker-compose.yml`) | 3 × 10 MB files (size-bounded, days at this volume) | `logging:` driver options |
| systemd / journald | **7 days** | `MaxRetentionSec=1week` in `journald.conf` |
| Reverse proxy | no request log at all | `log { output discard }` in `deploy/Caddyfile` |
| Audit log (database) | 365 days, `AUDIT_RETENTION_MS` | pruned by housekeeping |
| Notifications (database) | 90 days, `NOTIFICATION_RETENTION_MS` | pruned by housekeeping |
| Backups of any of the above | 35 days | `docs/BACKUPS.md` |

Roughly a week of volume is the target: long enough to debug a Friday incident on Monday and short enough
that the log cannot become a history of the service.

## Who can access it

- **Operator/root on the host** — the log stream, through `docker logs` or `journalctl`. This
  is the same person who can read the database, so the log grants no new power; keeping it
  boring is what limits the damage of *exporting* it.
- **Moderators and admins** — the audit log through `GET /api/moderation/audit`, in the
  product, with their reads themselves auditable. No access to stderr.
- **Users** — the `ref` of their own incident, and nothing else.
- **Third parties** — none. There is no log shipper, no APM agent, no error-reporting SaaS,
  and the CSP forbids any third-party origin, so adding one fails loudly.

If an operator ships logs off the host, the destination inherits every rule on this page. A
hosted log service that indexes route patterns is acceptable; one that would receive request
bodies, addresses or identifiers cannot be, because the application never produces them.

## When it is deleted

- Stderr lines: automatically, at the retention window above (7 days by default). No manual
  step, so nothing accumulates by inertia.
- Audit entries: by housekeeping, at `AUDIT_RETENTION_MS`.
- Rate-limit buckets: keys rotate daily; stale rows are pruned on the same interval.
- A deleted account: leaves nothing in the logs, because nothing about an account was there in
  the first place. That is the difference between a redaction pipeline and not collecting.
