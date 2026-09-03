# Environment

Configuration is read in exactly one file, `src/server/config.ts`, and nowhere else — the
lint rule `environment-outside-config` fails the build if that changes. So this page is the
whole surface, and `test/docs.test.ts` fails if a variable is read that is not listed here.

Everything has a safe default except the secret, which has no default in production: the
server refuses to start rather than run with a guessable pepper.

## Secrets

Any secret may be given as a file instead of a value by appending `_FILE` to the name
(`RATE_LIMIT_PEPPER_FILE=/run/secrets/pepper`). That is how Docker and Kubernetes mount
secrets, and it keeps the value out of `docker inspect`, out of the environment listing and
out of a crash dump.

| Variable | Default | What it does |
| --- | --- | --- |
| `RATE_LIMIT_PEPPER` | *none in production* | Derives daily-rotating rate-limit bucket keys, so no address is ever stored. At least 32 characters. Rotate freely — the only effect is that current allowances reset |
| `DATABASE_URL` | *unset* | PostgreSQL connection string. Contains a password, so it is treated as a secret; setting it also switches the dialect to `postgres` |

## Server

| Variable | Default | What it does |
| --- | --- | --- |
| `NODE_ENV` | `development` | `production` enables the strict checks (secret required, no development fallbacks) |
| `HOST` | `127.0.0.1` | Bind address. The default is deliberately *not* `0.0.0.0`: this service is meant to sit behind Caddy or Tor |
| `PORT` | `8080` | |
| `TRUST_PROXY` | `false` | Whether to believe `X-Forwarded-For`. Only turn this on when a proxy you operate sets it — a trusted header from an untrusted source is a rate-limit bypass |
| `BEHIND_TLS` | `true` | Whether cookies are marked `Secure`. Left alone unless you are running plain HTTP on localhost for development |
| `ONION_HOSTNAME` | *unset* | v3 onion address of this deployment. Validated at boot; enables the `Onion-Location` header and relaxes `Secure` cookies on that origin only |
| `POW_BITS` | `16` | Difficulty of the proof of work an unauthenticated account request must solve (register, login, recovery). Each bit doubles the expected work; 16 is roughly 65,000 hashes, a fraction of a second in a browser. `0` turns the gate off — supported for a closed instance, and a real decision, not a tuning knob (ADR-0039). Above 24 the server refuses to start |

## Storage

| Variable | Default | What it does |
| --- | --- | --- |
| `DB_DIALECT` | `sqlite`, or `postgres` if `DATABASE_URL` is set | |
| `SQLITE_PATH` | `data/symvolon.sqlite` | |

## Limits and retention

Every one of these is a privacy control as much as an operational one: they decide how long
the server remembers anything.

| Variable | Default | What it does |
| --- | --- | --- |
| `SESSION_TTL_MS` | 30 days | Absolute session lifetime. Set once when the session is created and never extended, so signing in again is a monthly event rather than never |
| `SESSION_IDLE_DAYS` | 14 | How long a session may go *unused* before it is deleted. The shorter of the two limits wins; day granularity, because the column behind it is a day and not a timestamp (ADR-0038) |
| `ENVELOPE_TTL_MS` | 30 days | How long an unacknowledged message ciphertext survives |
| `MAX_ENVELOPE_BYTES` | 64 KiB | Cap on one message envelope |
| `MAX_DELIVERY_BYTES` | 5 MiB | Cap on encrypted digital goods for one order |
| `DELIVERY_TTL_MS` | 30 days | How long a delivery stays collectable |
| `AUDIT_RETENTION_MS` | 365 days | How long administrative audit entries are kept before pruning |
| `NOTIFICATION_RETENTION_MS` | 90 days | How long a notification stays in an inbox, read or unread |
| `RATE_LIMITS` | *see below* | JSON overriding per-operation buckets |

### `RATE_LIMITS`

Fifteen scopes: `register`, `login`, `account_attempt`, `recovery`, `sensitive`,
`message_send`, `seller_application`, `listing_write`, `order_write`, `review`,
`moderation`, `search`, `key_bundle`, `read`, `write`. Each has a `burst` (tokens available at once) and
`perMinute` (refill rate). `key_bundle` is separate from `read` because claiming a prekey
bundle *consumes* one of the target's one-time prekeys (ADR-0035).
Override any subset:

```
RATE_LIMITS={"register":{"burst":2,"perMinute":0.1},"search":{"burst":10,"perMinute":10}}
```

An unknown scope name or a non-positive value **stops the server at boot**. A limit you
believe you tightened and did not is worse than no limit at all.

## Build

| Variable | Default | What it does |
| --- | --- | --- |
| `NODE_ENV` | | `production` makes `scripts/build-client.mjs` minify and drop the inline source map. The reproducible-build check (`npm run audit:bundle`) builds twice and compares digests |

`.env.example` is the copy-paste version of this page. It is committed; `.env` is not, and
`npm run audit:secrets` scans every tracked file on every push to keep it that way.
