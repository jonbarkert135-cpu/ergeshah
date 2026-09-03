# Environment

Configuration is read in exactly one file, `src/server/config.ts`, and nowhere else — the
lint rule `environment-outside-config` fails the build if that changes. So this page is the
whole surface, and `test/docs.test.ts` fails if a variable is read that is not listed here.

Everything has a safe default except the secret, which has no default in production: the
server refuses to start rather than run with a guessable pepper.

## Three environments (point 91)

`NODE_ENV` picks one of exactly three, and a value that is not one of them stops the server
at boot — `NODE_ENV=prod` used to read as "not production", which silently turned off every
strict check the production path adds.

| | `development` | `test` | `production` |
| --- | --- | --- | --- |
| Secrets | a placeholder prefixed `development-only-`, generated at boot | a random pepper per run (`test/helpers.ts`) | **required**, at least 32 characters, and a `development-only-` value is refused |
| Database | `data/symvolon.sqlite` | `:memory:`, per test file | `SQLITE_PATH` or `DATABASE_URL`, and a backup policy |
| Proof of work | 16 bits, as shipped | 4 bits, so a suite is not a mining pool | 16 bits unless an attack says otherwise |
| Cookies | `Secure`, unless `BEHIND_TLS=false` for plain-HTTP localhost | not `Secure` (no TLS in the harness) | `Secure`, except on a `.onion` origin |
| Failure mode | loud and local | a failed assertion | refuses to start rather than run weakened |

A development or test value must never be a production one, and the reverse matters just as
much: never point a development server at a production database or a production pepper. The
placeholder secret carries its own warning in its value, which is what lets the production
path refuse it by name (`test/environments.test.ts`).

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
| `TRUST_PROXY` | `false` | Whether to believe `X-Forwarded-For`. Prefer naming the proxy — `TRUST_PROXY=10.0.0.2` or `127.0.0.1/8, ::1` — over a bare `true`, which believes the header from anything that can reach the port (`docs/SELF_CRITIQUE.md`, finding 3) |
| `BEHIND_TLS` | `true` | Whether cookies are marked `Secure`. Left alone unless you are running plain HTTP on localhost for development |
| `ONION_HOSTNAME` | *unset* | v3 onion address of this deployment. Validated at boot; enables the `Onion-Location` header and relaxes `Secure` cookies on that origin only |
| `MAX_CONNECTIONS` | `512` | Sockets this process will hold at once. Beyond it the kernel queues rather than the process running out of memory. Lower it on a small VPS; a value that is not a whole number of at least 1 stops the server at boot |
| `POW_BITS` | `16` | Difficulty of the proof of work an unauthenticated account request must solve (register, login, recovery). Each bit doubles the expected work; 16 is roughly 65,000 hashes, a fraction of a second in a browser. `0` turns the gate off — supported for a closed instance, and a real decision, not a tuning knob (ADR-0039). Above 24 the server refuses to start |

## Storage

| Variable | Default | What it does |
| --- | --- | --- |
| `DB_DIALECT` | `sqlite`, or `postgres` if `DATABASE_URL` is set | |
| `SQLITE_PATH` | `data/symvolon.sqlite` | |
| `STORAGE_FLOOR_BYTES` | `536870912` (512 MB) | Free space that must remain after a blob write. Below it, uploads answer `503 storage_full` while everything else keeps working — a full disk stops the database, not just the uploads (`docs/SELF_CRITIQUE.md`, finding 1). `0` disables the floor |
| `DB_STATEMENT_TIMEOUT_MS` | `5000` | PostgreSQL only: the ceiling on one statement, and on a transaction left idle. A query that runs longer is a bug or an attack, and the request that started it is long gone. SQLite has no server-side equivalent — there its protection is the indexes and the `LIMIT` on every list query |

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

### Money

Amounts are decimal strings of XMR; the server stores piconero. `docs/PAYMENTS.md` explains
what each one protects.

| Variable | Default | What it does |
| --- | --- | --- |
| `ORDER_FEE_BPS` | `500` (5%) | The marketplace's cut of a completed order, in basis points, charged to the seller and rounded down in their favour. `0` is supported. Boot refuses anything above `2000` (20%), because `5000` where `500` was meant is a typo nothing downstream would question |
| `MIN_WITHDRAWAL_XMR` | `0.02` (≈$10) | Smallest payout the server will queue. Enforced: below it the network fee dominates the transfer |
| `MIN_DEPOSIT_XMR` | `0.02` | The smallest top-up this platform credits, and it is enforced (ADR-0067). A smaller transfer is recorded as `below_minimum`, left off the balance, shown to its owner, and refundable to an address they name once it reaches `MIN_REFUND_XMR` |
| `MIN_REFUND_XMR` | `0.001` | The smallest uncredited total this platform sends back on request (ADR-0071). Roughly twenty network fees: below it, refunding dust costs the payout float more than the dust is worth, so the money waits on the owner's screen or an operator settles it by hand. Must stay under `MIN_DEPOSIT_XMR` to mean anything |
| `SELLER_LEVEL_DECAY_DAYS` | `90` | Days without a settled sale before a seller's level falls one step (ADR-0072). The earned volume is never deleted: one settled sale restores the level it paid for. Lower makes the catalogue a picture of this month's traders; higher makes it a picture of the year |
| `MONERO_WALLET_RPC_URL` | *(none)* | Where the **view-only** `monero-wallet-rpc` answers on the internal network, e.g. `http://wallet:18082`. Unset means this deployment has no Monero tier: no deposit address is handed out, no scan runs, and the wallet screen says top-ups are not open. The wallet at the other end holds a private view key and nothing that can sign (ADR-0070) |
| `DEPOSIT_CONFIRMATIONS` | `3` | Confirmations before a top-up is credited — about six minutes. Lower is faster and cheaper to attack; higher is a longer wait for every payer |
| `WALLET_POLL_SECONDS` | `45` | How often the watcher asks the wallet what arrived, and compares the books against it. A block is ~2 minutes, so anything under 30 is asking more often than the chain changes |
| `PAYOUT_WORKER_TOKEN` | *(none)* | Shared secret the payout worker authenticates with (`openssl rand -base64 32`, at least 32 characters). Unset closes the payout queue endpoints entirely. It is the only credential that can read a payout destination, so it belongs in a file mounted from a secret store — `PAYOUT_WORKER_TOKEN_FILE` works like every other secret here |
| `AUTO_PAYOUT_MAX_XMR` | `2` (≈$1,000) | Default ceiling on automatic payouts, per request and per rolling 24 hours, for an account with no ceiling of its own. Above it a payout is queued for an administrator, never refused. Per-account overrides are set through the admin API and audited |

### `RATE_LIMITS`

Sixteen scopes: `register`, `login`, `account_attempt`, `recovery`, `sensitive`,
`message_send`, `attachment`, `seller_application`, `listing_write`, `order_write`, `review`,
`moderation`, `search`, `key_bundle`, `read`, `write`. Each has a `burst` (tokens available at once) and
`perMinute` (refill rate). `key_bundle` is separate from `read` because claiming a prekey
bundle *consumes* one of the target's one-time prekeys (ADR-0035). `attachment` is separate
from `message_send` because an attachment is megabytes and there is no per-account quota to
charge it against — the bucket *is* the quota (`docs/MODERATION.md`).
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
