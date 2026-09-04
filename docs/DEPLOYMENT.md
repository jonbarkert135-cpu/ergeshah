# Deployment

Target: one ordinary VPS (1 vCPU, 1 GB RAM is enough to start), Docker, a domain name,
and nothing else. No Kubernetes, no managed database, no cloud-specific service, no API
key.

**Status, stated plainly:** the sequence below has been rehearsed end to end on a
production-mode instance — build, boot, register, back up, destroy the database, restore,
boot again on the restored copy — but this service has not yet run on a real VPS behind a
certificate and a proxy (roadmap OPS-6). The steps are tested; the deployment is not.

## From a fresh VPS to a running service

Nine steps, in order, each one verifiable before you take the next. Harden the host first
if you are doing this for real: **`docs/HARDENING.md`** covers SSH, the firewall and
unattended upgrades, and it is easier to do before the service exists than after.

### 1. Install dependencies

Docker and git. Nothing else: there is no Node, no build toolchain and no database to
install on the host, because the image builds and carries its own.

```bash
sudo apt update && sudo apt install -y git ca-certificates curl
curl -fsSL https://get.docker.com | sudo sh          # Docker Engine + compose plugin
docker --version && docker compose version           # verify before continuing
```

### 2. Clone the repository

```bash
git clone https://github.com/jonbarkert135-cpu/ergeshah.git
cd ergeshah
```

### 3. Configure the environment

```bash
cp .env.example .env
# One required secret; the server refuses to start in production without it.
printf 'RATE_LIMIT_PEPPER=%s\n' "$(openssl rand -base64 48)" >> .env
chmod 600 .env
```

Read `.env` once, top to bottom. Every variable has a safe default except that secret, and
every one of them is documented in **`docs/ENVIRONMENT.md`**.

### 4. Configure the domain

Point an A/AAAA record at the server, then replace `example.com` in `deploy/Caddyfile`
with your domain. DNS must resolve *before* the first start, or the certificate request
fails and Caddy backs off.

```bash
dig +short your.domain            # expect this server's address
```

### 5. Run migrations

There is no separate migration step, and that is deliberate: the server applies pending
migrations at boot, inside a transaction, and refuses to start if one fails or if an
already-applied file has changed underneath it (`npm run audit:migrations`). Starting the
service *is* running the migrations. To watch it happen, start in the foreground first:

```bash
docker compose -f deploy/docker-compose.yml up --build app
```

### 6. Start the services

```bash
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml ps        # both services healthy?
```

### 7. Configure TLS

Nothing to do, and that is the point: Caddy requests a certificate from Let's Encrypt on
first start, renews it automatically, and redirects `http://` to `https://` with a 308.
The floor is TLS 1.2 and it is written down explicitly in `deploy/Caddyfile` rather than
inherited from a default that could move. Confirm from outside the machine:

```bash
curl -sI http://your.domain | head -1                          # 308 to https
curl -sI https://your.domain | grep -i strict-transport-security
```

### 8. Verify health

```bash
curl -s https://your.domain/healthz                            # ok
docker compose -f deploy/docker-compose.yml ps                 # State: healthy
docker compose -f deploy/docker-compose.yml exec app node -e "process.exit(0)"
npm ci && npm run audit:deployment -- https://your.domain      # the bytes served == the bytes built
```

### 9. Claim the administrator account

The **first account to register becomes the administrator**. Create it immediately, before
you announce the address, or the first stranger through the door is your admin.

Then read `docs/HARDENING.md` if you skipped it, and set up backups (`docs/BACKUPS.md`).

## What the running deployment looks like

Caddy obtains and renews the TLS certificate automatically. The application container has
**no published port and no route to the internet** — it sits alone on an `internal: true`
network, and only the proxy bridges that network to the outside (`docs/NETWORK.md`) — runs
read-only as an unprivileged user with every Linux capability dropped, and stores its
SQLite database in a named volume. Memory, CPU and process count are capped so that one
runaway loop cannot take the host with it.

`test/deployment.test.ts` asserts each of those properties against the files themselves, so
this paragraph cannot drift away from `deploy/docker-compose.yml` the way it did before.

## Verifying what you deployed

The client build is reproducible, so anyone holding this source — in practice, you — can
check that the server serves exactly what it builds. With the source closed this is an
operator's tool, not a user's:

```bash
npm ci                                        # locked versions; a different esbuild = different bytes
npm run audit:deployment -- https://your.domain
```

The deployment publishes the digests of the files it loaded at boot at `/build.txt`, and
`index.html` pins the script and stylesheet with subresource integrity. Publish the digest
of `app.js` wherever you announce the service: users cannot rebuild it, but they can check
that they were all served the same thing, which is what catches a bundle targeted at one
person.

## PostgreSQL instead of SQLite

Uncomment the `db` service in `deploy/docker-compose.yml`, then in `.env`:

```
DB_DIALECT=postgres
DATABASE_URL=postgres://symvolon:STRONG_PASSWORD@db:5432/symvolon
```

Same schema, same SQL, same migrations. Use PostgreSQL when you expect concurrent write
load or want streaming backups; SQLite is genuinely fine for a small instance.

### Least privilege (ADR-0095)

Do not hand the application a superuser. `deploy/postgres-roles.sql` creates the two roles a
deployment needs and nothing more:

```bash
psql "$ADMIN_URL" -v app_password="'…'" -v backup_password="'…'" -f deploy/postgres-roles.sql
```

- `symvolon_app` owns one schema, has no rights outside it, and is `NOSUPERUSER
  NOCREATEDB NOCREATEROLE NOBYPASSRLS`. It owns its schema because it applies its own
  migrations at boot.
- `symvolon_backup` may `SELECT` and nothing else; it is what `pg_dump` connects as.
- `PUBLIC` loses `CONNECT` on the database and everything on `public`, so a role that
  appears later inherits no access by accident.

The database listens on the internal Docker network only and is never published to the
internet (`docs/NETWORK.md`).

## Deployment profiles (ADR-0096)

Two supported shapes, one architecture. The code is identical in both — the difference is
which processes share a machine — so moving from one to the other is configuration, not a
rewrite, and nothing below needs Kubernetes.

| | **Single VPS** (the default) | **Scale mode** |
| --- | --- | --- |
| Orchestration | `deploy/docker-compose.yml` — app, proxy, optionally PostgreSQL and the Monero services | The same compose file split across hosts, or any orchestrator; no manifest in this repository is required |
| Database | SQLite file on the app's volume, or PostgreSQL beside it | PostgreSQL on its own host, reachable only from the app's network, with the roles above |
| Storage | rows in that database | rows in that database — blobs are not files, so "a storage node" is the database tier growing, not a new component (`docs/STORAGE.md`) |
| Cache | none. Sessions, buckets and challenges are rows with expiries | still none: adding Redis would add a second store holding session and challenge material, and it buys nothing until the database is the bottleneck (ADR-0095) |
| Workers | the housekeeping interval inside the app process; the payout worker on another host, always (ADR-0070) | the same, plus a second app instance if request volume needs one — the jobs are idempotent sweeps, and the durable queues are database tables |
| Monero | `monerod` and a view-only `monero-wallet-rpc` on the internal network | the node on its own host; the spend key stays on the payout host and nowhere else |

What does *not* change between them: the trust boundaries, the migrations, the audits, and
the rule that the application makes no outbound requests (ADR-0081). A deployment that needs
more than this is not a bigger version of this design; it is a different one, and it should
be recorded as such.

And what scale mode is *for*, said plainly because the question comes up: performance, fault
isolation, and surviving the loss of one machine. It is not for spreading a deployment across
jurisdictions to make an unlawful service harder to reach. This is a privacy product, not a way
to hide illegal activity (`README.md`, `docs/MODERATION.md`), and a topology chosen for that
purpose is outside what this documentation supports.

## Tor onion service

Two reasons to run one: users who do not want to reveal their address to your proxy or to
your hosting provider, and an entrypoint that needs no certificate authority.

```bash
# 1. Uncomment the `tor` service (and the tor-data volume) in deploy/docker-compose.yml
docker compose -f deploy/docker-compose.yml up -d --build tor

# 2. Read the address Tor generated for you
docker compose -f deploy/docker-compose.yml exec tor cat /var/lib/tor/symvolon/hostname

# 3. Tell the clearnet site about it, so Tor Browser can offer the switch
echo "ONION_HOSTNAME=<that address>" >> .env
docker compose -f deploy/docker-compose.yml up -d app
```

The `tor` container is built from Alpine's signed `tor` package (`deploy/tor/Dockerfile`),
runs with `SocksPort 0` — it is a hidden service and nothing else — and maps
`HiddenServicePort 80` straight to `app:8080`. The clearnet proxy is not involved: there is
no second place a request could be logged or a header rewritten. Tor's introduction-point
DoS defences and proof-of-work defence are enabled in `deploy/tor/torrc`;
single-hop/non-anonymous mode deliberately is not.

**The application adapts itself when it is reached over `.onion`** — you do not set
`BEHIND_TLS=false` and you do not run a second instance:

| Behaviour | Clearnet | Onion |
| --- | --- | --- |
| `Secure` on session and CSRF cookies | yes | no — an onion service is HTTP inside an authenticated circuit, and a Secure cookie would never be sent |
| `Strict-Transport-Security` | yes | no — it would pin an address that speaks no HTTPS |
| `upgrade-insecure-requests` in the CSP | yes | no — it would upgrade the page's own requests and break it |
| `Onion-Location` header | when `ONION_HOSTNAME` is set | not sent |

Everything else — the rest of the CSP, `SameSite=Strict`, the Origin check, rate limiting —
is identical, and `test/onion.test.ts` asserts exactly this table.

Back up `/var/lib/tor/symvolon` (the `tor-data` volume) the way you back up a private key,
because that is what it is: whoever holds it *is* your onion address.

What Tor hides: your users' network location from you and from your host. What it does not
hide: message timing and volume, anything a compromised client would leak, and the fact
that the same account can be used from both entrypoints — the onion service and the
clearnet site share one database, so an operator can still correlate activity across them.

## The Monero tier

Optional, and off by default: with `MONERO_WALLET_RPC_URL` unset the marketplace runs exactly
as it did before ADR-0070 — orders, escrow and balances all work, and nobody can top up.
Turning it on is three decisions, and the first two happen off this machine.

**1. Make the deposit wallet somewhere else.** On a machine that is not the server, create the
wallet that will receive top-ups and write down the seed. Then export a *view-only* copy —
`monero-wallet-cli --generate-from-view-key` with the address and the private view key — and
copy **only that** to the server. The spend key stays where you made it; it is the key that
can empty the marketplace.

**2. Start the node and the view-only wallet.** Uncomment the `node` and `wallet` services in
`deploy/docker-compose.yml`, put the view-only wallet file in the `monero-wallet` volume, the
wallet password in `deploy/secrets/wallet_password`, and set
`MONERO_WALLET_RPC_URL=http://wallet:18082`. The daemon needs ~90 GB pruned and a day to sync
before the first deposit address is worth handing out. `app` still has no egress: the daemon is
the container with the route out, which is the point of putting it in its own tier
(`docs/NETWORK.md`).

**3. Run the payout worker on another host.** Payouts queue whether or not a worker exists —
they simply wait. To send them, on a *different* machine with the hot wallet (a float of 1–2%
of liabilities, no more):

```bash
SYMVOLON_URL=https://example.org \
PAYOUT_WORKER_TOKEN=$(cat /etc/symvolon/payout-token) \
WALLET_RPC_URL=http://127.0.0.1:18083 \
MAX_PAYOUT_XMR=5 \
node scripts/payout-worker.mjs
```

Set the same token as `PAYOUT_WORKER_TOKEN` (or `PAYOUT_WORKER_TOKEN_FILE`) on the server. The
worker refuses anything above `MAX_PAYOUT_XMR` and returns it to the owner's balance, so the
float is a ceiling on what a compromise of that host can cost.

**Then watch two numbers.** `GET /api/admin/treasury` reports `liabilitiesXmr` against
`walletXmr`; `shortfallXmr` must stay `0`. The watcher compares them every
`WALLET_POLL_SECONDS` and writes a `treasury.shortfall` error line when it does not — that is
the line to alert on, before a seller finds it for you.

**This has never been run against a real node** (roadmap PAY-6). Do a stagenet pass first:
same configuration, `--stagenet` on both Monero containers, a top-up, an order, a payout.

## Backups

`scripts/backup.mjs` takes an encrypted, verified, versioned snapshot, and prunes old ones on
a policy. Read **`docs/BACKUPS.md`** — it has the commands, the cron line and the retention
policy (35 days, minimum 7 files, no permanent archive tier, so a backup set does not become
a forever-copy of deleted accounts).

```bash
npm run backup:keygen > /etc/symvolon/backup.key   # once, offline
npm run backup -- --key /etc/symvolon/backup.key --out /var/backups/symvolon
npm run backup:prune -- --out /var/backups/symvolon
npm run backup:drill -- --out /var/backups/symvolon   # quarterly: does the service start on it?
```

The drill is the one that matters. `verify` proves a backup decrypts and that SQLite thinks
it is intact; the drill restores the newest one to a temporary copy, starts a real server on
it in production mode on a random port, waits for `/healthz` and asks for the page — then
deletes the copy. The live database is not touched. Run it before you need it.

The database contains no plaintext messages, but it does contain password hashes, sealed
vaults, marketplace records and public keys. The backup key is not part of the application's
configuration on purpose: a compromised running service cannot decrypt the backup history.

## When something goes wrong

Procedures — credential rotation, session revocation, a compromised server, a database
breach, a dependency vulnerability, a key compromise — are in
**`docs/INCIDENT_RESPONSE.md`**. Their commands are `scripts/incident.mjs`, run **on the
host** next to the database file rather than inside the container: the application image is
read-only and a break-glass path shipped inside the running service would be a backdoor
with a nicer name (ADR-0037).

```bash
npm run incident status                          # counts first: see the blast radius
npm run incident sessions:revoke-all -- --yes    # end every session on the deployment
npm run incident suspend someone -- --reason "under investigation" --yes
```

Every destructive command requires `--yes`, prints what it changed, and can only take
access away — there is no command that reads a message, a vault or a password hash.

## Logs

What is logged, why, for how long, who can read it and when it is deleted: **`docs/LOGGING.md`**.
Short version — a JSON line per 500, one at boot, no access log anywhere, and nothing that
identifies a user or a message.

## Operating notes

- **Updating**: `git pull && docker compose -f deploy/docker-compose.yml up -d --build`.
  Migrations are applied on boot inside a transaction.
- **Health**: `GET /healthz` returns 200 when the database answers; the container health
  check uses it.
- **Housekeeping**: expired sessions, expired envelopes and stale rate-limit buckets are
  pruned hourly inside the process. No cron job is needed.
- **Logs**: the application logs errors only. If you enable proxy access logs for
  debugging, set a retention of hours, not weeks, and remember what you are creating.
- **Hardening the host**: SSH, firewall, updates, exposed ports, TLS, isolation, backups,
  monitoring and intrusion detection are a page of their own — **`docs/HARDENING.md`**.

## What is deliberately missing

Payments, email delivery, push notifications, object storage, an analytics stack and a
CDN. Each of them would introduce a third party who learns something about your users;
when they are added, they must be optional, isolated and documented — see
`docs/ROADMAP.md`.

## Secrets, and rotating them

Nothing secret is in this repository, and `npm run audit:secrets` scans every tracked file
on each push to keep it that way (`docs/AUDIT.md`). What the server needs at runtime it
takes from the environment, or — preferably — from a file:

| Secret | Supplied as | Rotation |
| --- | --- | --- |
| `RATE_LIMIT_PEPPER` | env or `RATE_LIMIT_PEPPER_FILE` | Any time. Buckets are per-day; rotating only resets current allowances |
| `DATABASE_URL` (contains the database password) | env or `DATABASE_URL_FILE` | Change the password in PostgreSQL, update the secret, restart. No data is re-encrypted, because the server holds no key that protects user content |

Both accept the `_FILE` form so that a Docker secret, a Kubernetes secret or a
`systemd` credential can be mounted as a file instead of exported into the process
environment:

```yaml
# docker-compose.yml
services:
  app:
    environment:
      RATE_LIMIT_PEPPER_FILE: /run/secrets/rate_limit_pepper
    secrets: [rate_limit_pepper]
secrets:
  rate_limit_pepper:
    file: ./secrets/rate_limit_pepper
```

What is deliberately *not* on this list: any key that protects user content. There is no
message-encryption key, no vault key and no signing key on the server to rotate, because
none exists there — that is the whole architecture (`docs/ARCHITECTURE.md`). The worst a
leaked server secret does is let someone forge rate-limit buckets or reach the database;
neither yields a plaintext message.
