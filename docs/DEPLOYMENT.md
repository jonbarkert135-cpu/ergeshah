# Deployment

Target: one ordinary VPS (1 vCPU, 1 GB RAM is enough to start), Docker, a domain name,
and nothing else. No Kubernetes, no managed database, no cloud-specific service, no API
key.

## Clearnet deployment

```bash
git clone https://github.com/jonbarkert135-cpu/symvolon.git
cd symvolon
cp .env.example .env

# One required secret; the server refuses to start in production without it.
printf 'RATE_LIMIT_PEPPER=%s\n' "$(openssl rand -base64 48)" >> .env

# Put your domain into deploy/Caddyfile (replace example.com), then:
docker compose -f deploy/docker-compose.yml up -d --build
```

Caddy obtains and renews the TLS certificate automatically. The application container has
no route to the internet (`internal: true` network), runs read-only with all capabilities
dropped, and stores its SQLite database in a named volume.

Migrations run automatically at boot. The **first account to register becomes the
administrator** — create it immediately after the first deploy, before announcing the
address.

## Verifying what you deployed

The client build is reproducible, so anyone — including you, after an update — can check
that the server serves exactly what this source tree builds:

```bash
npm ci                                        # locked versions; a different esbuild = different bytes
npm run audit:deployment -- https://your.domain
```

The deployment publishes the digests of the files it loaded at boot at `/build.txt`, and
`index.html` pins the script and stylesheet with subresource integrity. Publish the digest
of `app.js` wherever you announce the service; a user who compares it is doing the audit
you cannot do for them.

## PostgreSQL instead of SQLite

Uncomment the `db` service in `deploy/docker-compose.yml`, then in `.env`:

```
DB_DIALECT=postgres
DATABASE_URL=postgres://symvolon:STRONG_PASSWORD@db:5432/symvolon
```

Same schema, same SQL, same migrations. Use PostgreSQL when you expect concurrent write
load or want streaming backups; SQLite is genuinely fine for a small instance.

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

## Backups

```bash
# SQLite: consistent copy without stopping the service
docker compose exec app node -e "
  const {DatabaseSync}=require('node:sqlite');
  new DatabaseSync('data/symvolon.sqlite').exec(\"VACUUM INTO 'data/backup.sqlite'\");
"
# then encrypt before it leaves the host
age -r age1yourkey -o backup-$(date +%F).sqlite.age backup.sqlite
```

The database contains no plaintext messages, but it does contain password hashes,
marketplace records and public keys. Encrypt every backup, and store the key somewhere
the backup is not.

## Operating notes

- **Updating**: `git pull && docker compose -f deploy/docker-compose.yml up -d --build`.
  Migrations are applied on boot inside a transaction.
- **Health**: `GET /healthz` returns 200 when the database answers; the container health
  check uses it.
- **Housekeeping**: expired sessions, expired envelopes and stale rate-limit buckets are
  pruned hourly inside the process. No cron job is needed.
- **Logs**: the application logs errors only. If you enable proxy access logs for
  debugging, set a retention of hours, not weeks, and remember what you are creating.
- **Hardening the host**: SSH keys only, unattended security upgrades, a firewall that
  exposes 80/443 only, and no other service on the box that logs client addresses.

## What is deliberately missing

Payments, email delivery, push notifications, object storage, an analytics stack and a
CDN. Each of them would introduce a third party who learns something about your users;
when they are added, they must be optional, isolated and documented — see
`docs/ROADMAP.md`.
