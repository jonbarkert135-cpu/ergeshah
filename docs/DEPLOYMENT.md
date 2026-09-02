# Deployment

Target: one ordinary VPS (1 vCPU, 1 GB RAM is enough to start), Docker, a domain name,
and nothing else. No Kubernetes, no managed database, no cloud-specific service, no API
key.

## Clearnet deployment

```bash
git clone https://github.com/jonbarkert135-cpu/ergeshah.git
cd ergeshah
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

## PostgreSQL instead of SQLite

Uncomment the `db` service in `deploy/docker-compose.yml`, then in `.env`:

```
DB_DIALECT=postgres
DATABASE_URL=postgres://ergeshah:STRONG_PASSWORD@db:5432/ergeshah
```

Same schema, same SQL, same migrations. Use PostgreSQL when you expect concurrent write
load or want streaming backups; SQLite is genuinely fine for a small instance.

## Tor onion service

Two reasons to run one: users who do not want to reveal their address to your proxy, and
an entrypoint that needs no certificate authority.

1. Uncomment the `tor` service in the compose file and give it a `torrc` that maps
   `HiddenServicePort 80 app:8080`.
2. Uncomment the onion block in `deploy/Caddyfile` (or let Tor reach `app` directly).
3. Set `BEHIND_TLS=false` **only** if you serve the onion service without TLS, and
   remember this disables `Secure` on cookies — run a separate instance rather than
   weakening the clearnet one.

What this hides: your users' IP addresses from your server and your hosting provider.
What it does not hide: message timing and volume, and anything a compromised client
would leak. The onion service and the clearnet proxy see the same database, so an
operator can still correlate account activity across both.

## Backups

```bash
# SQLite: consistent copy without stopping the service
docker compose exec app node -e "
  const {DatabaseSync}=require('node:sqlite');
  new DatabaseSync('data/ergeshah.sqlite').exec(\"VACUUM INTO 'data/backup.sqlite'\");
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
