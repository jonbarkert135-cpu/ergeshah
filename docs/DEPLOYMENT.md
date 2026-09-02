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

`scripts/backup.mjs` takes an encrypted, verified, versioned snapshot, and prunes old ones on
a policy. Read **`docs/BACKUPS.md`** — it has the commands, the cron line and the retention
policy (35 days, minimum 7 files, no permanent archive tier, so a backup set does not become
a forever-copy of deleted accounts).

```bash
npm run backup:keygen > /etc/symvolon/backup.key   # once, offline
npm run backup -- --key /etc/symvolon/backup.key --out /var/backups/symvolon
npm run backup:prune -- --out /var/backups/symvolon
```

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
- **Hardening the host**: SSH keys only, unattended security upgrades, a firewall that
  exposes 80/443 only, and no other service on the box that logs client addresses.

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
