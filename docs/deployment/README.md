# Deployment

- [`../DEPLOYMENT.md`](../DEPLOYMENT.md) — one VPS, Docker, Caddy, the optional Tor onion
  service, verifying what you deployed, secrets and how to rotate them, operating notes.
- [`../HARDENING.md`](../HARDENING.md) — the machine underneath: SSH, firewall, updates,
  exposed ports, TLS checks, service isolation, backups, monitoring, intrusion detection.
- [`../NETWORK.md`](../NETWORK.md) — the five tiers, what each may talk to, and why the
  database is not on the internet.
- [`../ENVIRONMENT.md`](../ENVIRONMENT.md) — every variable the server reads, its default
  and what it does. Nothing is read outside `config.ts`.
- [`../BACKUPS.md`](../BACKUPS.md) — encrypted snapshots, the restore drill, and the
  retention window that stops a backup set becoming a permanent copy of deleted accounts.
- [`../LOGGING.md`](../LOGGING.md) — a JSON line per 500, one at boot, no access log.
- [`../INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) — when the deployment is the
  incident.

**Code:** `deploy/docker-compose.yml`, `deploy/Caddyfile`, `deploy/tor/`,
`deploy/github-ci.yml` (the CI definition a human copies to `.github/workflows/`),
`scripts/backup.mjs`, `scripts/incident.mjs`, `src/server/config.ts`.

**Kept honest by:** `test/deployment.test.ts` (every property these pages claim about the
containers, the networks and the TLS floor, asserted against the files themselves —
ADR-0040), `test/defaults.test.ts` (the shipped configuration is the private one),
`test/onion.test.ts` (clearnet and onion behaviour differ in exactly four documented ways),
`test/backup.test.ts`, `test/incident.test.ts`, and `npm run audit:deployment`, which
compares a live deployment with a local reproducible build.
