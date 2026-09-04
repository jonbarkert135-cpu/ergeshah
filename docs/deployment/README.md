# Deployment

- [`../DEPLOYMENT.md`](../DEPLOYMENT.md) — one VPS, Docker, Caddy, the optional Tor onion
  service, verifying what you deployed, secrets and how to rotate them, operating notes.
- [`../HARDENING.md`](../HARDENING.md) — the machine underneath: SSH, firewall, updates,
  exposed ports, TLS checks, service isolation, backups, monitoring, intrusion detection.
- [`../NETWORK.md`](../NETWORK.md) — the five tiers, what each may talk to, and why the
  database is not on the internet.
- [`../STORAGE.md`](../STORAGE.md) — where uploaded bytes live (rows, never files), what is
  checked on the way in, what metadata is stripped, and what a stolen volume yields.
- [`../ENVIRONMENT.md`](../ENVIRONMENT.md) — every variable the server reads, its default
  and what it does. Nothing is read outside `config.ts`.
- [`../RELEASE.md`](../RELEASE.md) — the release gate: the clean-clone verification, the
  checklist, the security baseline, the fourteen areas a commit clears before it ships, and
  where each requirement of points 109–140 is answered.
- [`../DEPENDENCY_INVENTORY.md`](../DEPENDENCY_INVENTORY.md) — the generated inventory and
  freeze: every package, its licence, and the four reviewed facts per direct dependency.
- [`../BACKUPS.md`](../BACKUPS.md) — encrypted snapshots, the restore drill, and the
  retention window that stops a backup set becoming a permanent copy of deleted accounts.
- [`../LOGGING.md`](../LOGGING.md) — a JSON line per 500, one at boot, no access log.
- [`../OBSERVABILITY.md`](../OBSERVABILITY.md) — the two health endpoints, the counters
  behind them, what is deliberately not measured, and what to look at when something breaks.
- [`../INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) — when the deployment is the
  incident.

**Code:** `deploy/docker-compose.yml`, `deploy/Caddyfile`, `deploy/tor/`,
`deploy/github-ci.yml` (the CI definition a human copies to `.github/workflows/`),
`deploy/postgres-roles.sql` (the least-privilege roles, ADR-0095),
`deploy/security-baseline.json` (the recorded security surface, point 139),
`scripts/backup.mjs`, `scripts/incident.mjs`, `scripts/release.mjs`, `scripts/clean-clone.mjs`,
`src/server/config.ts`.

**Kept honest by:** `test/deployment.test.ts` (every property these pages claim about the
containers, the networks and the TLS floor, asserted against the files themselves —
ADR-0040), `test/defaults.test.ts` (the shipped configuration is the private one),
`test/onion.test.ts` (clearnet and onion behaviour differ in exactly four documented ways),
`test/observability.test.ts` (health is administrator-only and holds nothing but numbers),
`test/resources.test.ts` (the ceilings that hold when a request never finishes),
`test/backup.test.ts`, `test/incident.test.ts`, `test/release.test.ts` (the gate, the baseline
and the inventory all describe a system that exists), and `npm run audit:deployment`, which
compares a live deployment with a local reproducible build.
