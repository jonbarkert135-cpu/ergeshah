# Security

- [`../../SECURITY.md`](../../SECURITY.md) — the policy: assumptions, model summaries,
  known limitations, and how to report a vulnerability.
- [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — the contract. Attackers, mitigations and the
  residual risk of each. A claim not made here is not made anywhere.
- [`../SECURITY_REVIEW.md`](../SECURITY_REVIEW.md) — the ten review passes, what each round
  found, and the test that closed each finding.
- [`../INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) — credential rotation, session
  revocation, compromised server, database breach, dependency vulnerability, key
  compromise.
- [`../MODERATION.md`](../MODERATION.md) — the four moderation lanes kept apart, why private
  messages have none, and every control that stops abuse without watching everybody.
- [`../PAYMENTS.md`](../PAYMENTS.md) — payments do not exist yet; this is the architecture
  they have to follow if they ever do.
- [`../HARDENING.md`](../HARDENING.md) — hardening the host the service runs on.
- [`../NETWORK.md`](../NETWORK.md) — the network tiers, and what the application container
  cannot reach.
- [`../AUDIT.md`](../AUDIT.md) — the scanners that run on every push (bundle, secrets,
  history, migrations, supply chain) and what each one refuses.
- [`../LOGGING.md`](../LOGGING.md) — what is written down, and for how long.

- [`../MECHANISMS.md`](../MECHANISMS.md) — one row per security mechanism: the threat it
  answers, the property it provides, where it lives, what proves it, and how it fails.
- [`../SELF_CRITIQUE.md`](../SELF_CRITIQUE.md) — the weaknesses found by reviewing this
  repository against its own claims, graded, with the fix or the reason there is not one.

**Also:** [`../CHANGE_REVIEW.md`](../CHANGE_REVIEW.md) — the security-regression question
every change answers before it is committed, and the priority order when two requirements
conflict.

**Code:** `src/server/security.ts` (CSP, headers, CSRF), `src/server/app.ts`
(authentication, roles, limits), `src/server/lib/rate_limit.ts`, `lib/validate.ts`,
`lib/audit.ts`, `scripts/incident.mjs`.

**Kept honest by:** `test/authorization.test.ts` (every route refuses an anonymous caller
unless it is on an explicit public list), `test/security.test.ts` (one suite per attack
class in point 53), `test/sessions.test.ts` (lifetime, rotation, revocation and the
identifier split), `test/antiautomation.test.ts` (the proof-of-work gate and uniform
recovery answers), `test/deployment.test.ts` (the containers and networks the service runs
in), `test/limits.test.ts`, `test/hardening.test.ts`, `test/defaults.test.ts`,
`test/incident.test.ts`, `test/abuse.test.ts` (moderation cannot reach a message, and the
report lanes stay separate), `test/payments.test.ts` (no card-shaped column, no route that
takes one).
