# The security pipeline

Points 141–180. This page is the process half of that block: what the project *does*
continuously, with which commands, and what each one is allowed to claim. The mechanisms it
tests are in `docs/MECHANISMS.md`, the defects it has found are in
`docs/SECURITY_FINDINGS.md`, and the fixes are in `docs/SECURITY_CHANGELOG.md`.

The starting point (point 141) is a change of stance rather than a new subsystem: this is a
**continuously audited system**, so every change answers the same eight questions before it is
committed — what can be broken, what can be attacked, what new data comes into existence, did
the attack surface grow, is there a new dependency, a new outbound request, a new privilege, a
new metadata leak. `docs/CHANGE_REVIEW.md` §1 is where those answers land; this page is what
runs when nobody is asking.

## The commands

| Command | What it is | Where it runs |
| --- | --- | --- |
| `npm run audit:security` | the static half: the source rules, the findings register, the suppression file | inside `npm run audit`, so on every push and in CI |
| `npm run security` | the ten stages of point 150, end to end | before a release, and whenever a sweep is worth repeating |
| `npm run security:tools` | which external scanners exist on this machine, and what each would add | when deciding whether to install one |
| `npm run release` | the release gate: fourteen areas, the baseline, the clean clone | before a production release (`docs/RELEASE.md`) |

Nothing above needs an account, a key or a network service. `npm run audit:cost` fails the
build if that ever stops being true, which is the mechanical form of the promise in point 149.

## The ten stages, and what covers each

Point 150 asks for a pipeline. Most of it already existed here as audits and tests, so the
pipeline is a *map* rather than a second implementation — the alternative is two half-checks
that disagree.

| Stage | Evidence |
| --- | --- |
| SOURCE SCAN | `scripts/security.mjs` rules (below) plus `scripts/lint.mjs` through `npm run check` |
| DEPENDENCY SCAN | `npm run audit:deps` (npm advisories at high), `audit:dependencies` (budget, licences), `audit:inventory` (the freeze), optional `osv-scanner` |
| SECRET SCAN | `npm run audit:secrets` (working tree), `audit:history` (every blob in every commit), `audit:bundle` (what the browser gets), optional `trivy` |
| CONFIG SCAN | `npm run audit:cost`, `audit:egress`, and the five static checks in `scripts/release.mjs` |
| CONTAINER SCAN | `test/deployment.test.ts` and the baseline's privileged/hardening counts (`deploy/security-baseline.json`) |
| UNIT SECURITY TESTS | `test/fuzz.test.ts`, `test/cryptography.test.ts`, `test/hkdf.test.ts`, `test/padding.test.ts` |
| INTEGRATION SECURITY TESTS | `test/authz_fuzz.test.ts`, `test/authorization.test.ts`, `test/idor.test.ts`, `test/security.test.ts`, `test/compromise.test.ts` |
| DYNAMIC APPLICATION TEST | OWASP ZAP against a running deployment — an operator step, not a CI step (see below) |
| REPORT | the summary `npm run security` prints, and the register |
| FIX AND RESCAN | `skills/vulnerability-remediation/SKILL.md`, the loop in point 179 |

**Why the dynamic test is an operator step.** ZAP needs something running to attack. A CI job
could start the service, but it would be a service with an empty database, no Tor, no reverse
proxy and no TLS — the four things the dynamic findings would be about. So the honest
arrangement is: the suite covers the application logic, and the active scan is run against a
staging deployment by whoever operates it, with `zap.sh -cmd -quickurl <origin>`. Until that
happens the stage prints NOT RUN, and NOT RUN is not a pass.

## The source rules

`scripts/security.mjs` holds them, one per class of mistake, each with a severity and the
reason it exists. They are patterns, for the same reason `scripts/lint.mjs` is: a generic
analyser brings a hundred packages and does not know one thing that matters here. What it
knows instead:

- **cryptography (point 174)** — a weak hash, an unauthenticated cipher mode, a nonce that is
  not random per message, a password used directly as a key, a secret compared with `===`;
- **mass assignment (point 164)** — a request body spread into a row or an update;
- **CORS (point 169)** — a wildcard origin, a reflected origin, a CORS plugin;
- **cookies (point 171)** — a `set-cookie` built by hand instead of through `serializeCookie`;
- **SSRF (point 165)** — a URL taken from a request and fetched;
- **XSS variants (point 166)** — a URL attribute set outside `el()`, or any HTML/markdown
  renderer appearing in the tree;
- **enumeration (point 172)** — an authentication path whose error names the account.

A rule can be waived on a line with an `audit:allow` comment and a reason, as everywhere else.
A rule that fires on correct code is a bug in the rule and is narrowed there — that is what
happened to two of them on the first run, and it is preferable to a suppression.

## Severity, triage and the release block

Every finding is a row in `docs/SECURITY_FINDINGS.md` with the eleven fields point 151 asks
for. Severity is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` (point 152), judged against
*this* system: what an attacker gets, what they need first, what it costs the people using it.

An open `CRITICAL` or `HIGH` blocks a release. `npm run audit:security` fails while one
exists, so the block is mechanical rather than a promise — and the exit is a status of
`accepted` whose reasoning is written in the row, not a silent downgrade.

## Suppressions (point 153)

A scanner is not switched off, a warning is not muted globally, and a severity is not lowered
because a fix is inconvenient. What is allowed is a scoped suppression in
`deploy/security-suppressions.json` carrying a rule, a scope, a reason, an owner and a review
date; the scan fails on a missing field, an unknown rule or a review date in the past. The
file is currently empty, and the two sweep results that turned out to be design are `accepted`
rows in the register instead — a decision with reasoning beats a mute.

## Patch management (points 176, 177)

| Severity | Response |
| --- | --- |
| CRITICAL | reviewed immediately; the fix or the mitigation is the next commit |
| HIGH | priority: before the next feature |
| MEDIUM | scheduled: this cycle, with a date in the register |
| LOW | backlog, re-read when exploitability changes |

A dependency advisory follows the same seven steps every time (point 176): find the affected
version, judge whether the vulnerable path is reachable *here*, find the fixed version, check
compatibility, update, run `npm run check && npm test && npm run audit`, and record the result
— in `docs/DEPENDENCY_INVENTORY.md` (the freeze) and in the changelog if it was reachable.
A breaking update is not applied blind: it is its own commit with its own review, and if it
cannot be applied the finding stays open with the reason. Nothing unpatched is hidden — an
advisory this project cannot act on yet is a row in the register with a status, which is why
`npm audit` runs at `--audit-level=high` on production dependencies only and is never
`--force`d.

## What this process does not claim

It does not claim the system is secure, and `npm run security` prints that sentence at the end
of every run. What it claims is narrower and checkable: these checks ran, on this commit, and
this is what they found. The gaps are named where a reader will find them —
`docs/SECURITY_REVIEW.md` for what the internal reviews missed, `docs/EXTERNAL_REVIEW.md` for
the audit that has not happened (roadmap CRY-1), `docs/THREAT_MODEL.md` for the residual risks
that no test can close.
