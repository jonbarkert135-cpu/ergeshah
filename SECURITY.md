# Security policy

## Reporting a vulnerability

Report privately, not in a public issue. Open a GitHub *security advisory* on this
repository (Security → Advisories → Report a vulnerability). Include:

- affected component and version/commit,
- reproduction steps or a proof of concept,
- the impact you believe it has,
- whether the issue is already public.

Please do not run automated scanners, load tests, or account-enumeration attempts
against a deployment you do not own.

## Scope

In scope: authentication, session handling, authorization/IDOR, the cryptographic
protocol and its implementation, metadata leaks beyond what `docs/THREAT_MODEL.md`
already documents, injection, SSRF, supply-chain issues in our dependency set.

Out of scope: findings that only restate a *documented* residual risk in
`docs/THREAT_MODEL.md`, missing hardening that has no attack path, self-XSS,
and issues in third-party infrastructure of a specific deployment.

## What we will not claim

We do not claim anonymity, unbreakability, or complete metadata protection. Security
statements in this repository are tied to a written threat model, and a report that
narrows the gap between that model and reality is always welcome.
