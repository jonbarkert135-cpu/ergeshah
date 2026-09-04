# Releasing

Points 109, 138, 139 and 140. Everything this project verifies already exists as a lint rule,
a test or an audit. What did not exist was the **gate**: one command that runs them from a
clean starting point, maps each area a release has to clear onto the evidence that actually
covers it, and compares this commit's security surface with a recorded baseline so that an
expansion is a failure rather than a footnote nobody reads.

```bash
npm run release                  # check, tests, audits, static checks, baseline
npm run release -- --clean-clone  # the same, plus a full fresh-clone verification
npm run verify:clean-clone       # only the clean clone (minutes, and a network)
npm run release:baseline         # only the baseline comparison (seconds)
```

Three rules it is built around, because they are the three ways a release gate lies:

1. **A check that did not run is never green.** A category without evidence prints `NOT RUN`,
   and the command exits non-zero. The clean-clone verification is the usual absentee: it
   needs minutes and a network, so it is opt-in, and until it has run this commit is not
   production-ready. A check the network prevented prints `COULD NOT RUN` — also not a pass,
   but not a finding against the commit either. The two are worth separating: `audit:deps`
   asks the public registry for advisories, and a registry that answers 503 says nothing
   about this code. For the same reason the gate runs the thirteen audits one at a time
   instead of `npm run audit`: that script is a chain of `&&`, so one unreachable host used
   to leave ten audits unrun and printed as failures. `scripts/clean-clone.mjs` exits 0
   verified, 1 a finding, 2 not verified (the network).
2. **The report carries measured values**, not remembered ones — 4 direct dependencies, 65
   packages in the production tree, 2 published ports, 13 response headers.
3. **The baseline is a ratchet.** A number that grew, a port that appeared, a header that
   disappeared: each fails until it is fixed, or recorded on purpose in
   `deploy/security-baseline.json` by the commit that caused it.

## The clean-clone gate (point 109)

The working directory is not the source of truth. It has a `node_modules` installed weeks
ago, a built `public/`, and possibly a file nobody committed — and an audit that reads
*tracked* files passes locally on a tree that would fail anywhere else. So the official
verification starts from an empty directory:

```
an empty directory -> git clone -> npm ci -> lint and types -> build -> tests -> audits
```

`node scripts/clean-clone.mjs` does exactly that, in a temporary directory it removes
afterwards (`--keep` leaves it). The remote comes from `git remote get-url origin` rather
than from the source, because a host name written into this repository is something
`audit:cost` and `audit:egress` refuse. The clone is full rather than shallow, because
`audit:history` walks every commit. Unit, integration and security tests are one command:
`vitest` runs every suite under `test/`, and `docs/TESTING.md` groups them by what they
prove rather than by kind. "Production checks" is `npm run audit` — the ten audits CI runs.

If the clone is not at the same commit as the working tree, the script says so: unpushed work
is not what a clean clone verifies.

GitHub Actions performs the same pipeline on every push (`deploy/github-ci.yml`: checkout,
`npm ci`, `npm run check`, `npm test`, `npm run build:client`, `npm run audit`), which is why
this script exists in addition rather than instead — a green tick proves that GitHub's runner
said those commands exited zero, and an operator who wants that answer without trusting a
third party runs it themselves.

### Reproducible install and build (point 110)

| Property | How it is held | Where it is checked |
| --- | --- | --- |
| Deterministic install | `package-lock.json` is committed; `npm ci` refuses to resolve anything the lockfile does not pin; every entry carries an integrity hash and resolves to the public registry; `.npmrc` sets `ignore-scripts=true` | `npm run audit:supply` |
| Pinned build tool | `esbuild` is pinned to an exact version, because a caret on the bundler is a caret on the bytes the browser runs | `npm run audit:supply` |
| Deterministic build | The client is built twice and the digests compared, so a plugin that embeds a timestamp or a path is a failed build | `npm run audit:bundle` |
| The same commit, the same bytes | `public/BUILD.txt` records a SHA-256 per artifact; `npm run audit:deployment -- <origin>` compares a running deployment with a local build of the same source | `test/audit.test.ts` |
| Reproducible migrations | Migrations are ordered with no gaps, checksummed in `CHECKSUMS.txt`, and a released one is never edited | `npm run audit:migrations` |

What is *not* claimed: bit-for-bit reproducibility across Node versions or platforms. The
build is reproducible on one machine and between two machines running the same Node and the
same lockfile, which is what the two-build comparison verifies. A different Node minor
version can produce different minified bytes, and nothing here detects that for you.

## Dependency changes (points 111, 112)

`docs/DEPENDENCY_INVENTORY.md` is generated (`npm run inventory:update`) and committed:
totals, the runtime dependencies, every direct dependency with its purpose, security
relevance, network behaviour and replacement possibility, the whole production tree with
licences, and the development tree. `npm run audit:inventory` — part of `npm run audit` —
regenerates it and fails if the result differs from what is committed.

That failure is the freeze. A dependency changed, and the change owes four reviews before the
document is regenerated: **security** (advisories, what it can reach), **licence** (on the
allowlist, shippable in a closed-source product), **privacy** (does it open a connection,
does it send anything anywhere), **regression** (`npm run check && npm test && npm run
audit`). The freeze digest at the top of the inventory is the token to quote in the commit
message.

The document is the inventory; `docs/DEPENDENCIES.md` is still the argument for each
dependency, written by a person, and `audit:dependencies` still fails if a package enters the
tree without a section there.

## The release checklist (point 138)

Printed by `npm run release`, with the run that decided each line. Nothing on this list is
answered by reading.

| Checklist item | What proves it |
| --- | --- |
| tests green | `npm test` — every suite under `test/` |
| migration status | `audit:migrations` — ordered, checksummed, unedited since release |
| secrets clean | `audit:secrets` (working tree) and `audit:history` (every blob in every commit) |
| dependencies audited | `audit:deps`, `audit:dependencies`, `audit:supply`, `audit:inventory` — each run separately, each reported separately |
| containers hardened | `test/deployment.test.ts`, and `containersWithoutHardening` in the baseline |
| security headers active | `test/hardening.test.ts`, and `securityHeaders` in the baseline |
| database inaccessible externally | `test/deployment.test.ts` — no published database port, internal network with no gateway |
| storage inaccessible directly | `test/uploads.test.ts` — blobs are rows, served as JSON to their owner only |
| debug disabled | `npm run release` static check: no debug variable in `config.ts`, no production source map |
| production environment valid | `test/environments.test.ts`, `test/defaults.test.ts` |
| no accidental external services | `audit:cost` and `audit:egress` |
| no test credentials | `npm run release` static check over every deployed file |
| no development routes | `npm run release` static check over the route table |
| security findings triaged | `audit:security` — the source rules in `scripts/security.mjs`, the findings register with no open CRITICAL or HIGH, and the suppression file (`docs/SECURITY_PIPELINE.md`) |

The three static checks are in `scripts/release.mjs` because they are about what is *absent*,
and an absence has no natural home in a suite about behaviour. Two more are there for the same
reason, and they belong to point 134:

## Break-glass, and what does not exist (point 134)

There is an emergency mechanism, it is documented, and it can only take access away:
`scripts/incident.mjs` — suspend an account, revoke every session, freeze writes (ADR-0037,
ADR-0080, `docs/INCIDENT_RESPONSE.md`). It runs from a clone as an operator command against
the database, and `deploy/Dockerfile` copies `scripts/` into the *build* stage only, so it is
not inside the image the service runs. A break-glass path shipped inside the running service
is a backdoor with a nicer name.

What does not exist, and what the release gate checks does not appear in the configuration:
a master password, a master token, a master key, a recovery backdoor, an `ADMIN_PASSWORD` or
a `ROOT_PASSWORD`. There is no credential that authenticates as somebody else. An
administrator cannot read a message, a vault or a delivery — those are encrypted to keys the
server never holds — and the emergency tool cannot either.

## The baseline (point 139)

`deploy/security-baseline.json` is the recorded security surface of the last approved
release, measured by `scripts/release.mjs` and compared on every run (and in CI, through
`npm run audit`). Eleven fields, three kinds, and the kind decides which direction is a
failure:

| Kind | Fields | Failure |
| --- | --- | --- |
| Count | direct production dependencies, packages in the production tree, privileged containers, containers missing a hardening flag | The number **grew** |
| Surface | published ports, services with a route to the internet, files allowed to make an outbound call, authentication and session routes | A member the baseline does **not** name appeared |
| Defence | security headers, storage limits enforced server-side, values a log line never carries | A member the baseline names **disappeared** |

The other direction is never a failure. It prints as `DRIFT`, which means the baseline is
describing a system that no longer exists and should be re-recorded:
`node scripts/release.mjs baseline --update`, in the commit that earned it, with the reason in
the message. Re-recording is not a way to make a failure go away quietly — the diff of that
file is one line per change, and it is the most readable security diff in the repository.

Every value is derived from the tree, never from a document: the container flags from
`deploy/docker-compose.yml`, the headers from `src/server/security.ts`, the storage limits
from `src/server/config.ts` and `src/server/lib/rate_limit.ts`, the redactions from
`src/server/lib/log.ts`, the outbound destinations from the egress audit's own allowlist, the
package counts from the lockfile. `test/release.test.ts` fails if the committed baseline stops
matching what those files say.

## The final gate (point 140)

Fourteen areas, each resting on evidence from *this* run:

| Area | Evidence |
| --- | --- |
| ARCHITECTURE | `test/architecture.test.ts`, `test/features.test.ts`, `test/adr.test.ts` |
| SECURITY | `test/security.test.ts`, `test/hardening.test.ts`, `test/compromise.test.ts`, `test/fuzz.test.ts`, `audit:security` |
| PRIVACY | `test/metadata.test.ts`, `test/logging.test.ts`, `test/observability.test.ts` |
| AUTH | `test/auth.test.ts`, `test/authorization.test.ts`, `test/authz_matrix.test.ts`, `test/sessions.test.ts`, `test/idor.test.ts`, `test/authz_fuzz.test.ts` |
| CRYPTO | `test/cryptography.test.ts`, `test/protocol.test.ts`, `test/hkdf.test.ts`, `test/pgp.test.ts` |
| DATABASE | `audit:migrations`, `test/migrations.test.ts`, `deploy/postgres-roles.sql` (ADR-0095) |
| STORAGE | `test/uploads.test.ts`, `test/attachments.test.ts`, `test/images.test.ts`, `test/jobs.test.ts` |
| NETWORK | `audit:egress`, `audit:bundle`, `test/deployment.test.ts` |
| CONTAINER | `test/deployment.test.ts`, and the baseline's container counts |
| BACKUP | `test/backup.test.ts`, `test/backup_postgres.test.ts`, and `npm run backup:drill` / `backup:pg:drill` for a real restore |
| DEPENDENCY | `audit:deps`, `audit:dependencies`, `audit:supply`, `audit:inventory` |
| CLEAN-CLONE | `node scripts/clean-clone.mjs` |
| COST | `audit:cost` — zero mandatory paid services, API keys or hosted dependencies |
| REGRESSION | `deploy/security-baseline.json` |

A final report says what was measured. It does not say "secure" — the word that belongs
there is the property and its test. It does not say "privacy-preserving" without naming which
property (`docs/PRIVACY.md`, `docs/METADATA.md`, and the residual risks in
`docs/THREAT_MODEL.md`). And it does not say "zero-cost" if `audit:cost` found a mandatory
paid dependency — that audit prints seven numbers precisely so the claim can be quoted with
them.

## Restoring, which is the other half of a release (points 136, 137)

A release you cannot roll back to a working state is a release you cannot make twice.
`docs/BACKUPS.md` is the policy — encrypted snapshots, verified on creation and again on
restore, integrity-checked, access-controlled, retention-bounded — and the drill is the part
that matters here:

```
NEW VPS -> INSTALL -> RESTORE DATABASE -> RESTORE STORAGE -> RUN MIGRATIONS
        -> VERIFY INTEGRITY -> HEALTH CHECK -> APPLICATION ONLINE
```

Storage is not a separate step in this architecture: blobs are rows in the database
(`docs/STORAGE.md`), so restoring the database restores the uploads with it — which is one of
the reasons that decision was made. `npm run backup:drill` performs restore, integrity check,
migrations and a real boot with a health check on a temporary copy; `test/backup.test.ts` runs
the whole round trip on every commit, including a wrong key and a flipped byte. The step no
script can do for you is the first one, and `docs/DEPLOYMENT.md` is the path through it.

## Where the rest of this block is answered

Points 113–137 are mostly older work; this page exists so that nobody has to guess where.

| Requirement | Where it lives |
| --- | --- |
| 113 zero-cost gate | `npm run audit:cost` (ADR-0094), `docs/AUDIT.md` §The zero-cost audit |
| 114 outbound network audit | `npm run audit:egress`, `docs/NETWORK.md` §Every external request |
| 115 no silent telemetry | `audit:egress` (telemetry packages, transitive included), `audit:bundle` (`sendBeacon`, remote URLs), `test/fingerprint.test.ts` |
| 116 third-party assets | `audit:bundle` — system fonts, inline SVG, everything from this origin |
| 117 secret scanning | `audit:secrets` (tracked files), `audit:history` (every blob ever committed) |
| 118 build artifact scan | `audit:bundle` builds production and scans the output; no source map; `audit:deployment` compares served bytes |
| 119 Docker hardening | `deploy/docker-compose.yml`, `deploy/Dockerfile`, `test/deployment.test.ts`, and the baseline |
| 120 filesystem hardening | Uploads are database rows, never files; the container is read-only with a tmpfs (`docs/STORAGE.md`) |
| 121 storage quotas | `MAX_DELIVERY_BYTES`, `STORAGE_FLOOR_BYTES`, `MAX_BLOB_ROWS`, the `attachment` and `upload_bytes` buckets (ADR-0093), all server-side |
| 122 storage atomicity | One transaction per upload, and the sweep that removes what a failed one left (`src/server/lib/jobs.ts`, `test/jobs.test.ts`) |
| 123 orphaned file detection | The hourly blob sweep and the object ceiling (`docs/STORAGE.md`) |
| 124 safe file replacement | Ownership and state are re-checked in the handler; one blob per order, never replaced in place (`test/uploads.test.ts`) |
| 125 file content security | `test/uploads.test.ts` — ELF header, SVG payload, zip bomb, traversal, MIME spoofing, oversized bodies |
| 126 image sanitisation regression | `test/uploads.test.ts` and `test/images.test.ts` — JPEG, PNG and WebP fixtures asserted metadata-free, idempotently (ADR-0092) |
| 127 private file cache | `cache-control: no-store` on every private reply, no static route over user content (`test/hardening.test.ts`) |
| 128 authorised download matrix | `test/uploads.test.ts` and `test/idor.test.ts` — owner allowed, order party allowed, stranger, moderator, administrator and unknown id refused identically |
| 129 message attachment security | Encrypted in the browser, stored and served as ciphertext, no server-side preview (`test/attachments.test.ts`) |
| 130 message metadata review | `docs/METADATA.md`, the four questions per leak, `test/metadata.test.ts` |
| 131 session revocation | `test/auth.test.ts`, `test/recovery.test.ts`, `test/security_center.test.ts` — password change, key rotation, recovery and logout-everywhere each end every other session |
| 132 authorisation matrix | `docs/AUTHZ_MATRIX.json` — who × resource × action per route, checked live in both directions by `test/authz_matrix.test.ts`; `test/authorization.test.ts` walks the route table for the missing-check case: public by allowlist, ownership, and every staff route refused to a normal account |
| 133 privilege escalation | The same suite, plus `test/moderation.test.ts` and `test/idor.test.ts`: no route promotes its caller |
| 134 break-glass | This page, ADR-0037, `scripts/incident.mjs`, and the static check above |
| 135 database least privilege | `deploy/postgres-roles.sql` (ADR-0095) — a non-superuser application role, a read-only backup role, and the migration trade stated in the file |
| 136 backup security gate | `docs/BACKUPS.md`, `test/backup.test.ts`, `test/backup_postgres.test.ts` (ADR-0115) |
| 137 restore drill | `npm run backup:drill`, and the sequence above |
