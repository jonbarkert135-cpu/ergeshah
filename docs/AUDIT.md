# Auditing this system

An external cryptographic audit costs money this project does not have. What it *can* have
is a system that is cheap to audit: small, dependency-poor, and checked by machine on every
push. When the money exists, the brief to send with the repository is
[`EXTERNAL_REVIEW.md`](EXTERNAL_REVIEW.md): what to review, in which order, what CI already
proves, and the five questions this project cannot answer about itself.

**Read this first: the source is closed** (`LICENSE`). Everything below is therefore an
*internal* audit — it is run by the people who hold the repository, and its results are a
claim to everyone else. A user of a deployment cannot repeat any of it. Where this document
used to say "what you can verify yourself", it now says "what the operator can verify", and
the difference is not cosmetic: an internal check that nobody outside can reproduce is
evidence of diligence, not evidence of behaviour.

The one thing an outsider can still do is read the client their own browser downloads — it
is minified, but it is there, and the network tab shows every request it makes. That is the
floor of verifiability for any web application, and closing the source does not lower it.

## What CI enforces on every push

| Check | Command | What a failure means |
| --- | --- | --- |
| Lint | `npm run lint` | A project rule was broken: markup built from a string, `Math.random`, the environment read outside `config.ts`, SQL built by interpolation, a `.only` test |
| Types | `npm run typecheck` | TypeScript strict mode found a hole |
| Behaviour | `npm test` | Crypto vectors, ratchet properties, authorization, limits, defaults, migrations, documentation drift |
| Dependency CVEs | `npm run audit:deps` | A production dependency has a high or critical advisory |
| Dependency policy | `npm run audit:dependencies` | A package entered the tree without a justification in `docs/DEPENDENCIES.md`, carries a licence we cannot ship, or the tree exceeded its budget |
| Client bundle | `npm run audit:bundle` | What we serve would talk to a host we do not operate |
| Repository | `npm run audit:secrets` | Something that looks like key material is committed |
| Git history | `npm run audit:history` | Something that looks like key material was committed *at any point*, including in a commit later reverted |
| Migrations | `npm run audit:migrations` | A released migration was edited, numbering has a gap, or something destructive is unexplained |
| Supply chain | `npm run audit:supply` | The lockfile lost an integrity hash, a package resolves outside the public registry, or install scripts are no longer disabled |
| Reproducibility | part of `audit:bundle` | Two identical builds produced different bytes |

`npm run check` runs lint and types; `npm run audit` runs the seven audits.

They all live in `scripts/audit.mjs` and `scripts/lint.mjs`, are `String.matchAll` and
`git` plumbing, and add no dependency.

### What subresource integrity does and does not cover

`index.html` pins the entry script and the stylesheet with `integrity=`, and a browser
refuses either if the bytes do not match. It cannot do the same for the lazily imported
cryptography chunk: there is no browser-enforced integrity for a dynamic `import()`. That
chunk is instead protected by three weaker things — a content-addressed filename (its name
*is* the hash of its bytes), its digest in `/build.txt`, and `default-src 'self'`, which
means it can only come from this origin. Weaker in kind, and worth stating rather than
glossing: an operator who swaps the chunk and the page together defeats all of it, exactly
as they would defeat SRI by editing the page (ADR-0027).

### `audit:history` — nothing secret was *ever* committed

`audit:secrets` reads the working tree, which answers the wrong question: a key committed
in March and deleted in April is still in every clone of this repository. `audit:history`
enumerates every blob in every commit (deduplicated by hash, so 39 commits cost 365 scans,
not thousands) and applies the same rules. A finding here cannot be fixed by editing a
file: rotate the secret, then rewrite history. The scanner's own test fixtures — bare PEM
headers, AWS's documented example key id, the RFC 7519 example JWT — are listed by blob
hash in `scripts/history-allow.json` with the reason each was reviewed.

### `audit:migrations` — a released migration is immutable

Editing a migration that has already run somewhere is the one mistake a redeploy cannot
fix: the developer's database has the change, production does not, and nothing says so
until a constraint fails months later. Digests live in
`src/server/db/migrations/CHECKSUMS.txt`; `npm run migrate:checksums` registers a new
migration; changing an old one fails the build.

### `audit:supply` — the install itself

`ignore-scripts=true` in `.npmrc` means no package executes code during installation,
which is the most-used npm compromise path. The audit verifies that setting, that every
locked package has an integrity hash and resolves to the public registry, that the
lockfile is version 3 or newer, and that the build tool is pinned to an exact version
rather than a range — a caret on `esbuild` is a caret on the bytes the browser runs.

### `audit:bundle` — the client talks to us and no one else

It builds the *production* client (`NODE_ENV=production`: minified, no inline source
map) and greps `public/app.js`, `app.css` and `index.html` for:

- remote `http(s)://`, `ws(s)://` and protocol-relative URLs — anything that would make
  a browser open a connection to a third party. Loopback and our own relative paths pass,
  as do the three XML namespace identifiers (`www.w3.org/2000/svg` and friends), which no
  browser ever fetches and which a standalone SVG must carry;
- `sourceMappingURL` — a production source map leaks build paths and original sources;
- `navigator.sendBeacon` — the analytics primitive that survives page unload;
- `openpgp` — ADR-0015 promises that dependency stays on the server;
- everything the secret rules below look for.

Why this check and not a policy document: a CDN font, an error-reporting SDK or a
single analytics snippet added in a hurry would silently break the "no third party ever
sees a request" claim in `docs/PRIVACY.md`, and no test would notice. This one fails
the build.

The runtime backstop is the Content-Security-Policy in `src/server/security.ts`
(`default-src 'self'`, no `connect-src` to anywhere else). The audit catches the
mistake at build time; the CSP catches it in the browser if the audit is wrong.

### `audit:secrets` — nothing sensitive is committed

Every git-tracked file is scanned for private-key blocks (PEM and OpenPGP), AWS access
key ids, JWTs, and long string literals assigned to a name like `password`, `token`,
`apiKey` or `secret`. Obvious placeholders (`changeme`, `your-…`, `process.env.…`,
`${…}`) are ignored, as are fixture passwords under `test/` — but key material in a
fixture is still a failure, because a test private key is a real private key.

It reads *tracked* files only, so run it after `git add` — a new file that has not been
staged is invisible to it, and to CI it will not be. A line can opt out with an
`audit:allow` comment plus a reason. That is deliberately
ugly and shows up in review.

## The zero-cost audit

A requirement of this project is that the whole of it runs with no compulsory spending at
all: a VPS the operator chooses, open-source software, a local database, local storage. The
inventory below is what that claim means in practice, and most of it is enforced by a script
rather than by intent.

| Thing a system usually pays for | What is here instead | Enforced by |
| --- | --- | --- |
| Authentication provider | Username, client-stretched password, optional PGP key, recovery phrase. No Google/Apple/Discord/Telegram login anywhere | `test/authorization.test.ts`, no OAuth dependency in `package.json` |
| Email or SMS delivery | Neither exists. No email column, no phone column, no password-reset mail, no SMS second factor — recovery is cryptographic (ADR-0006, ADR-0014) | `docs/DATABASE.md`, `test/recovery.test.ts` |
| CAPTCHA | Proof of work in the browser, `POW_BITS`, no third party (ADR-0039) | `test/antiautomation.test.ts` |
| Anti-DDoS / WAF | Token buckets keyed to an HMAC of the subject, plus the proxy's own limits. Absorbing a real flood is the operator's hosting decision, not a subscription this code needs | `test/limits.test.ts` |
| Analytics | None. No pixel, no session replay, no advertising identifier, no third-party origin permitted by the CSP | `audit:bundle`, `test/hardening.test.ts` |
| Monitoring / APM | In-process counters behind an admin-only health endpoint (`docs/OBSERVABILITY.md`) | `test/observability.test.ts` |
| Managed database | SQLite by default, PostgreSQL optional — both self-hosted (ADR-0005) | `docs/DEPLOYMENT.md` |
| Object storage | Blobs live in the database as ciphertext | `docs/DATABASE.md` |
| Fonts, icons, CDN | System fonts, inline SVG, everything served from this origin | `audit:bundle` ("no external references") |
| Cryptography as a service | libsodium and OpenPGP.js, both local, both open source | `docs/DEPENDENCIES.md` |
| AI APIs | None, anywhere in the product | — |

The one external service this system can talk to is a **Monero node and wallet RPC**, which
is open-source software the operator runs themselves, on their own hardware, and which the
deployment works without: with no wallet configured the marketplace still runs and the screen
says top-ups are not open (ADR-0070). `audit:bundle` fails the build if the client ever
references a host the operator does not run, which is the mechanical half of this promise;
the rest is this table, and it is reviewed when a dependency changes.

Cost of the core project: **the VPS, and nothing else.**

## What the operator can verify, for free

1. **Read the dependency list.** `package.json` — four production dependencies
   (`fastify`, `libsodium-wrappers-sumo`, `openpgp`, `pg`). Every one is justified in
   `docs/DECISIONS.md`. There is no build-time code you did not read here.
2. **Check the crypto against the specs.** `docs/CRYPTO.md` names every construction and
   parameter; `test/hkdf.test.ts` and `test/protocol.test.ts` check them against RFC
   vectors and as properties (out-of-order delivery, skipped keys, forward secrecy).
3. **Dump the database and look.** `test/*.test.ts` end with exactly this: a full dump
   asserted to contain no plaintext, no recovery words, no private keys. Run the server
   locally, use it, and read the tables yourself.
4. **Watch the network tab.** No requests to anything but the origin. That is the claim
   `audit:bundle` protects.
5. **Compare the served bundle with a build of this source.** The build is reproducible, so
   this is one command — available to whoever holds the repository, and to nobody else:

   ```bash
   npm ci                                   # locked dependency versions, or the bytes differ
   npm run audit:deployment -- https://the-deployment
   ```

   It builds the client here, fetches `/`, `/assets/app.js`, `/assets/app.css` and
   `/favicon.svg` from that deployment, and compares SHA-256 digests of the bytes actually
   sent. It catches a deployment that has drifted from the source, a bad build, or a
   compromised host — which is worth having — but it proves nothing to a user, who has no
   source to build. The deployment publishes its digests at `/build.txt`, and `index.html`
   pins the script and stylesheet with subresource integrity, so a browser refuses a bundle
   that does not match the page it arrived with. A user *can* compare that digest across
   browsers, machines and networks: identical digests everywhere mean at least that nobody
   is being served a personalised bundle.

## What none of this proves

- **Not a cryptographic audit.** Property tests find broken code; they do not find a
  broken *design*. CRY-1 in the roadmap stays open.
- **A grep is a grep.** `audit:bundle` finds a literal URL. It does not find one
  assembled at runtime from fragments, and it never will. Its purpose is to stop honest
  mistakes, not a malicious commit — a hostile committer is out of scope here and
  in the threat model.
- **`audit:secrets` has both error kinds.** It misses a credential that does not look
  like one, and it will occasionally shout about a constant that is not one. Rotate
  anything it finds; never resolve a finding by widening the placeholder rule.
- **Closed source caps all of it.** With the source private, every statement in this
  repository about what the software does is a statement of intent that an outsider must
  take on trust. The mitigations that survive are indirect: the client is delivered to the
  browser and can be inspected there, the served digests can be compared between users, and
  the network tab shows where requests go.
- **Reproducible is not trustworthy.** A reproducible build proves the deployment matches
  *this source*; it says nothing about whether this source is correct. And it is an
  after-the-fact check by whoever runs it: a server can serve one bundle to an auditor and
  another to one user, which is residual risk #1 in `docs/THREAT_MODEL.md` and is not
  solved by hashing.
- **CI runs on GitHub's infrastructure.** A green tick proves that *their* runner said
  these commands exited zero. It is not a proof about the artifact your users receive;
  the artifact your users receive; comparing that artifact is what `audit:deployment` is
  for.
- **Nothing here audits the deployment.** Server configuration, TLS termination, the
  operator's own machine and their backups are outside every check in this document.
  See `docs/DEPLOYMENT.md` and the operator section of `docs/THREAT_MODEL.md`.

## When you find something

Do not open a public issue for a vulnerability — `SECURITY.md` explains the private route
and what is in scope. A closed-source project depends on that channel more than an open one
does: nobody will read the code and send a patch, so the report is the only signal. Findings from the checks above that are *not* vulnerabilities — a false
positive, a missing rule — are ordinary issues and pull requests; new rules go in
`scripts/audit.mjs` with a test in `test/audit.test.ts` that fails without them.
