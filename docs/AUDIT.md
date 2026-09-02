# Auditing this system for nothing but time

An external cryptographic audit costs money this project does not have. What it *can*
have is a system that is cheap to audit: small, dependency-poor, and checked by
machine on every push. This document says what is checked automatically, what you can
verify yourself in an hour, and — the part that matters — what neither of those proves.

## What CI enforces on every push

| Check | Command | What a failure means |
| --- | --- | --- |
| Types | `npm run check` | TypeScript strict mode found a hole |
| Behaviour | `npm test` | Crypto vectors, ratchet properties, authorization, recovery, PGP |
| Dependency CVEs | `npm run audit:deps` | A production dependency has a high or critical advisory |
| Client bundle | `npm run audit:bundle` | What we serve would talk to a host we do not operate |
| Repository | `npm run audit:secrets` | Something that looks like key material was committed |

`npm run audit` runs the last three together. The two new ones live in
`scripts/audit.mjs`, are about a hundred lines of `String.matchAll`, and add no
dependency.

### `audit:bundle` — the client talks to us and no one else

It builds the *production* client (`NODE_ENV=production`: minified, no inline source
map) and greps `public/app.js`, `app.css` and `index.html` for:

- remote `http(s)://`, `ws(s)://` and protocol-relative URLs — anything that would make
  a browser open a connection to a third party. Loopback and our own relative paths pass;
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

## What you can verify yourself, for free

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
5. **Diff the served bundle.** Build the client from this source and compare with what
   the server sends you. Byte-for-byte reproducibility is not there yet (OPS-1 in
   `docs/ROADMAP.md`) — until it is, this check is indicative, not conclusive.

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
- **CI runs on GitHub's infrastructure.** A green tick proves that *their* runner said
  these commands exited zero. It is not a proof about the artifact your users receive;
  only reproducible builds (OPS-1) would move that trust.
- **Nothing here audits the deployment.** Server configuration, TLS termination, the
  operator's own machine and their backups are outside every check in this document.
  See `docs/DEPLOYMENT.md` and the operator section of `docs/THREAT_MODEL.md`.

## When you find something

Do not open a public issue for a vulnerability — `SECURITY.md` explains the private
route (a GitHub security advisory) and what is in scope. Findings from the checks above that are *not* vulnerabilities — a false
positive, a missing rule — are ordinary issues and pull requests; new rules go in
`scripts/audit.mjs` with a test in `test/audit.test.ts` that fails without them.
