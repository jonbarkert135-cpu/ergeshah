# Dependencies

Every dependency is code we did not write, running with our privileges, updated by someone
we do not know. The rule in this project is not "few dependencies" as a slogan — it is that
**no package enters the production tree without a written reason on this page**, and
`npm run audit:dependencies` fails the build if one does.

**budget: 68** production packages, transitive included. Today the tree is 65. Raising this
number is allowed; raising it in a commit that does not explain why is not.

**The inventory is generated, and it is a freeze (points 111, 112).**
[`DEPENDENCY_INVENTORY.md`](DEPENDENCY_INVENTORY.md) lists the whole tree — transitive
included, with a licence per package and the four reviewed facts per direct dependency — and
`npm run audit:inventory` regenerates it and fails if the committed copy no longer describes
the tree. So a version change cannot arrive unnoticed: it owes a **security review**, a
**licence review**, a **privacy review** and a **regression test** before
`npm run inventory:update` writes the new document. This page stays the argument; that page is
the record.

The rule that keeps the number small: *a dependency must do something we cannot do correctly
ourselves in a comparable amount of code*. Cryptography and a database protocol qualify.
Padding a string, generating a UUID, parsing a cookie, formatting a date, deep-cloning an
object and validating a schema do not — those are in `src/shared` and `src/server/lib`,
under a hundred lines each, and they carry no supply-chain risk.

## What each one does on the network (point 53)

A security review of a dependency asks whether it has a CVE. A privacy review asks a different
question — *does it talk to anyone?* — and the answer has to be per package, because "we have
four dependencies" says nothing about what those four do at runtime.

| Package | Opens a connection? | Sends anything anywhere? |
| --- | --- | --- |
| `fastify` | Yes: it *is* the listener. Inbound only — it accepts connections, it never initiates one | No telemetry, no update check, no phone-home |
| `libsodium-wrappers-sumo` | No. WASM and arithmetic | No |
| `openpgp` | No, in the way this project uses it: signature verification over bytes already in memory. It has no key-server client here and is never given a URL | No |
| `pg` | Yes: to the database in `DATABASE_URL`, and nowhere else | No |

Two checks keep that table from becoming a claim nobody verifies: `npm run audit:egress` fails
if a package whose purpose is telemetry appears anywhere in `package-lock.json`, or if any file
under `src/server` or `scripts` grows an outbound call that the audit does not already name with
a reason. What neither check can see is a *transitive* dependency that opens a socket at
runtime without saying so in its name — the mitigations for that are the small tree, the
install-script refusal (`.npmrc`), and the application container having no route to the
internet at all (`docs/NETWORK.md`).

## Production dependencies

### `libsodium-wrappers-sumo`

| | |
| --- | --- |
| Why | X25519, XChaCha20-Poly1305, Argon2id, Ed25519 — the whole primitive set the protocol needs (`docs/CRYPTO.md`). Hand-writing any of it would be malpractice |
| Necessity | Unavoidable. WebCrypto has no XChaCha20-Poly1305 and no Argon2id, and both are load-bearing here |
| Popularity / maintenance | The official JS distribution of libsodium, tracking upstream releases; libsodium itself is audited and is the reference implementation for these primitives |
| Vulnerabilities | None in `npm audit`; the WASM is compiled from the audited C |
| Licence | ISC |
| Transitive | 1 (`libsodium-sumo`, the WASM payload) |
| Size | ~400 KB WASM in the client bundle. The largest single cost in the project, accepted knowingly |

### `openpgp`

| | |
| --- | --- |
| Why | Optional PGP login for users who already have a key (`docs/CRYPTO.md`). Verifying an OpenPGP signature means implementing RFC 4880 packet parsing — the exact opposite of something to write by hand |
| Necessity | Only for the PGP feature. It is **server-side only**, dynamically imported, and `audit:bundle` fails if the string `openpgp` ever appears in the client bundle |
| Popularity / maintenance | OpenPGP.js, maintained by Proton, the standard implementation for JS |
| Vulnerabilities | None outstanding |
| Licence | LGPL-3.0+ — used unmodified as a separate module, which is what the LGPL requires of a closed-source caller (`THIRD_PARTY.md`) |
| Transitive | 0 |
| Size | Large, but never reaches the browser |

### `fastify`

| | |
| --- | --- |
| Why | HTTP routing, and — the part that matters — a router that does not do surprising things: no automatic body coercion, explicit `bodyLimit`, `requestTimeout`, and a route table we can enumerate (`app.routeInventory`, used by the authorization test to prove no endpoint is left unauthenticated) |
| Necessity | `node:http` would work; we would then write routing, cookie parsing and body limits ourselves, which is more security-relevant code, not less |
| Popularity / maintenance | Among the most used Node frameworks, active security process |
| Vulnerabilities | None outstanding |
| Licence | MIT |
| Transitive | ~50 packages, the bulk of the tree. This is the honest cost of the choice, and it is why the budget exists |
| Size | Server only |

### `pg`

| | |
| --- | --- |
| Why | The PostgreSQL wire protocol, for deployments larger than one machine |
| Necessity | Only for `DB_DIALECT=postgres`. It is behind a dynamic `import()`, so a SQLite deployment never loads it — but `npm ci` still installs it, so it counts against the budget |
| Popularity / maintenance | The de-facto Node driver, long-maintained |
| Vulnerabilities | None outstanding |
| Licence | MIT |
| Transitive | ~12 |
| Size | Server only |

SQLite has no entry here because it has no package: it is `node:sqlite`, built into Node 22.

## Development dependencies

`typescript` and `@types/*` (types, no runtime), `vitest` (test runner), `esbuild` (the one
build tool, pinned to an exact version because it decides the bytes the browser runs),
`@scure/bip39` and `jsqr` — these last two are **test-only oracles**: the recovery-phrase and
QR implementations in `src/shared` are ours, and the tests check them against an independent
implementation rather than against themselves. None of these ship.

## What we refused

- **A linter framework.** ESLint plus a TypeScript plugin is roughly a hundred packages for
  style opinions; `tsc --noEmit` already does the type-aware part, and the rules that matter
  here are project-specific (no markup from strings, no `Math.random`, environment read in
  one file). They live in `scripts/lint.mjs`, ~130 lines, zero dependencies.
- **A formatter.** Whitespace hygiene is four checks in the same script.
- **A validation library.** `src/server/lib/validate.ts` is explicit about every field's type,
  length, canonical form and allowed characters. A schema library would be shorter to write
  and harder to audit, and validation is exactly the code an auditor must be able to read.
- **A QR library, a BIP-39 library, a UUID library, a date library, a cookie library, an ORM.**
  Each is under a hundred lines here, tested, and free of anyone else's release schedule.

## How to add one

1. Answer the seven questions above in a new `###` section, honestly, before installing.
2. `npm install <name>` — `.npmrc` sets `save-exact`, so the version is pinned.
3. `npm run audit` — dependency policy, licence, lockfile integrity and install scripts.
4. If the budget must rise, raise it in the same commit and say why in the message.
5. Run `npm run inventory:update` and commit the regenerated inventory with the four reviews
   named in the message. `npm run audit` fails until you do.
