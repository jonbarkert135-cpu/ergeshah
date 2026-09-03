<img src="brand/symvolon-mark.svg" alt="" width="72" height="72">

# Symvolon

A privacy-first web platform that combines an **end-to-end encrypted messenger** with a
**marketplace for digital goods and online services**.

*σύμβολον* — in the ancient world, a token deliberately broken in two. Each party kept a
half; fitting the halves back together was the proof that the two belonged to the same
agreement. That is what the handshake in this codebase does, and it is what a marketplace
needs before strangers trade. The mark is that token, cut once, its halves out of true.

Design philosophy, in priority order:

1. **Collect nothing that is not strictly required.**
2. **Trust as little as possible.**
3. **Security is enforced by architecture, not by promises.**
4. **Privacy is a property of the system, not a checkbox in the UI.**

> **Honest scope statement.** This project does *not* claim to be anonymous,
> unbreakable, or free of metadata. It claims a specific, written-down threat model with
> documented trust boundaries, residual risks and known limitations. Read
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before you trust it with anything.
>
> **The source is closed.** Symvolon is proprietary (see [`LICENSE`](LICENSE)), so the
> architecture below is something you are *told*, not something an outsider can check. The
> design still assumes the server is hostile — keys stay in the browser, the database holds
> ciphertext, and there is no code path from an operator to a plaintext message — but with
> the source closed, an outsider cannot verify that the deployed client is the client
> described here. That limitation is real, it is listed as residual risk #1 in
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and no wording in this repository is
> allowed to paper over it.

## What is implemented

| Area | Status |
| --- | --- |
| Account identity (username + password, no email/phone required) | working |
| Password change (re-seals the vault) and self-service account deletion | working |
| Device linking: a second browser gets its own identity, authorised by a signed-in device | working |
| Recovery phrase (BIP-39, 12/24 words, generated in the browser) restoring account *and* history | working |
| PGP as a second factor: challenge, detached signature, verification — private key never leaves the user | working |
| Password handling (client-side Argon2id split → server-side scrypt) | working |
| Opaque session tokens (hashed at rest, rotating, revocable) | working |
| Cryptographic identity (Ed25519 identity + X25519 prekeys, per device) | working |
| E2EE messaging: X3DH-style handshake + Double Ratchet (forward secrecy, PCS) | working |
| Safety-number verification: scannable code, per-device verified state, warning on a new key | working |
| Encrypted ratchet headers + padded plaintexts (no ratchet keys, counters or exact sizes on the wire) | working |
| Store-and-forward envelopes, deleted from the server on delivery | working |
| Marketplace: seller applications, listings, orders, reviews | working |
| Escrow-only guarantee: seller level and catalogue rank earned on settled on-platform orders; listings may not advertise a way around it | working |
| Digital delivery: file encrypted in the browser, blind blob on the server, key over the encrypted channel | working |
| Physical orders: delivery address encrypted to the seller, never a column in any table | working |
| Moderation: reports, admin review queue, privacy-safe audit log | working |
| Reproducible client build: published digests, subresource integrity, one-command deployment check | working |
| Single-VPS deployment: Docker Compose + reverse proxy + TLS, SQLite or PostgreSQL | working |
| Tor onion service: one instance serves both entrypoints, headers and cookies adapt, `Onion-Location` advertised | working |
| Money: balances, escrow on an order, a 5% fee, payout queue with per-account limits, double-entry ledger | working |
| Monero tier: a subaddress per account, a view-only watcher that credits confirmed top-ups, a solvency check | working — optional; without a wallet configured the screen says top-ups are not open |
| Payouts: a queue the marketplace cannot send from, pulled by a worker on another host that holds the key | working — **never yet run against a real node**, see `docs/ROADMAP.md` PAY-6 |
| Post-quantum hybrid handshake (PQXDH-style) | **planned** — see `docs/ROADMAP.md` |

## Quick start (development)

```bash
npm install
cp .env.example .env      # dev defaults are fine; never reuse them in production
npm run migrate           # creates ./data/symvolon.sqlite
npm run dev               # http://127.0.0.1:8080
```

Continuous integration: copy `deploy/github-ci.yml` to `.github/workflows/ci.yml` to run
type checking, the test suite, the client build and a production dependency audit on
every push. (It is not committed under `.github/` because the automation account that
created this repository is not permitted to write workflow files — see `AGENTS.md`.)
Later checks are added as npm scripts, not as workflow steps, so the copy under
`.github/workflows/` should not need updating again.

`npm test` runs the unit + API test suite (crypto vectors, ratchet properties, auth,
marketplace, moderation). `npm run check` runs TypeScript in strict mode. `npm run audit`
checks dependency advisories, greps the production bundle for anything that would contact
a third party, verifies the build repeats byte-for-byte, and scans the repository for
committed key material. `npm run audit:deployment -- https://host` compares a running
deployment with a build of this source, which is now an *internal* check — with the source
closed, only someone holding this repository can run it. See
[`docs/AUDIT.md`](docs/AUDIT.md), which also lists what those checks do *not* prove.

## Production

One VPS, one container, one database, one reverse proxy — no Kubernetes, no managed
cloud services, no third-party API keys required for any core feature. See
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), including the Tor onion-service variant.

## For AI agents (and humans) working on this code

**Every change to this repository is made with `skills/ponytail/SKILL.md` applied.** It is
committed here for exactly that reason: the laziest solution that actually works, standard
library before dependencies, native platform features before libraries, deletion before
addition, no abstraction with a single implementation. If an agent (Claude, Codex, Cursor,
anything else) is asked to work on this project, that skill is part of the brief, not a
suggestion — see `AGENTS.md`.

The single exception is the one the skill itself states: input validation at trust
boundaries, error handling that prevents data loss, and security or privacy measures are
never simplified away. In this codebase they *are* the product.

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | components, trust boundaries, data flow, module layout |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | attackers, assets, mitigations, residual risk, limitations |
| [`docs/CRYPTO.md`](docs/CRYPTO.md) | key hierarchy, handshake, ratchet, wire format, test vectors |
| [`docs/PRIVACY.md`](docs/PRIVACY.md) | every field stored, why, retention, what leaks anyway |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | fresh VPS to running service in nine steps, TLS, backups, onion service |
| [`docs/HARDENING.md`](docs/HARDENING.md) | the host underneath: SSH, firewall, updates, ports, isolation, monitoring, intrusion detection |
| [`docs/NETWORK.md`](docs/NETWORK.md) | the five network tiers, and why the database is not on the internet |
| [`docs/API.md`](docs/API.md) | every endpoint, its authentication, its rate-limit bucket |
| [`docs/DATABASE.md`](docs/DATABASE.md) | every table, what it stores, what it deliberately does not, retention |
| [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) | every configuration variable and its default |
| [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) | why each dependency exists, and what was refused |
| [`docs/TESTING.md`](docs/TESTING.md) | how the suites are organised and what is not covered |
| [`docs/DESIGN.md`](docs/DESIGN.md) | the design system: tokens, components, dark and light |
| [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) | what a first visit costs, and every lever pulled to get there |
| [`docs/BACKUPS.md`](docs/BACKUPS.md) | encrypted, versioned, tested backups — and the retention policy that stops them becoming forever |
| [`docs/LOGGING.md`](docs/LOGGING.md) | what we log, why, for how long, who can read it, when it is deleted |
| [`docs/MECHANISMS.md`](docs/MECHANISMS.md) | every security mechanism: threat, property, implementation, test, failure mode |
| [`docs/EXTERNAL_REVIEW.md`](docs/EXTERNAL_REVIEW.md) | the brief for an external cryptographic review: what to read, in what order, and the five questions we cannot answer ourselves |
| [`docs/SELF_CRITIQUE.md`](docs/SELF_CRITIQUE.md) | what is wrong with this system, graded by severity, with the fix or the reason there is none |
| [`docs/CHANGE_REVIEW.md`](docs/CHANGE_REVIEW.md) | the questions every change answers, the priority order, the quality bar, the cycle |
| [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) | the two health endpoints, what is measured, what is refused, and what to look at when it breaks |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | the working loop, and what every change is held to |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | ADRs: tech choices, dependency + license justification |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what is deliberately not built yet, and in which order |
| [`SECURITY.md`](SECURITY.md) | how to report a vulnerability |
| [`THIRD_PARTY.md`](THIRD_PARTY.md) | open-source components we depend on, and their obligations |

## Краткое описание (RU)

Платформа состоит из двух частей: приватный мессенджер со сквозным шифрованием
(X3DH-подобное установление сессии + Double Ratchet, все ключи только на клиенте) и
маркетплейс цифровых товаров и услуг (продавцы, заявки, заказы, отзывы, модерация).
Разворачивается одной командой `docker compose up` на обычном VPS, без внешних API.
Все технические решения, модель угроз и остаточные риски описаны в `docs/`.

## License

Proprietary — all rights reserved. See [`LICENSE`](LICENSE); the reasoning and what it
costs are recorded in `docs/DECISIONS.md` (ADR-0022, which supersedes ADR-0002).

Third-party components keep their own licences, and one of them constrains us:
[`THIRD_PARTY.md`](THIRD_PARTY.md) lists what survives a proprietary distribution.
