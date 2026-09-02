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

## What is implemented

| Area | Status |
| --- | --- |
| Account identity (username + password, no email/phone required) | working |
| Password handling (client-side Argon2id split → server-side scrypt) | working |
| Opaque session tokens (hashed at rest, rotating, revocable) | working |
| Cryptographic identity (Ed25519 identity + X25519 prekeys, per device) | working |
| E2EE messaging: X3DH-style handshake + Double Ratchet (forward secrecy, PCS) | working |
| Encrypted ratchet headers + padded plaintexts (no ratchet keys, counters or exact sizes on the wire) | working |
| Store-and-forward envelopes, deleted from the server on delivery | working |
| Marketplace: seller applications, listings, orders, reviews | working |
| Moderation: reports, admin review queue, privacy-safe audit log | working |
| Single-VPS deployment: Docker Compose + reverse proxy + TLS, SQLite or PostgreSQL | working |
| Payments | **not implemented by design** — see `docs/ROADMAP.md` |
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
created this repository is not permitted to write workflow files.)

`npm test` runs the unit + API test suite (crypto vectors, ratchet properties, auth,
marketplace, moderation). `npm run check` runs TypeScript in strict mode.

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
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | VPS setup, TLS, backups, onion service, hardening |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | ADRs: tech choices, dependency + license justification |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what is deliberately not built yet, and in which order |
| [`SECURITY.md`](SECURITY.md) | how to report a vulnerability |

## Краткое описание (RU)

Платформа состоит из двух частей: приватный мессенджер со сквозным шифрованием
(X3DH-подобное установление сессии + Double Ratchet, все ключи только на клиенте) и
маркетплейс цифровых товаров и услуг (продавцы, заявки, заказы, отзывы, модерация).
Разворачивается одной командой `docker compose up` на обычном VPS, без внешних API.
Все технические решения, модель угроз и остаточные риски описаны в `docs/`.

## License

[AGPL-3.0-only](LICENSE). Rationale — including compatibility with the cryptographic
libraries we may adopt later — is recorded in `docs/DECISIONS.md` (ADR-0002).
