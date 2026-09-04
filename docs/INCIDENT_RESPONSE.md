# Incident response

This is the document to open at 3am. It assumes one operator, one VPS, the deployment in
[`DEPLOYMENT.md`](DEPLOYMENT.md), and no on-call rota to escalate to.

Two facts shape every procedure below, and they are the reason this file is short rather
than ceremonial:

- **The server holds no key that decrypts a message or a vault.** A total compromise of the
  application, the database and the backups does not yield message plaintext
  ([`ARCHITECTURE.md`](ARCHITECTURE.md)). What it does yield is listed in each procedure.
- **There is no email, no push and no phone number.** Users cannot be notified by the
  platform. Notification means publishing on whatever channel announced the service, and
  the in-app notice an operator adds to the shell — plan for it before you need it.

The commands are `scripts/incident.mjs`, run on the host next to the database. Every
destructive one requires `--yes`, prints what it changed, and can only take access away —
it cannot read a message, open a vault or mint a session (`test/incident.test.ts`).

```bash
npm run incident status                      # blast radius first, always
npm run incident sessions:revoke-all -- --yes
npm run incident sessions:revoke alice -- --yes
npm run incident devices:revoke alice -- --yes
npm run incident suspend alice -- --reason "under investigation" --yes
npm run incident links:purge -- --yes
```

## 0. The procedure around every procedure

1. **Write down the time and what you saw.** A file, not memory. Everything after this is
   evidence handling, and the first casualty of a panic is the timeline.
2. **Decide the severity in one line.** *Confidentiality* (someone read what they should
   not), *integrity* (someone changed something), *availability* (nobody can use it).
   Confidentiality wins ties: it is the only one that cannot be undone.
3. **Preserve before you fix.** `docker compose logs --since 24h > /root/incident-<date>.log`
   and `npm run backup -- --key … --out …` *before* restarting anything. A restart is the
   most common way an incident becomes unexplainable.
4. **Stop the bleeding**, using the smallest control that works: a rate limit
   (`RATE_LIMITS`), a suspension, a session revocation, the container stopped.
5. **Fix, then verify with a test.** A finding that does not leave a regression test behind
   comes back. `docs/SECURITY_REVIEW.md` records what each pass found and where its test is.
6. **Tell people what happened**, in the terms of `THREAT_MODEL.md`: what an attacker could
   have obtained, what they could not, and what a user should do. Say "we do not know" when
   that is the truth. Never claim more protection than the model documents (point 60).

## 1. Credential rotation

Everything the server holds that could be called a secret, and what rotating it costs:

| Secret | Where | Rotate by | Impact on users |
| --- | --- | --- | --- |
| `RATE_LIMIT_PEPPER` | env or `_FILE` | new value, restart | current allowances reset; nothing else |
| `DATABASE_URL` password | env or `_FILE` (PostgreSQL only) | change in PostgreSQL, update secret, restart | none |
| Backup key | `/etc/symvolon/backup.key` | `npm run backup:keygen` into a new file, take a fresh backup with it, keep the old key until the old backups age out | none |
| TLS certificate | Caddy | `docker compose restart caddy`, or `caddy reload`; Caddy re-issues | none |
| Onion service key | `tor-data` volume | delete the volume, restart `tor`, publish the new address | **the address changes**; announce it before deleting |
| A user's password | the user's own client | the user changes it (`POST /api/auth/password`) | their other sessions end |

```bash
printf 'RATE_LIMIT_PEPPER=%s\n' "$(openssl rand -base64 48)" > /run/secrets/rate_limit_pepper
docker compose -f deploy/docker-compose.yml up -d app     # picks up the new secret
```

**There is no server-side key protecting user content to rotate**, because none exists.
Identity keys, prekeys, vault keys and message keys live on devices; the procedures for
those are §6 and §7.

## 2. Session revocation

| Situation | Command |
| --- | --- |
| One account, all its devices | `npm run incident sessions:revoke <username> -- --yes` |
| Everyone, right now (suspected token theft, stolen backup, unexplained access) | `npm run incident sessions:revoke-all -- --yes` |
| One session only | the user, in *Account → Sessions*, or `DELETE /api/auth/sessions/:id` |
| An account that must stop acting at all | `npm run incident suspend <username> -- --reason … --yes` |

Sessions are rows: deleting one takes effect on the next request, with no cache to wait
for and no token to expire. A user can do the same for themselves with **Sign out
everywhere** in the account view.

Revoking sessions does not revoke *devices* — a device that is still trusted will simply
sign in again. Revoking a device does not end its sessions either; the two controls are
independent on purpose, and an incident usually needs both:

```bash
npm run incident devices:revoke alice -- --yes
npm run incident sessions:revoke alice -- --yes
npm run incident links:purge -- --yes      # pending device-link codes, if any are open
```

Revoking sessions and devices does **not** reach a stolen stockpile of sealed-sender tokens:
those carry no owner, so nothing can select one account's (ADR-0084). If a suspended account
is still posting envelopes with them, raise the global revocation epoch — this invalidates
*every* outstanding token at once, so use it as an incident control, not a per-account one;
legitimate clients mint a fresh batch on their next send (ADR-0111):

```bash
npm run incident send-tokens:revoke -- --yes
```

## 2a. The freeze: when you are not yet sure what happened

Between "something is wrong" and "I know what to do" there is usually an hour, and during that
hour a live attacker is still spending balances and approving payouts. That hour is what the
freeze is for (ADR-0080):

```bash
npm run incident lockdown:on -- --note "unexplained admin login" --yes
```

While it is on, **every write in the deployment is refused with 503** — signed-in users,
administrators, registration, login, and the payout worker's queue, so nothing leaves the
wallet — and **every read still works**. That second half is deliberate: a marketplace that
freezes *and* hides balances is indistinguishable, from the outside, from one that has run off
with the money, and you need those same reads (the treasury, the queue, the audit log) to work
out what happened.

It touches no data and revokes no session. If you also believe a session was stolen, compose
the two:

```bash
npm run incident sessions:revoke-all -- --yes
```

Lift it when you know what you are dealing with:

```bash
npm run incident lockdown:off -- --yes
```

**What this is not.** There is no self-destruct here and there will not be: deleting the
ledger destroys the record of what this platform owes its sellers, an automatic trigger is a
denial of service handed to whoever can fire it, and there is no readable message content on
the server to save — it is encrypted end to end. Erasure at rest is full-disk encryption plus
destroying the key, which is §4 and an operating-system operation, not something the
application can do to itself.

## 3. Compromised server

Assume the attacker had root on the VPS. What that gives them, precisely:

- **Yes:** the database (see §4), the ability to serve modified client JavaScript to every
  user from now on, the ability to see who connects and when, live session cookies as they
  arrive, and the onion service key.
- **No:** past message plaintext, vaults, private keys, or the contents of encrypted
  backups whose key is not on the box.

A modified client build is the worst of these and is unmitigated by design
([`THREAT_MODEL.md`](THREAT_MODEL.md), residual risk #1): a browser cannot defend itself
against its own server. Treat every session and every message sent *after* the compromise
window began as suspect.

```bash
# 0. If you are still deciding, freeze first (§2a): writes stop, reads and evidence stay.
npm run incident lockdown:on -- --note "suspected host compromise" --yes
# 1. Cut it off. Availability is the cheapest thing to sacrifice.
docker compose -f deploy/docker-compose.yml stop app caddy tor
# 2. Preserve: image or copy the disk, and the container logs, before anything else.
# 3. Rebuild the host from scratch. Do not "clean" it; you cannot prove it is clean.
# 4. Restore the newest backup taken before the compromise window (docs/BACKUPS.md).
# 5. Rotate everything in §1, including the onion key if the host held it.
npm run incident sessions:revoke-all -- --yes
# 6. Re-verify what you serve, from your own source, before you re-open the door.
npm run audit:deployment -- https://your.domain
```

Then publish the compromise window, the fact that the served client could have been
modified during it, and the advice that follows from that: change the password (which
re-seals the vault under a new key), verify safety numbers again with every contact, and
treat anything sent during the window as read by the attacker.

## 4. Database breach

A stolen dump — from the host, a backup with its key, or a misconfigured PostgreSQL.

| In the dump | What it means |
| --- | --- |
| `users` | usernames, scrypt-over-Argon2id password hashes, roles, day-granular creation dates, PGP public keys |
| `vaults` | sealed blobs; useless without a password or recovery phrase, and cracking one costs a full Argon2id per guess |
| `devices`, `one_time_prekeys` | public key material only |
| `envelopes` | undelivered ciphertext, its recipient *device*, a client-chosen channel id, a millisecond timestamp — no sender |
| marketplace tables | listings, orders, reviews, disputes: commercial history at day granularity, and who traded with whom |
| `audit_log` | moderator actions |
| `rate_limits` | daily-rotating HMACs; not addresses |

Response: rotate as in §1, `sessions:revoke-all`, and tell users. The honest message is
that **passwords should be changed** (a hash is a hash, and a weak password is crackable),
that message content and vaults were not exposed, and that marketplace activity and account
metadata were. Recommend a new password rather than implying the old one is fine.

If the dump came from a backup, check the key: a backup whose key was on the same host is a
plaintext backup with extra steps.

## 5. Dependency vulnerability

The dependency set is four runtime packages, deliberately ([`DEPENDENCIES.md`](DEPENDENCIES.md)).

```bash
npm run audit:deps          # npm advisories, production tree, high and above
npm run audit:supply        # lockfile integrity, pinned versions, install scripts
npm ls <package>            # who actually pulls it in
```

1. **Decide whether it is reachable here.** A prototype-pollution bug in a code path this
   application never calls is not an emergency; a parser bug in `openpgp` reached from
   `POST /api/auth/pgp/complete` is. Say which route reaches it, in the incident notes.
2. **Patch the lockfile, not the range**: `npm install <pkg>@<fixed>`, run
   `npm run check && npm test && npm run audit`, deploy.
3. **If no fix exists**, disable the reachable path rather than waiting: PGP login can be
   turned off for the deployment, uploads can be capped, a route can be removed. Removing a
   feature for a week is a smaller cost than the vulnerability.
4. **If the package is compromised at the source** (a hijacked release), treat it as §3:
   the build ran its code. Rebuild the client from a clean checkout and republish digests.

## 6. Cryptographic key compromise

| Key | Held by | If it is compromised |
| --- | --- | --- |
| Device identity key (Ed25519) | the user's vault | Revoke the device (`devices:revoke`). The identity can never be re-published — revocation is final — so the user creates a new device identity, and contacts must compare safety numbers again |
| Signed prekey / one-time prekeys | the user's vault | Publishing a new device rotates them; past sessions are unaffected, since the ratchet has moved on |
| Ratchet state for one conversation | a device | Everything up to the next DH ratchet step is readable. Post-compromise security recovers the session after both sides send again; the honest advice is to assume the whole conversation was read |
| Vault key (from the password) | the user's memory | Change the password: the master key is re-wrapped and the server's copy of the old wrap becomes useless |
| Recovery phrase | the user | Set a new phrase from the account view; the old public half is replaced |
| Backup key | the operator | New key, new backup, destroy the old backups when they age out |

There is no platform-wide key to compromise: no signing key for the client bundle, no
message-encryption key, no escrow. The published build digests take that role, and if they
are wrong the answer is §3.

**Do not** invent a "key revocation broadcast": this platform has no authenticated channel
to publish one on, and pretending otherwise would be exactly the fake guarantee point 60
forbids. Users verify each other with safety numbers, and that remains the mechanism.

## 7. Reporting and receiving a vulnerability report

Inbound reports arrive as GitHub security advisories ([`../SECURITY.md`](../SECURITY.md)).
Acknowledge, reproduce, and — if it is exploitable against a live deployment — apply the
matching procedure above before you write the patch. A report is an incident when a bug is
already being used; treat the first one as if it is.
