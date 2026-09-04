# Backups

A backup of this service is the most valuable artefact its operator holds. It contains no
plaintext messages — those are ciphertext the server cannot open, by construction — but it
does contain password hashes, sealed vaults, public keys, the marketplace record of who
bought what, and every timestamp the database keeps. Treat it as the database, not as a file.

The five properties point 50 asks for, and where each one lives:

| Property | How |
| --- | --- |
| Encrypted | `scripts/backup.mjs` writes AES-256-GCM only. There is no code path that writes a plaintext snapshot to the backup directory |
| Access-controlled | The key is a file the *running service cannot read*; snapshots are written `0600`; the directory belongs to the operator, not to the app user |
| Versioned | One file per run, named `symvolon-<UTC timestamp>.sqlite.enc`; nothing is overwritten |
| Tested | Every `create` decrypts, runs `PRAGMA integrity_check` and counts tables before it reports success; `restore` verifies before it writes; `npm run backup:drill` boots a real service on the restored copy; `test/backup.test.ts` does the whole round trip, including a wrong key, a flipped byte and the drill |
| Documented | This file |

## The security backup policy, in five parts (points 27, 66, 70)

One page, five named things, so that "we have backups" cannot stand in for four of them.

**1. Database backups.** `npm run backup` — AES-256-GCM, one file per run, `0600`, daily at
03:00, kept 35 days with a floor of 7 files, verified on creation and again on restore. Details
below.

**2. Storage backups.** There is no separate storage tier: blobs are rows, so the database
snapshot *is* the storage backup. Nothing else on the host holds user data — the container
filesystem is read-only, `/tmp` is a tmpfs, and no upload ever becomes a file
(`docs/NETWORK.md`, `test/uploads.test.ts`). What is deliberately **not** backed up: the client
vaults, because they are in the users' browsers and the server never has them.

**3. Secrets backup.** Backing up the wrong thing here loses everything or leaks everything, so
each secret is named with where its copy belongs:

| Secret | Where the copy lives | If it is lost |
| --- | --- | --- |
| `backup.key` | Offline, off this machine — a password manager, a printed copy, or both. **Never in the snapshot directory**, which would put the lock inside the box | Every existing snapshot is unopenable. This is the one loss with no recovery, which is why the copy is made before the first backup |
| `DATABASE_URL` / `SQLITE_PATH` | The operator's own secret store, with the rest of the deployment configuration | Recreate it; it is a location, not a value |
| `RATE_LIMIT_PEPPER` | The same store | Rate-limit buckets reset once. Harmless |
| `PAYOUT_WORKER_TOKEN` | The same store, and on the worker host | Generate a new one on both sides |
| Wallet password / wallet file | With the Monero wallet, not with this service | The view-only wallet can be recreated from its view key; a payout wallet is the operator's own custody problem (`docs/PAYMENTS.md`) |
| TLS and onion private keys | The proxy volume, and a copy in the same store | Reissue the certificate; a new onion key means a new address |

**4. Restore.** Not a claim until it has been run: `npm run backup:restore` for the file, and
`npm run backup:drill` for the question a restore alone cannot answer — *does the service come
up on it?* The drill runs in `test/backup.test.ts` on every commit and quarterly by hand
(point 67).

**5. Emergency rotation.** `docs/INCIDENT_RESPONSE.md` §Rotation is the order to do it in, and
`scripts/incident.mjs` is the freeze that buys time first (ADR-0080).

### The backup key's lifecycle (point 70)

The one key in this system with no cryptographic envelope around it, written out because every
other key here has its lifecycle documented in `docs/CRYPTO.md` §Key separation and this one did
not.

| Stage | How |
| --- | --- |
| Generation | `npm run backup:keygen`, once, offline: 32 bytes from the OS CSPRNG. Written to a file, `chmod 400`, never passed as a command-line argument (arguments are visible in `ps`) |
| Usage | Read from `BACKUP_KEY_FILE` by `scripts/backup.mjs` only. It appears nowhere in `src/` — the running service cannot read it and cannot decrypt its own backups |
| Rotation | Generate a second key, re-encrypt the snapshots worth keeping (`backup:restore` with the old key, `backup` with the new one), verify one restore, then destroy the old key. Rotate after any suspicion the file was read, and after an operator with access leaves |
| Revocation | Deleting the key revokes access to every snapshot it encrypted. There is no revocation short of that, because a symmetric key has no certificate to withdraw |
| Backup | An offline copy, made before the first snapshot. Two copies in two places beats one, and neither belongs in the snapshot directory |
| Destruction | Overwrite and delete the file, then the offline copies, once the last snapshot it encrypted is past its 35-day window. Then it is unrecoverable — as it should be |

## Commands

```bash
npm run backup:keygen > /etc/symvolon/backup.key   # once, offline; chmod 400, store a copy elsewhere
npm run backup -- --key /etc/symvolon/backup.key --out /var/backups/symvolon
npm run backup:verify -- /var/backups/symvolon/symvolon-…​.enc --key /etc/symvolon/backup.key
npm run backup:restore -- <file> /var/lib/symvolon/restored.sqlite --key /etc/symvolon/backup.key
npm run backup:prune -- --out /var/backups/symvolon --days 35 --keep 7
npm run backup:drill -- --out /var/backups/symvolon --key /etc/symvolon/backup.key
```

`drill` is `verify` plus the question `verify` cannot answer: **does the service come up on
this file?** It restores the newest backup (or the one you name) to a temporary copy, starts
a real server against it in production mode on a random port with a throwaway pepper, waits
for `/healthz`, fetches the page, and deletes the copy. It never touches the live database
and never binds the production port. A quarterly run is the exercise
`docs/HARDENING.md` asks for; `test/backup.test.ts` runs it on every commit, because a
procedure nobody has executed is a wish.

`--db` defaults to `SQLITE_PATH`, `--key` to `BACKUP_KEY_FILE`. The key is read from a file and
never from a command-line argument, because arguments are visible in `ps` and in shell history.
A snapshot is taken with `VACUUM INTO`, never with `cp`: copying a WAL database gives you a file
that no longer matches its write-ahead log.

The application does not hold the backup key and cannot decrypt its own backups. A compromised
running service therefore does not hand over the backup history.

PostgreSQL deployments use `pg_dump` and the same rules: encrypt before the dump leaves the
host, keep the key elsewhere, prune on the same schedule.

## Retention policy

A backup set that is never pruned is a permanent copy of everything every user ever asked to
have deleted. Deletion in this product is real — `DELETE FROM users` cascades through every
table, and `test/auth.test.ts` proves it — and a five-year-old backup would quietly undo that.

The policy:

| | Window | Why |
| --- | --- | --- |
| Daily backups | **35 days** | Long enough to survive a corruption discovered late, a bad migration or a compromise found a month after the fact |
| Minimum kept | **7 files** | A retention rule that can empty the directory is a data-loss rule |
| Weekly / monthly / yearly archives | **none** | An archive tier is a permanent copy of deleted accounts. If an operator has a legal obligation to keep one, it belongs in that jurisdiction's own encrypted store with its own justification — not in the default configuration of a privacy product |
| Off-site copies | same window | The rule follows the bytes: an off-site copy inherits 35 days, not "forever" |
| Restore drills | quarterly | `npm run backup:restore` into a scratch path, boot the app against it, then delete it. An untested backup is a hope |

Consequences a user can rely on: an account deleted today is gone from live data immediately
and from every backup within 35 days. Consequences an operator must accept: data lost more
than 35 days ago is not recoverable, and that is the deliberate trade.

`prune` deletes by modification time and never leaves fewer than `--keep` files. Run it on the
same schedule as `create`:

```
0 3 * * *  cd /srv/symvolon && npm run backup -- --key /etc/symvolon/backup.key --out /var/backups/symvolon && npm run backup:prune -- --out /var/backups/symvolon
```

## What a stolen backup gives an attacker

Everything `docs/THREAT_MODEL.md` lists under "server attacker", minus what is not there:
no plaintext messages, no delivery addresses, no filenames, no IP addresses, no access log.
Password hashes are Argon2id over a client-derived secret, and a sealed vault needs the
account password — but both are offline-attackable at leisure, which is why the backup is
encrypted at rest and the key lives somewhere else.
