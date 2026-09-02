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
| Tested | Every `create` decrypts, runs `PRAGMA integrity_check` and counts tables before it reports success; `restore` verifies before it writes; `test/backup.test.ts` does the whole round trip, including a wrong key and a flipped byte |
| Documented | This file |

## Commands

```bash
npm run backup:keygen > /etc/symvolon/backup.key   # once, offline; chmod 400, store a copy elsewhere
npm run backup -- --key /etc/symvolon/backup.key --out /var/backups/symvolon
npm run backup:verify -- /var/backups/symvolon/symvolon-…​.enc --key /etc/symvolon/backup.key
npm run backup:restore -- <file> /var/lib/symvolon/restored.sqlite --key /etc/symvolon/backup.key
npm run backup:prune -- --out /var/backups/symvolon --days 35 --keep 7
```

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
