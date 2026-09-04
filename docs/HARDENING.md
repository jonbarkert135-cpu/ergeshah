# Hardening the host

`docs/DEPLOYMENT.md` gets the service running. This page is about the machine underneath
it, which is the part an attacker will actually try first.

Everything here is for a single Debian or Ubuntu VPS, the target this project is built for.
Run it once, at build time, before the first account exists.

## 1. SSH

The default configuration of a fresh VPS allows password authentication, which means your
security is a password on a machine that is scanned within minutes of getting an address.

```bash
# On your laptop, if you do not have a key yet:
ssh-keygen -t ed25519 -C "symvolon-admin"
ssh-copy-id you@server
```

Then, on the server, in `/etc/ssh/sshd_config.d/10-hardening.conf`:

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding yes          # keep: this is how you reach the database (docs/NETWORK.md)
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers deploy
```

```bash
sudo sshd -t && sudo systemctl reload ssh    # test the config BEFORE reloading
```

**Keep the current session open** until you have proved a new one works. Locking yourself
out of a VPS is a support ticket, and support tickets are people with root access to your
machine.

Moving SSH off port 22 is not on this list. It reduces log noise and nothing else; a
scanner finds the new port in seconds.

## 2. Firewall

Two rules: the ports the world needs, and nothing else. `ufw` is the least error-prone.

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp           # or your admin address only: sudo ufw allow from A.B.C.D to any port 22
sudo ufw allow 80,443/tcp
sudo ufw enable
sudo ufw status verbose
```

Docker publishes ports by writing its own iptables rules, which bypass ufw's INPUT chain —
a container with `ports: ["5432:5432"]` is reachable from the internet even with ufw
"denying" it. This is the single most common way a database ends up public. The defence
here is structural rather than a firewall rule: only the proxy publishes anything, and
`test/deployment.test.ts` fails if that changes. Verify from somewhere else, not from the
host:

```bash
nmap -Pn -p- your.domain          # expect 80 and 443, and nothing else
```

## 3. Updates

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

In `/etc/apt/apt.conf.d/50unattended-upgrades`, enable automatic reboots at a time you are
awake, and keep the security origin enabled:

```
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
```

The application's own updates are a `git pull` and a rebuild (`docs/DEPLOYMENT.md`); its
dependencies are audited on every push (`npm run audit`, `docs/AUDIT.md`). Container base
images are pinned by digest, so they update when you refresh the digest and not before —
which is the trade: reproducible builds in exchange for having to notice a base-image CVE
yourself. Check monthly:

```bash
docker buildx imagetools inspect node:22-bookworm-slim   # is the digest still the current one?
```

## 4. Minimal exposed ports and minimal software

A VPS image ships with things you did not ask for.

```bash
sudo ss -tulpn                       # what is listening, and which process owns it
sudo systemctl list-units --type=service --state=running
sudo apt purge -y rpcbind avahi-daemon        # if present and unused
```

Nothing on this machine should log client addresses except, temporarily, you. That is the
main reason not to co-host anything else here: another service's access log undoes a
property this application spends real effort on (`docs/LOGGING.md`).

## 5. TLS

Caddy obtains and renews certificates automatically; the floor is set explicitly to TLS 1.2
in `deploy/Caddyfile` and asserted by `test/deployment.test.ts`. Two things worth doing
once the domain is live:

```bash
# What you actually negotiate, from outside:
openssl s_client -connect your.domain:443 -tls1_2 </dev/null 2>/dev/null | grep Protocol
openssl s_client -connect your.domain:443 -tls1_1 </dev/null 2>&1 | grep -i "no protocols"
curl -sI http://your.domain | head -1        # expect a 308 to https
curl -sI https://your.domain | grep -i strict-transport-security
```

HSTS is sent by the application, not by the proxy (`src/server/security.ts`), and it is
deliberately not sent on an onion address. Submitting the domain to the HSTS preload list
is a decision with a long undo time — read what it costs before you do it.

## 6. Service isolation

The containers are already unprivileged, read-only and capability-free
(`deploy/docker-compose.yml`, point 64). The host side of the same idea:

```bash
sudo adduser --disabled-password --gecos "" deploy
sudo usermod -aG docker deploy        # membership in `docker` is equivalent to root: only the deploy user
```

Keep the repository and `.env` owned by `deploy`, mode `600` on `.env`, and out of every
other user's reach. Do not run the stack as root, and do not put secrets in a shell
history: use `printf '%s\n' "$SECRET" >> .env` in a script, not an interactive command.

## 7. Backups

Encrypted, verified, expiring — the commands and the retention policy are in
`docs/BACKUPS.md`. Two host-level points that belong here rather than there:

- the backup key lives **off** this machine (`/etc/symvolon/backup.key`, mode `400`, and a
  copy somewhere the server cannot reach). A compromised server that can decrypt its own
  backup history has turned a backup into a second copy of the breach;
- a backup you have never restored is a hypothesis. Once a quarter run
  `npm run backup:drill -- --out /var/backups/symvolon` (SQLite) or
  `npm run backup:pg:drill -- --out /var/backups/symvolon --admin-url-file …` (PostgreSQL),
  which restores the newest backup to a temporary copy and starts a real server on it, and
  note the date somewhere. It does not touch the live database.

## 8. Monitoring

The honest version, for a service that refuses to keep an access log:

| Question | How it is answered |
| --- | --- |
| Is it up? | `GET /healthz`, from an external checker you trust — the container health check only tells the host |
| Is it failing? | One JSON line per 500 on stderr, with a reference and no request context (`docs/LOGGING.md`) |
| Is the disk filling? | `df -h`, plus an alert; SQLite and an unpruned backup directory are the two things that grow |
| Is someone attacking? | 429s and 428s rise; `docker compose logs --since 1h proxy` shows connection volume without content |
| How is it holding up? | `GET /api/admin/health` as an administrator: uptime, CPU, memory, disk, database latency, error rate and latency percentiles — numbers only, and nobody's numbers in particular (`docs/OBSERVABILITY.md`) |

What is deliberately absent: an APM agent, an error-reporting SaaS, an uptime service that
loads a script into your page. Each of them is a third party who would learn something
about your users, which is the thing this project exists to avoid.

## 9. Intrusion detection

For a single VPS, in order of value per hour spent:

1. **File integrity on the deployment.** The image is read-only, so the interesting
   directory is the host's: `sudo apt install aide` and take a baseline after deployment.
2. **`fail2ban` on SSH.** Small, boring, effective against the constant background of
   password scanners. It is *not* useful in front of the application: the rate limiter and
   the proof-of-work gate already handle that layer, and fail2ban would need an access log
   to work from — the artefact this project refuses to create.
3. **Authentication log review.** `journalctl -u ssh --since -7d | grep -i accepted` once a
   week tells you who got in, which is short enough to actually read.
4. **The application's own audit log.** Refused privileged requests are recorded with the
   route pattern and no URL (`docs/AUDIT.md`); a burst of them is a compromised or curious
   account.

An IDS you never read is theatre. Two alerts that reach your phone beat a dashboard nobody
opens.

## What this does not protect you from

Your hosting provider, who can read the disk and the memory of the machine; a kernel
vulnerability reachable from a container; and a compromised administrator laptop, which is
the fastest route to any of this. `docs/THREAT_MODEL.md` states these as residual risks
rather than pretending a checklist closed them.
