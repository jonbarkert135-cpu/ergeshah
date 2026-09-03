# Network architecture

Five tiers. Each one can only be reached from the tier above it, and the interesting
property is not what each can do — it is what each *cannot*.

```
            internet
               │
        ┌──────┴──────┐   PUBLIC          80/443 only, on the host firewall
        │   firewall  │
        └──────┬──────┘
               │
        ┌──────┴──────┐   REVERSE PROXY   caddy — the only container with a published
        │    proxy    │                   port, the only one on both networks, and the
        └──────┬──────┘                   last place a client IP address exists
               │  (docker network: internal, no gateway)
        ┌──────┴──────┐   APPLICATION     node — no published port, no route to the
        │     app     │                   internet, read-only filesystem, no capabilities
        └──┬───────┬──┘
           │       │
   ┌───────┴──┐ ┌──┴────────┐
   │ DATABASE │ │  STORAGE  │            SQLite file or postgres on the internal network;
   │          │ │           │            a named volume, never a bind mount of $HOME
   └──────────┘ └───────────┘
```

The onion service, when enabled, is a second entrypoint at the REVERSE PROXY level: the
`tor` container reaches `app:8080` across the internal network and never passes through
Caddy, so the two entrypoints share no TLS terminator and no log.

## What each tier may talk to

| From | To | Why |
| --- | --- | --- |
| Internet | proxy:80, proxy:443 | The only ports the firewall opens |
| proxy | app:8080 | Reverse-proxied requests |
| proxy | Internet | ACME (certificate issue and renewal) — the only egress in the deployment |
| app | database, storage volume | Its own data |
| app | *nothing else* | `internal: true` gives the network no gateway, so there is nothing to reach |
| database | *nothing* | It answers; it does not call out |

## The database is not on the internet

There is no `ports:` mapping on the database service, and the commented-out PostgreSQL
example in `deploy/docker-compose.yml` does not contain one either — deliberately, so that
uncommenting it cannot publish 5432 by accident. `test/deployment.test.ts` asserts this
about both the live services and the commented example.

If you need a psql prompt, tunnel it and close it again:

```bash
ssh -L 5432:127.0.0.1:5432 you@server   # the port exists on your laptop, not on the internet
```

## Egress, and a claim this project used to get wrong

The application container has no route to the internet. That matters for one specific
class of bug: a server-side request forgery, a compromised dependency phoning home, or an
exfiltration attempt all end at a connection error rather than at somebody's collector.

This was written down before it was true. Until 2026-09 the `app` service was attached to
both the `edge` and `internal` networks, which gave it a default gateway — while its own
comment, `docs/DEPLOYMENT.md` and `docs/THREAT_MODEL.md` all stated it had none. The
service is now on `internal` alone, and `test/deployment.test.ts` fails if it ever appears
on `edge` again. A security property nothing checks is a sentence, not a control.

## What this does not do

Docker networks are a routing boundary, not a security boundary in the way a separate host
is. Everything here shares one kernel: a container escape, or a kernel bug reachable from
inside a container, defeats the whole picture at once. Splitting the tiers across machines
(or at least giving the database its own) is the next step up, and it is a step this
project has not taken — see `docs/ROADMAP.md`.

The tiers also say nothing about who can read what *inside* the application. That is the
authorization model (`docs/ARCHITECTURE.md`), and it is enforced per route.
