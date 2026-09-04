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

The MONERO tier, when enabled, hangs off the internal network beside the database: a
`monero-wallet-rpc` opened with a **view key** that only `app` can reach, and a `monerod`
behind it that has the egress. The payout wallet is not in this picture at all — it lives on
another machine and reaches the marketplace the way any client does, over the public
entrypoint, with a bearer token (docs/PAYMENTS.md §Keys).

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
| app | wallet:18082 | The view-only Monero wallet, when a deployment has one: `create_address`, `get_transfers`, `get_balance` and nothing else (ADR-0070) |
| wallet | node:18081 | Its own daemon, on the internal network |
| node | Internet (Tor, ideally) | The Monero peer-to-peer network. This is the *only* container besides the proxy with egress, and it holds no key |
| app | *nothing else* | `internal: true` gives the network no gateway, so there is nothing to reach |
| database | *nothing* | It answers; it does not call out |

## Every external request (point 51)

Six call sites in this repository can leave the process, and `npm run audit:egress` fails the
build if a seventh appears or if a host is written into the source instead of read from
configuration. This is the table that check enforces: what, where to, why, what is sent, and
whether the deployment needs it.

| Call site | Destination | Why | What is sent | Needed? |
| --- | --- | --- | --- | --- |
| `src/server/lib/monero.ts` | `MONERO_WALLET_RPC_URL` — the view-only wallet, on the internal network | `create_address`, `get_transfers`, `get_balance`, and nothing else (ADR-0070) | A subaddress index, a minimum height, a JSON-RPC method name. No username, no order id, no user text | **Optional.** With no wallet configured the marketplace runs and the screen says top-ups are not open |
| `scripts/payout-worker.mjs` (×2) | This platform's payout queue, and the worker's own wallet — both from its environment, on another host | The only process holding a spend key pulls the queue; nothing can call it (ADR-0070) | A bearer token, a payout id, an address and an amount | **Optional.** Payouts queue without it and say so |
| `scripts/backup.mjs` (×2) | `127.0.0.1` — the throwaway server the restore drill just started | Proving a backup boots, not just decrypts (`docs/BACKUPS.md`) | Nothing: a `GET /healthz` and a page load | Operator tool; never runs in the service |
| `scripts/audit.mjs` | The origin an operator names on the command line | Comparing a running deployment's bytes with this source tree | Nothing but the request | Operator tool |
| The browser (`src/client/api.ts`) | This origin only | The application | What the user typed, encrypted where it matters | Mandatory, and constrained by `connect-src 'self'` plus `audit:bundle` |

Everything a product like this usually calls out to is absent rather than optional: no email or
SMS gateway, no push service, no CAPTCHA provider, no analytics, no error reporter, no CDN, no
font host, no AI API, no update check, no licence check (`docs/AUDIT.md` §The zero-cost audit).
`docs/DEPENDENCIES.md` records the same question per package, because a dependency that opens a
socket is an external request whether or not this code asked for one.

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

## WebSockets

There are none. Messaging is HTTP: the client posts an envelope and polls for the ones
addressed to its devices. That is a metadata decision before it is a transport one — an open
socket per user is a presence signal the server would hold whether it wanted it or not, and
this project already refuses to keep `last_seen` (ADR-0042, `docs/METADATA.md`). Polling over
Tor costs a round trip that a socket would not; that is the trade, and it is stated in
`docs/PERFORMANCE.md` rather than hidden.

`test/api.test.ts` fails if a socket appears: no `new WebSocket`, no `ws:`/`wss:` URL, no
`ws` or `socket.io` dependency, and `connect-src 'self'` in the Content-Security-Policy with
no socket scheme added to it.

If one is ever wanted — a live order chat is the plausible reason — it is not an upgrade of
the transport, it is a new trust boundary, and it arrives with all of this or not at all
(point 87):

| Requirement | What it means here |
| --- | --- |
| Authentication | The session cookie is verified at the handshake, not on the first frame; an unauthenticated socket is closed, never left open "until it logs in" |
| Authorisation | Every subscription is checked against the same role and ownership rules the HTTP routes use, per frame, not per connection |
| Origin validation | `Origin` compared against `Host` at the handshake — a WebSocket is not covered by `SameSite`, which is exactly how cross-site socket hijacking works |
| Rate limiting | Frames consume the same token buckets as requests (`lib/rate_limit.ts`), keyed on the account |
| Connection limits | Per account and per process, on top of `MAX_CONNECTIONS` |
| Heartbeat | Server-sent ping, and a socket that misses two is dropped |
| Timeout | An idle socket is closed; a handshake that stalls is closed sooner |
| Message size limits | A frame cap no larger than `MAX_ENVELOPE_BYTES`, enforced before the frame is buffered |
| Reconnect protection | Exponential backoff in the client and a reconnect bucket on the server, so a flapping client is not a flood |

Until all nine exist, the answer to "should we add a socket" is no, and the polling client
is the feature that keeps that answer cheap.

## Internal callers authenticate too — with one exception, named (point 59)

"It is inside the Docker network, therefore trusted" is the assumption that turns one
compromised container into all of them. Where a boundary is crossed here, there is a credential:

| Caller | Boundary | Credential |
| --- | --- | --- |
| The payout worker → this platform | Another host, over the public entrypoint | A bearer token, compared in constant time, and the route does not exist when the token is unset (`routes/payouts.ts`) |
| A browser → this platform | The internet | A session cookie, `SameSite=Strict`, plus a double-submit CSRF token and an `Origin` check |
| `app` → PostgreSQL | The internal network | Its own database credentials, from `DATABASE_URL` |
| `app` → wallet RPC | The internal network | **None.** The commented wallet service runs with `--disable-rpc-login` |

That last row is the exception, and it is an accepted risk rather than an oversight:

- **What it costs.** Anything that can open a TCP connection to `wallet:18082` can call the
  wallet. That is `app` and nothing else — the network is `internal: true`, the wallet publishes
  no port, and `test/deployment.test.ts` fails if either changes.
- **What it cannot cost.** The wallet is opened with a **view key**. It cannot spend, and the
  three methods the application uses (`create_address`, `get_transfers`, `get_balance`) are all
  it can usefully be asked for (ADR-0070). The spend key lives on the payout worker's host,
  which has no inbound surface at all.
- **Why it is not simply fixed.** `--rpc-login` means HTTP digest authentication, which the
  application would have to implement by hand against a wallet nobody here can integration-test
  without a real `monero-wallet-rpc`. Hand-written authentication code in front of a view-only
  wallet is a worse trade than the network boundary plus the view key — and the honest version
  of "we rely on the network here" is this paragraph, not silence. It is on `docs/ROADMAP.md` as
  OPS-8, to be done together with the stagenet pass (PAY-6) where it can actually be verified.

## What this does not do

Docker networks are a routing boundary, not a security boundary in the way a separate host
is. Everything here shares one kernel: a container escape, or a kernel bug reachable from
inside a container, defeats the whole picture at once. Splitting the tiers across machines
(or at least giving the database its own) is the next step up, and it is a step this
project has not taken — see `docs/ROADMAP.md`.

The tiers also say nothing about who can read what *inside* the application. That is the
authorization model (`docs/ARCHITECTURE.md`), and it is enforced per route.
