# Reviewing a change

Two questions before every commit that touches more than a typo, and one ordering to settle
the argument when the answers disagree (points 92, 93, 95). None of this is a ceremony: each
question has a mechanical answer in this repository, and the command that gives it is next to
it.

## 1. Did this change reduce security?

Ask it about the change you actually made, not the one you meant to make. It is reduced if
any of these became true:

| Reduction | Where it shows up |
| --- | --- |
| A trust boundary now trusts more | a value reaching SQL, the filesystem or the DOM without passing `lib/validate.ts` or `el()` |
| Something the server could not read, it now can | a new column, a new field in a request body, a decrypted value crossing into a handler |
| A check moved from the server to the client | authorisation, ownership, a state-machine transition, a limit |
| An error says more than it did | a driver message, a path, a table name, whether an account exists |
| A privileged action stopped being audited | `recordAudit` missing from a staff route, or a refusal that is no longer recorded |
| A limit got looser or disappeared | a bucket, a body cap, a timeout, a connection ceiling |
| A dependency arrived | anything in `package.json` that `docs/DEPENDENCIES.md` does not justify |
| A claim got stronger than the code | a document that now promises more than `docs/THREAT_MODEL.md` accepts |

Answer it with: `npm run check && npm test && npm run audit`. The suites marked **Security**
in `docs/TESTING.md` are the ones that fail on most of the rows above; `authorization.test.ts`
walks the whole route table, `security.test.ts` sweeps every unsafe route, `defaults.test.ts`
checks that the shipped configuration is still the private one. A green run is evidence, not
proof: the rows a test cannot see — a check moved to the client, a claim that outran the code
— are read by a human, which is what the table is for.

**If the answer is yes: redesign.** Not "mitigate later", not "document the risk and move on".
The one legitimate exit is an ADR that states the trade, what was gained, and what residual
risk `docs/THREAT_MODEL.md` now carries — and if the trade is worth an ADR, it is worth doing
properly.

## 2. Did this change create a performance regression?

| Regression | How it is caught |
| --- | --- |
| The first paint got heavier | `npm run audit:bundle` — the entry, stylesheet and shell budgets in `test/audit.test.ts` |
| Cryptography crept into the entry bundle | the same audit: the crypto chunk must stay several times larger than the entry |
| A query started scanning | `test/search.test.ts` reads the query plan; `test/migrations.test.ts` asserts the hot indexes exist |
| A list route lost its `LIMIT`, or grew an `OFFSET` | review, and ADR-0030: pages are cursors here |
| A screen started waiting twice | two sequential `await`s where `Promise.all` was enough |
| A handler got slower under load | `GET /api/admin/health`: `requests.latencyMsP95` against a run before the change (`docs/OBSERVABILITY.md`) |

**If the answer is yes: optimise without weakening security.** A faster path that skips a
validation, caches an authorisation decision, widens a rate limit, or logs more in order to
find out why it is slow is not an optimisation — it is question 1 answered wrong. Speed here
comes from doing less work (an index, a cursor, a smaller bundle, one round trip instead of
two), never from checking less.

## 3. When two requirements conflict

In this order, highest first. Lower items are real requirements — they are not optional, and
most changes satisfy all ten — but when two cannot both be met, the higher one wins and the
lower one is what gets redesigned:

1. **Cryptographic correctness** — a protocol that is subtly wrong is worse than one that is
   slow, absent or ugly, because nothing downstream can detect it.
2. **Security** — authentication, authorisation, isolation, the limits that keep the service
   alive.
3. **Privacy** — what the server learns and keeps. Below security only because a compromised
   service protects nobody's privacy.
4. **Data integrity** — an order, a balance or an audit entry that is wrong is worse than one
   that is briefly unavailable.
5. **Authorization** — enforced per request, in the handler, on the server. (It sits under
   integrity because a correct answer given to the wrong person is recoverable by revocation;
   a corrupted record is not.)
6. **Reliability** — the service is up, and behaves the same way twice.
7. **Performance** — including the Tor round trips and the size of the first paint, which are
   privacy features as much as comfort ones.
8. **Maintainability** — the laziest solution that actually works (`skills/ponytail/SKILL.md`),
   fewest moving parts, no abstraction with one implementation.
9. **User experience** — clear wording, no dead ends, no surprise.
10. **Visual effects** — an animation is the first thing to cut and the last thing to defend.

Two consequences of this order, stated so they are not re-argued each time: a security
measure is never removed to make an interface smoother, and a rate limit is never widened to
make a demo feel faster. If a change needs an exception to this list, it needs an ADR
(`docs/adr/`), and the exception is the decision being recorded.
