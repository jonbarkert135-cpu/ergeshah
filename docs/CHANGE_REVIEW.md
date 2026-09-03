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

## 4. Choosing between two solutions

Two rules, and the second one overrides the first (point 96).

**Prefer the safer design when its complexity stays reasonable for one VPS.** Simpler is the
default everywhere else in this project (`skills/ponytail/SKILL.md`), and this is the
exception the skill itself carves out: a trust boundary, error handling that prevents data
loss, and a security or privacy property are never simplified away. "Reasonable for a VPS"
is the limit — a design that needs a cluster, a queue, an HSM or a second team is not safer
here, it is unrunnable, and an unrunnable design degrades into an unmaintained one.

**But never prefer homemade cryptography to an audited standard.** If option A is a published,
audited primitive and option B is something written here, A wins even when B looks neater,
smaller or faster. Every primitive comes from libsodium or the Node standard library
(ADR-0003, ADR-0012); what this project writes is *composition* — a handshake and a ratchet
built from published specifications, with test vectors — and even that is documented as the
part most in need of external review (roadmap CRY-1). The line is: compose standards, never
invent primitives.

## 5. The bar

Point 98. This is what the tree is allowed to look like, and the check that keeps each line
true. Not one of these is aspirational; a violation fails a command.

| Not allowed | What stops it |
| --- | --- |
| Amateur architecture | Domain boundaries read from the imports (`test/architecture.test.ts`), authorisation proved by the route table (`test/authorization.test.ts`) |
| Security theatre | Every mechanism carries a threat, a property, a test and a failure mode (`docs/MECHANISMS.md`, `test/mechanisms.test.ts`); a mechanism that cannot fill the row is deleted, not shipped |
| Hardcoded secrets | `npm run audit:secrets` over every tracked file, `npm run audit:history` over every blob in every commit, and production refuses a `development-only-` value (`test/environments.test.ts`) |
| Plaintext passwords | The password never leaves the browser (ADR-0006); the server stores a scrypt hash of an auth secret (`test/auth.test.ts`) |
| Plaintext private messages | `test/security.test.ts` dumps every table and fails if a known plaintext appears in any column |
| Unnecessary telemetry | No access log, no analytics, no third-party origin the CSP would even allow; monitoring counts numbers only (`test/observability.test.ts`, `test/logging.test.ts`) |
| Insecure defaults | `test/defaults.test.ts`: a deployment that sets nothing gets the private behaviour |
| Giant unmaintainable files | The `giant-file` lint rule: 700 lines in `src/` and `test/`, with one exemption for standard data (`scripts/lint.mjs`) |
| Undocumented cryptographic assumptions | `docs/CRYPTO.md` and `docs/THREAT_MODEL.md`, with `test/docs.test.ts` refusing an absolute claim anywhere in the documentation |
| Fake privacy claims | The same test, plus `docs/PRIVACY.md` listing every field stored and what still leaks |
| Dependency chaos | Four runtime dependencies, a budget enforced by `npm run audit:dependencies`, licences checked, install scripts refused (`.npmrc`), integrity hashes verified |

## 6. The cycle

Point 100. Every block of requirements goes through the same loop, and the loop is never
"finished" — the roadmap and `docs/SELF_CRITIQUE.md` exist because the last pass always leaves
something.

**Research** what already exists here and how it is done elsewhere, then **threat model** the
new thing: who attacks it, with what, and what they get. Only then **architecture** — where it
belongs, what it may import, what it must not learn — and a **plan** small enough to fit in one
commit. **Implement** it with the laziest solution that clears section 4 above, and **test** it
with the assertion that fails if the property disappears, not the one that proves the happy
path.

Then four reviews, in this order because each can invalidate the one before.
**security review** — section 1 of this page.
**privacy review** — what does the server now know, for how long, and who can read it.
**performance review** — section 2.
**code review** — read the diff as a stranger would, looking for the check that moved, the
case that is not handled, the name that lies.

**Document** in the same commit: the endpoint in `docs/API.md`, the table in
`docs/DATABASE.md`, the mechanism in `docs/MECHANISMS.md`, the decision in `docs/DECISIONS.md`.
Then **reassess** — what did this change make possible, and what did it make worse? — and
**improve**: the finding goes into `docs/SELF_CRITIQUE.md` or the roadmap with a severity, not
into a private list of things somebody might get to.
