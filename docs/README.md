# Documentation

Point 62 asks for a section per area. Each directory below is an index: it names the
documents that carry the detail, the code the section describes, and the tests that keep
the two honest. The documents themselves stay at the top level so that every link in the
repository — and in every commit message written so far — keeps working, and so that a
fact has exactly one home.

| Section | Answers |
| --- | --- |
| [architecture/](architecture/) | What the pieces are and why there are so few of them |
| [security/](security/) | The threat model, the reviews, and what to do when it goes wrong |
| [cryptography/](cryptography/) | The protocol, its composition and its tests |
| [deployment/](deployment/) | Running it on one VPS, backups, logs, hardening |
| [database/](database/) | The schema, migrations and what each column is allowed to hold |
| [api/](api/) | Every endpoint, its limit and its authentication |
| [testing/](testing/) | What is tested, how, and what is deliberately not |
| [privacy/](privacy/) | What the server learns, refuses to learn, and forgets |

Five documents sit above the sections because they cut across all of them:
[`DECISIONS.md`](DECISIONS.md) (why things are the way they are, indexed by area in
[`adr/`](adr/)), [`CHANGE_REVIEW.md`](CHANGE_REVIEW.md) (the two questions every change
answers, and the order that settles a conflict between requirements) and
[`ROADMAP.md`](ROADMAP.md) (what is known to be missing),
[`MECHANISMS.md`](MECHANISMS.md) (every security mechanism with its threat, property, test and
failure mode) and [`SELF_CRITIQUE.md`](SELF_CRITIQUE.md) (the weaknesses this project found in
itself, graded, with what was done about each).
