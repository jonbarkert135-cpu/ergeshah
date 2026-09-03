# Contributing

This repository is **closed source** (`LICENSE`). "Contributing" here means the people and
agents who hold write access — there is no public pull-request process, and unsolicited
patches cannot be accepted for licensing reasons. If you found a vulnerability, read
`SECURITY.md` instead; that channel is open to everyone.

## Getting a working copy

```
npm ci                 # exact versions from the lockfile, no install scripts (.npmrc)
cp .env.example .env    # nothing in it is secret in development
npm run dev             # builds the client, starts the server on http://127.0.0.1:8080
```

Node 22.5 or newer, because the server runs TypeScript directly (`--experimental-strip-types`)
and uses the built-in `node:sqlite`. There is no build step for the server and no `dist/`.

Read before the first change: `AGENTS.md` (how work is done here), `docs/ARCHITECTURE.md`
(what the pieces are), `docs/THREAT_MODEL.md` (who we are defending against, and who we are
not).

## The loop

```
npm run check     # lint (project rules) + TypeScript strict
npm test          # everything, ~20 s
git add -A
npm run audit     # dependencies, licences, bundle, secrets, git history, migrations, supply chain
git commit && git push origin main
```

`npm run audit` reads **git-tracked** files, so it goes after `git add`, not before.

Work goes straight to `main`. There are no feature branches in this project: the tree is
small, CI is fast, and a branch that lives for a week is a merge conflict in the security
layer. What replaces the pull-request gate is that the same checks run locally and in CI, and
that CI is red for everyone until it is fixed.

## What every change is held to

1. **The laziest solution that actually works** (`skills/ponytail/SKILL.md`) — with one
   exception that is not negotiable: never simplify away validation at a trust boundary,
   error handling, or a security or privacy property. Simplicity is for the parts that are
   not load-bearing.
2. **No new dependency without a written justification** in `docs/DEPENDENCIES.md`. The audit
   enforces it. If a library exists for a function you can write in fifty readable lines,
   write the fifty lines.
3. **A decision that is hard to reverse gets an ADR** in `docs/DECISIONS.md`: what the context
   was, what was decided, what it costs. The ADRs are the reason a later reader does not
   undo a security property by accident.
4. **Security claims are argued, never asserted.** No "unbreakable", no "fully anonymous", no
   "impossible to deanonymise". Say what the attacker can do, what they still learn, and
   which risk remains — `docs/THREAT_MODEL.md` has the vocabulary.
5. **Tests belong with the change**, and the interesting ones assert on what is *not* in the
   database (`docs/TESTING.md`).
6. **Two questions before the commit message** (`docs/CHANGE_REVIEW.md`): *did this change
   reduce security?* and *did this change create a performance regression?* Both have a
   mechanical answer in this repository, and both have a priority order to settle the
   argument when they disagree with each other.
7. **Documentation is checked by machine.** `test/docs.test.ts` fails if a route, table or
   environment variable exists that `docs/API.md`, `docs/DATABASE.md` or
   `docs/ENVIRONMENT.md` does not mention. Adding an endpoint means documenting it.

## Migrations

New file `src/server/db/migrations/NNN_name.sql`, then `npm run migrate:checksums`, then
commit both. A migration that has been released is never edited — write another one. Anything
destructive needs a `-- destructive: why` comment, and every new migration declares
`-- reversible: yes — <what undoes it>` or `-- reversible: no — <why>`. The audit checks for
both; `docs/DATABASE.md` explains what rolling back actually means here.

## Secrets

Nothing secret is ever committed, including in a commit that is later reverted:
`npm run audit:history` walks every blob in every commit. If something does slip in, the fix
is to rotate the secret first and rewrite history second — a deleted file is still in every
clone.

## Commit messages

Explain the *why*. The diff already shows the what. A commit that changes a security
property says which property, and links the ADR.
