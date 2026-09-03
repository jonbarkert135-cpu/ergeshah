# Working on this repository

Read `skills/ponytail/SKILL.md` first and apply it to every change: the laziest solution
that actually works, standard library and native platform features before dependencies,
deletion before addition, no abstraction with one implementation. It is not optional
here, and it is the standard this codebase is reviewed against.

The one carve-out is the skill's own: never simplify away input validation at trust
boundaries, error handling that prevents data loss, or a security or privacy measure.
This project's whole point is those measures, so when brevity and the threat model
disagree, the threat model wins — and the extra code gets a comment saying why.

Then read `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md`. New security claims belong
in the threat model with their residual risk, or nowhere. `docs/DECISIONS.md` records why
things are the way they are (indexed by area in `docs/adr/`); add an ADR when you change one
of them.

Before you commit, answer the two questions in `docs/CHANGE_REVIEW.md` — *did this change
reduce security?* and *did this change create a performance regression?* — and, when two
requirements conflict, resolve them with the priority order on that page: cryptographic
correctness, security, privacy, data integrity, authorization, reliability, performance,
maintainability, UX, visual effects. Security is never traded for an animation.

Requirements arrive in numbered blocks, and every block is a continuation of the same
system — `docs/CHANGE_REVIEW.md` §7 says how to start one (read `docs/FEATURES.md` and
`docs/MECHANISMS.md` before writing anything; most of a block is usually already built), §8
says what to do when an instruction conflicts with the standing brief (explain the conflict,
propose the safer version, never ship the unsafe one silently), and §9 is the list of
questions asked before the code. A feature that gains a route, a screen or a table needs its
row in `docs/FEATURES.md`; a construction taken from a specification needs its line in
`docs/SOURCES.md`. Both are enforced by `test/features.test.ts`.

## Branching: there is none

The owner wants the whole project on `main`, not spread across branches. Commit and push
straight to `main`, one commit per coherent change, with a message that says what changed
and why. No feature branches, no pull requests unless the owner asks for one.

That makes the local checks the only gate, so they are not optional. Before every push:

```
npm run check && npm test && npm run audit
```

`npm run audit` reads git-*tracked* files, so run it after `git add`, not before — an
untracked file it would reject passes locally and fails in CI.

`npm run check` is lint plus types. The lint rules are in `scripts/lint.mjs` and are
specific to this project (no markup from strings, no `Math.random`, the environment read
in `config.ts` only, no SQL built by interpolation). A rule can be waived on a line with
an `audit:allow` comment — on the line, or in the comment directly above it — and the
waiver must carry a reason.

Documentation is machine-checked: `test/docs.test.ts` fails if a route, table or
environment variable exists that `docs/API.md`, `docs/DATABASE.md` or
`docs/ENVIRONMENT.md` does not mention, and if any document makes an absolute security
claim. A new endpoint is not done until it is documented.

A new migration needs `npm run migrate:checksums`; an old one is never edited.

## CI files: what an agent may and may not touch

A GitHub App (and most automation tokens) cannot write anything under `.github/workflows/`
— the push is rejected for missing the `workflows` permission. So in this repository:

- The CI definition lives at **`deploy/github-ci.yml`**. Agents edit that file.
- The running copy is **`.github/workflows/ci.yml`**, copied there by a human owner.
- Never try to commit, rename or "fix" a file under `.github/workflows/`, and never
  silently drop a CI change because the push failed. Change `deploy/github-ci.yml`,
  and say in the PR description that the human has to re-copy it.

Because re-copying costs a human action, keep the workflow **stable**: steps call npm
scripts (`npm run check`, `npm test`, `npm run audit:*`), never inline commands. A new
check is a new script in `package.json` — and better still, folded into the composite
`check` or `audit` scripts the workflow already calls, which needs no re-copy at all.
Only a change that cannot be expressed as an npm script (runner permissions, a pinned
action, `fetch-depth`) justifies asking for a re-copy.
