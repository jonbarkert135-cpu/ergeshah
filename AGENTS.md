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
things are the way they are; add an ADR when you change one of them.

Before opening a PR: `npm run check && npm test && npm run audit:deps`.

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
check is a new script in `package.json`; the workflow calls the optional ones with
`--if-present`, so it keeps working before the script exists. Only a change that cannot
be expressed as an npm script justifies asking for a re-copy.
