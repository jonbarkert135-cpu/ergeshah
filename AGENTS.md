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
