# Hive — a team of coding agents you can actually afford to run

Hive is a build orchestrator: a pool of coding LLM agents (Claude, GPT, Gemini, DeepSeek,
Groq, local models — anything with an API) that **plans a project, writes it in isolated git
worktrees, reviews its own diffs, runs your quality gates and commits the result**.

You give it two things: a goal in `GOAL.md` and API keys in `.env`. It gives you commits.

```
python -m hive init      # scaffold .env, GOAL.md, hive.gates.json
python -m hive demo      # watch the whole loop work offline, no keys, no network
python -m hive doctor    # validates your keys with a real call and shows role → model routing
python -m hive run       # plan → build → gate → review → merge → push → verify → repeat
python -m hive status    # tasks, spend, per-key credit budgets, events
```

Requirements: **Python 3.10+ (3.12 fine) and git. No pip install, no Docker, no daemon.**
Everything is standard library.

---

## The three problems this solves

**1. Ten agents "discussing" a project burn money and produce mush.**
Hive is hierarchical, not a round table. One architect decomposes the goal into tasks with
*disjoint file ownership*. Seven specialists build them in parallel, each seeing only its own
files. Two reviewers from *other model families* look at the diff. Nothing merges because a
model said it was good — it merges because your gates exit 0.

**2. Keys run out mid-build.**
Every call is charged to the key that made it, in tokens, dollars and "credits". At 80% of a
key's budget you get a warning; when it dies (budget spent, or the API answers *insufficient
quota*), the key is retired, the work rotates to the next key, and if a provider has nothing
left the run **pauses and tells you** — console, `NEEDS_ATTENTION.md`, Slack webhook, or any
shell command. Drop a new key into `.env` and the run continues; it re-reads the file on a
timer, no restart needed. State lives in SQLite, so Ctrl-C, a crash or a reboot costs you at
most the task in flight.

**3. Agentic coding is absurdly token-hungry.**
Four deliberate design choices, in order of impact:

| Technique | Effect |
| --- | --- |
| Byte-stable cached prefix (core rules + goal + repo map) shared by **all ten agents** | after the first call of an iteration everyone hits the provider's prompt cache — ~10% of the input price on Anthropic/OpenAI/DeepSeek |
| Quote-based `SEARCH/REPLACE` edits instead of whole-file rewrites | output tokens drop by an order of magnitude on edits to large files |
| Repo *map* (paths + signatures) instead of file dumps; full text only for owned files | context stays flat as the repo grows |
| Cost-tiered routing: `ultra` for architecture/crypto/security review, `cheap` for tests, docs, devops | nobody pays opus prices to write a README |

Plus hard limits: attempts per task, tasks per iteration, output tokens, per-key budgets and
an optional global `HIVE_MAX_SPEND_USD` that stops the run instead of surprising you.

---

## Quick start

```bash
python -m hive init                     # in the repo you want built
$EDITOR .env                            # paste one or more API keys
$EDITOR GOAL.md                         # describe the finished state you want
python -m hive doctor                   # green light?
python -m hive run --push               # build, and push every merge
```

`.env` accepts as many keys per provider as you like:

```ini
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_API_KEY_2=sk-ant-...          # rotation target
OPENAI_API_KEYS=sk-a,sk-b               # or a comma-separated list
DEEPSEEK_API_KEY=sk-...
HIVE_ENABLE_OLLAMA=1                    # local models, no key

HIVE_KEY_BUDGET=45000                   # credits per key (1 credit = $0.001 by default)
HIVE_MAX_SPEND_USD=25                   # global stop
HIVE_SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

Supported out of the box: `anthropic`, `openai`, `gemini`, `deepseek`, `openrouter`, `groq`,
`mistral`, `xai`, `together`, `moonshot`, `ollama`. Anything else OpenAI-compatible works with
`HIVE_BASE_URL_<NAME>` + `<NAME>_API_KEY`.

> **On subscription seats.** Hive talks to *paid API endpoints*. Do not point it at
> subscription-only accounts (Claude Code / Codex personal plans) or juggle accounts to dodge
> plan limits — that violates those terms and gets accounts banned. Rotating your own API keys,
> which is what Hive does, is normal and allowed.

---

## The cycle

```
read GOAL.md + build repo map
├─ architect: is the goal already met?            (skipped on a fresh project)
├─ architect: plan ≤N tasks, disjoint file ownership, explicit acceptance criteria
├─ workers (up to HIVE_MAX_PARALLEL at once), each in its own git worktree:
│    ├─ produce edits for its own files only
│    ├─ apply → protocol/ownership errors go straight back to the model
│    ├─ commit → run gates inside the worktree
│    └─ gate failure → the real command output is fed back, up to HIVE_MAX_ATTEMPTS
├─ reviewers ×2 (different model families, never the author's): blocking findings → one rework cycle
├─ orchestrator merges serially into the integration branch
│    └─ gates run again on the merged tree; failure ⇒ merge reverted, task failed
├─ push (optional)
└─ architect verifies the goal → done, or gaps feed the next iteration
```

Artifacts after every run: `.hive/REPORT.md` (outcome, spend, per-key budgets, task table),
`.hive/report.json`, `.hive/EVENTS.md`, `.hive/hive.log`, `.hive/hive.sqlite3`.

---

## Gates

`hive.gates.json` is auto-detected on first run (npm/pnpm/yarn scripts, python unittest, cargo,
go) and is yours to edit:

```json
{
  "gates": [
    {"name": "npm:typecheck", "cmd": "npm run typecheck --silent", "required": true, "timeout": 1200},
    {"name": "npm:test", "cmd": "npm run test --silent", "required": true, "timeout": 1200},
    {"name": "npm:lint", "cmd": "npm run lint --silent", "required": false}
  ]
}
```

`required: false` gates are advisory: they run and get reported, but do not block a merge. A
built-in secret scan always runs on changed files, so no agent can commit an API key, and it
cannot be disabled.

---

## Configuration reference (all optional)

| Variable | Default | Meaning |
| --- | --- | --- |
| `HIVE_PROJECT_DIR` | `.` | repository to build |
| `HIVE_GOAL_FILE` | `GOAL.md` | the final goal |
| `HIVE_GIT_BRANCH` / `HIVE_GIT_REMOTE` | `main` / `origin` | integration branch and remote |
| `HIVE_GIT_PUSH` | `0` | push after every successful merge |
| `HIVE_MAX_PARALLEL` | `3` | agents building simultaneously |
| `HIVE_MAX_ATTEMPTS` | `3` | attempts per task before it fails |
| `HIVE_MAX_ITERATIONS` | `6` | plan/build/verify cycles per `run` |
| `HIVE_MAX_TASKS_PER_ITERATION` | `8` | plan size cap |
| `HIVE_REVIEW_COUNT` | `2` | reviewers per change (`0` disables review) |
| `HIVE_BLOCKING_SEVERITIES` | `critical,high` | which findings block a merge |
| `HIVE_KEY_BUDGET` / `<PROVIDER>_KEY_BUDGET` | `45000` | credits per key |
| `HIVE_CREDIT_UNIT` | `usd_milli` | `usd_milli` \| `usd` \| `tokens` \| `ktokens` \| `requests` |
| `HIVE_MAX_SPEND_USD` | `0` (off) | global stop |
| `HIVE_MAX_OUTPUT_TOKENS` | `8000` | per-call output cap |
| `HIVE_REPOMAP_CHARS` | `18000` | repo-map budget |
| `HIVE_KEY_WAIT_SECONDS` | `20` | how often `.env` is re-read while paused |
| `HIVE_SHARED_DIRS` | `node_modules,.venv,vendor` | symlinked into worktrees so gates can run |
| `HIVE_FORBIDDEN_PATHS` | — | extra paths agents may never touch |
| `HIVE_ROLE_<ROLE>` | — | pin a role, e.g. `HIVE_ROLE_ARCHITECT=openai:gpt-5` |
| `HIVE_MODEL_<PROVIDER>_<TIER>` | — | pin a model, e.g. `HIVE_MODEL_ANTHROPIC_SMART=claude-sonnet-4-5` |

## The roster

| Role | Tier | Job |
| --- | --- | --- |
| `architect` | ultra | decompose the goal, verify it, resolve conflicting requirements |
| `backend` `frontend` `database` `crypto` | smart / ultra | implementation |
| `tests` `devops` `docs` | cheap | test suites, deployment, documentation |
| `reviewer_code` | smart | bugs, contracts, unmet acceptance criteria |
| `reviewer_security` | ultra | injection, authz, crypto misuse, privacy and metadata leaks |

Model ids drift; the defaults live in `hive/roster.py` and every one is overridable from `.env`.
`python -m hive doctor` prints exactly which model each role will use.

## Tests

```bash
python -m unittest discover -s hive/tests -t .     # 100 tests, no network, no keys
python -m hive demo                                 # full loop end to end on a fake provider
```

## Honest limitations

- Hive is a **force multiplier for a person who reviews the output**, not a replacement for one.
  Read the diffs it pushes.
- Quality is bounded by your gates. A repo with no meaningful tests will happily accumulate
  code that compiles and does nothing.
- Ten agents give you parallelism and reviewer diversity — not ten times the intelligence.
- Cost estimates use the price table in `hive/pricing.py`. Unknown models fall back to a default
  rate; `doctor` says so instead of pretending.
- Long-running builds want a machine that stays awake; there is no scheduler here on purpose.
