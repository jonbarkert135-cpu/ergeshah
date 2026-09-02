"""``python -m hive`` — the whole tool from one entry point.

    python -m hive init                 scaffold .env, GOAL.md and hive.gates.json
    python -m hive doctor               check python/git/keys/models/gates (validates keys live)
    python -m hive demo                 full offline dry run on a fake provider — no keys needed
    python -m hive plan                 show the task graph the architect would build
    python -m hive run                  the real thing (add --push to push each merge)
    python -m hive status               tasks, spend, key budgets, recent events
    python -m hive keys add openai sk-…  append a key to .env without opening an editor
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__, repomap
from .config import DEFAULT_ENV_FILE, PROVIDERS, Config
from .engine import Engine
from .gates import GATES_FILE, load_gates
from .keys import KeyPool
from .notify import Notifier
from .orchestrator import GOAL_TEMPLATE, Orchestrator
from .planner import Planner, summarize_state, tasks_to_json
from .providers import AuthError, Block, Message, QuotaError, build_provider
from .roster import ROLES, Router
from .store import Store
from .util import human_usd, setup_logging, trim

ENV_TEMPLATE = """\
# ─────────────────────────── Hive configuration ───────────────────────────
# Keys. Add as many as you like per provider: PROVIDER_API_KEY, _2, _3 … or PROVIDER_API_KEYS=a,b,c
# When one runs out, Hive rotates to the next and tells you which slot to refill.
ANTHROPIC_API_KEY=
# ANTHROPIC_API_KEY_2=
OPENAI_API_KEY=
# GEMINI_API_KEY=
# DEEPSEEK_API_KEY=
# OPENROUTER_API_KEY=
# GROQ_API_KEY=
# XAI_API_KEY=
# MISTRAL_API_KEY=
# HIVE_ENABLE_OLLAMA=1        # use a local Ollama server (no key needed)

# Budget per key, in credits. Default credit = $0.001, so 45000 credits = $45 per key.
HIVE_KEY_BUDGET=45000
HIVE_CREDIT_UNIT=usd_milli    # usd_milli | usd | tokens | ktokens | requests
HIVE_MAX_SPEND_USD=0          # 0 = no global cap

# What to build and where
HIVE_PROJECT_DIR=.
HIVE_GOAL_FILE=GOAL.md

# git
HIVE_GIT_BRANCH=main
HIVE_GIT_PUSH=0               # 1 = push after every successful merge
HIVE_GIT_REMOTE=origin

# Loop shape
HIVE_MAX_PARALLEL=3           # how many agents build at the same time
HIVE_MAX_ATTEMPTS=3           # attempts per task before it is failed
HIVE_MAX_ITERATIONS=6         # plan→build→verify cycles per `hive run`
HIVE_REVIEW_COUNT=2           # independent reviewers per change (0 disables review)

# Optional alerting when a key dies (Slack incoming webhook or any shell command)
# HIVE_SLACK_WEBHOOK=https://hooks.slack.com/services/…
# HIVE_NOTIFY_CMD=notify-send {message}

# Model pinning (optional). Defaults are in hive/roster.py.
# HIVE_ROLE_ARCHITECT=anthropic:claude-opus-4-1
# HIVE_MODEL_OPENAI_CHEAP=gpt-5-mini
"""

DEMO_GATES = {
    "_comment": "Gates for the offline demo project.",
    "gates": [
        {"name": "python:compile", "cmd": "python -m compileall -q .", "required": True, "timeout": 120},
        {
            "name": "python:tests",
            "cmd": (
                "python -c \"import os,subprocess,sys;"
                "sys.exit(subprocess.call([sys.executable,'-m','unittest','discover','-s','tests','-t','tests'])"
                " if os.path.isdir('tests') else 0)\""
            ),
            "required": True,
            "timeout": 300,
        },
    ],
}

DEMO_GOAL = """# Final goal

A tiny, dependency-free Python calculator package:

* `calc/core.py` exposes `add`, `sub`, `mul`, `div`
* `div` refuses to divide by zero with a clear error
* unit tests in `tests/` cover all four operations and the error case
* `USAGE.md` shows a two-line example

## Acceptance criteria

- [ ] `python -m unittest discover -s tests -t tests` passes
- [ ] no third-party dependencies
"""


# ─────────────────────────────────────────────────────────────────── context
class Context:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.ensure_dirs()
        self.store = Store(cfg.db_path)
        self.notifier = Notifier(cfg, self.store)
        self.pool = KeyPool(cfg, self.store, self.notifier)
        self.engine = Engine(cfg, self.store, self.pool, self.notifier)

    def close(self) -> None:
        self.store.close()


def make_config(args: argparse.Namespace) -> Config:
    overrides: dict[str, object] = {}
    if getattr(args, "project", None):
        overrides["project_dir"] = Path(args.project).expanduser().resolve()
    if getattr(args, "parallel", None):
        overrides["max_parallel"] = args.parallel
    if getattr(args, "push", None) is not None:
        overrides["git_push"] = args.push
    if getattr(args, "verbose", False):
        overrides["verbose"] = True
    cfg = Config.load(Path(args.env) if getattr(args, "env", None) else None, **overrides)
    if getattr(args, "goal", None):
        goal = Path(args.goal).expanduser()
        cfg.goal_file = goal if goal.is_absolute() else cfg.project_dir / goal
    if overrides.get("project_dir"):
        cfg.state_dir = Path(cfg.project_dir) / ".hive"
    setup_logging(cfg.state_dir, cfg.verbose)
    return cfg


# ─────────────────────────────────────────────────────────────────── commands
def cmd_init(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    project = Path(cfg.project_dir)
    project.mkdir(parents=True, exist_ok=True)
    created: list[str] = []

    env_path = Path(cfg.env_file)
    if not env_path.is_absolute():
        env_path = project / env_path
    if not env_path.exists():
        env_path.write_text(ENV_TEMPLATE, encoding="utf-8")
        created.append(str(env_path))
    goal = Path(cfg.goal_file)
    if not goal.exists():
        goal.write_text(GOAL_TEMPLATE, encoding="utf-8")
        created.append(str(goal))
    gates_path = project / GATES_FILE
    if not gates_path.exists():
        load_gates(project)  # writes auto-detected gates
        created.append(str(gates_path))
    gitignore = project / ".gitignore"
    needed = [".hive/", ".worktrees/", "NEEDS_ATTENTION.md", ".env", "__pycache__/", "*.pyc"]
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    missing = [line for line in needed if line not in existing]
    if missing:
        with gitignore.open("a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write("\n".join(missing) + "\n")
        created.append(str(gitignore))

    print("Hive initialised.")
    for path in created:
        print(f"  created  {path}")
    print(
        "\nNext:\n"
        f"  1. put at least one API key in {env_path}\n"
        f"  2. describe what you want in {goal}\n"
        "  3. python -m hive doctor\n"
        "  4. python -m hive run\n"
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    ctx = Context(cfg)
    problems: list[str] = []
    print(f"Hive {__version__} — environment check\n")

    print(f"python           {sys.version.split()[0]}")
    if sys.version_info < (3, 10):
        problems.append("Python 3.10+ is required (3.12 recommended)")
    git_path = shutil.which("git")
    print(f"git              {git_path or 'NOT FOUND'}")
    if not git_path:
        problems.append("git is not installed — worktree isolation and commits will not work")
    print(f"project          {cfg.project_dir}")
    print(f"goal file        {cfg.goal_file} {'(missing)' if not Path(cfg.goal_file).exists() else ''}")
    if not Path(cfg.goal_file).exists():
        problems.append(f"no goal file at {cfg.goal_file} — run `python -m hive init`")
    print(f"env file         {cfg.env_file} {'(missing)' if not Path(cfg.env_file).exists() else ''}")
    print(f"state            {cfg.db_path}")
    print(f"credit unit      {cfg.credit_unit} (budget per key: {cfg.default_key_budget:g})")
    print(f"push after merge {'yes' if cfg.git_push else 'no'}")

    gates = load_gates(cfg.project_dir)
    print(f"\ngates            {len(gates)} configured in {GATES_FILE}")
    for gate in gates:
        print(f"  - {gate.get('name', gate['cmd'])}: {gate['cmd']}" + ("" if gate.get("required", True) else "  (advisory)"))
    if not gates:
        problems.append(f"no gates configured — nothing will verify the agents' work (edit {GATES_FILE})")

    keys = ctx.pool.summary()
    print(f"\nkeys             {len(keys)} discovered")
    for key in keys:
        remaining = "∞" if key["remaining"] is None else f"{key['remaining']:.0f}"
        print(f"  - {key['id']:<16} {key['status']:<9} remaining {remaining} credits")
    if not keys:
        problems.append(f"no API keys found in {cfg.env_file} (see .env.example for the accepted names)")

    router = Router(cfg, ctx.pool.live_providers())
    print("\nrole → model")
    for row in router.describe():
        print(f"  {row['role']:<18} {row['tier']:<6} {row['primary']}" + (f"   (fallback: {row['fallbacks']})" if row["fallbacks"] else ""))
    unknown = [
        row["primary"]
        for row in router.describe()
        if row["primary"] != "— none available —" and not _price_known(row["primary"])
    ]
    if unknown:
        print(
            "\nnote: no price table entry for "
            + ", ".join(sorted(set(unknown)))
            + " — cost tracking for these uses the default rate; add them to hive/pricing.py for exact numbers."
        )

    if args.ping and ctx.pool.live_keys():
        print("\nlive key check")
        for key in list(ctx.pool.live_keys()):
            model = router.model_for(key.provider, "cheap") or router.model_for(key.provider, "smart")
            provider = build_provider(key.provider, cfg)
            try:
                completion = provider.complete(
                    model=model,
                    system=[Block("Reply with the single word OK.")],
                    messages=[Message("user", "ping")],
                    api_key="" if key.secret.startswith("keyless:") else key.secret,
                    max_tokens=16,
                    temperature=0.0,
                )
                print(f"  - {key.label:<26} OK   ({model}, {completion.usage.total_tokens} tokens)")
            except Exception as exc:  # noqa: BLE001 - report anything the provider throws
                kind = type(exc).__name__
                print(f"  - {key.label:<26} FAIL ({model}, {kind}): {trim(str(exc), 180)}")
                problems.append(f"{key.label}: {kind} — {trim(str(exc), 140)}")
                # a key that is provably dead should not be handed to agents later
                if isinstance(exc, (AuthError, QuotaError)):
                    ctx.pool.retire(key, "invalid" if isinstance(exc, AuthError) else "quota", trim(str(exc), 200))
    elif args.ping:
        print("\nlive key check   skipped (no live keys)")

    print()
    if problems:
        print("PROBLEMS")
        for problem in problems:
            print(f"  ✗ {problem}")
        print("\nFix these and run `python -m hive doctor` again.")
    else:
        print("✓ ready — `python -m hive run`")
    ctx.close()
    return 1 if problems else 0


def _price_known(primary: str) -> bool:
    from . import pricing

    _, _, model = primary.partition(":")
    return pricing.is_known(model)


def cmd_plan(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    ctx = Context(cfg)
    goal_path = Path(cfg.goal_file)
    if not goal_path.exists():
        print(f"no goal file at {goal_path} — run `python -m hive init` first")
        return 1
    goal = goal_path.read_text(encoding="utf-8")
    repo_map = repomap.build(cfg.project_dir, cfg.repomap_char_limit)
    planner = Planner(cfg, ctx.engine, ctx.store)
    state = summarize_state(ctx.store, "", [])
    result = planner.plan(goal, repo_map, state, iteration=0)
    if not result.tasks:
        print("the architect produced no tasks: " + "; ".join(result.errors))
        ctx.close()
        return 1
    print(tasks_to_json(result.tasks))
    for note in result.errors:
        print(f"# repaired: {note}", file=sys.stderr)
    if args.save:
        for task in result.tasks:
            ctx.store.upsert_task(task)
        print(f"\n# saved {len(result.tasks)} task(s) — `python -m hive run` will build them", file=sys.stderr)
    print(f"\n# planning cost: {human_usd(ctx.engine.spend_usd)}", file=sys.stderr)
    ctx.close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    ctx = Context(cfg)
    if not ctx.pool.live_keys():
        print(
            f"No usable API key found in {cfg.env_file}.\n"
            "Add one (e.g. ANTHROPIC_API_KEY=…) and run `python -m hive doctor`.\n"
            "To see the whole machinery work without keys: `python -m hive demo`."
        )
        ctx.close()
        return 1
    orchestrator = Orchestrator(cfg, ctx.store, ctx.pool, ctx.notifier, ctx.engine)
    summary = orchestrator.run(max_iterations=1 if args.once else args.iterations)
    print("\n" + "=" * 60)
    print(summary.as_text())
    print("=" * 60)
    print(f"report: {cfg.state_dir / 'REPORT.md'}")
    ctx.close()
    return 0 if summary.goal_done or summary.merged else 1


def cmd_status(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    ctx = Context(cfg)
    totals = ctx.store.totals()
    tasks = ctx.store.tasks()
    print(f"project {cfg.project_dir}")
    print(f"iteration {ctx.store.get_meta('iteration', 0)}   calls {totals['calls']}   "
          f"tokens {totals['tokens']} (cached {totals['cached_tokens']})   spend {human_usd(totals['cost_usd'])}\n")

    print(f"{'KEY':<16} {'STATUS':<10} {'SPENT':>10} {'BUDGET':>10} {'USD':>9} {'CALLS':>6}")
    for key in ctx.pool.summary():
        budget = f"{key['budget']:.0f}" if key["budget"] else "∞"
        print(f"{key['id']:<16} {key['status']:<10} {key['spent']:>10.0f} {budget:>10} {key['usd']:>9.4f} {key['calls']:>6}")
    if not ctx.pool.summary():
        print("(no keys configured)")

    print(f"\n{'TASK':<34} {'STATUS':<18} {'ROLE':<10} {'USD':>8}")
    for task in tasks:
        print(f"{task['id'][:33]:<34} {task['status']:<18} {task['role']:<10} {task['cost_usd']:>8.4f}")
    if not tasks:
        print("(no tasks yet)")

    verify = ctx.store.get_meta("last_verify")
    if verify:
        print(f"\ngoal reached: {'yes' if verify.get('done') else 'no'} — {verify.get('summary', '')}")
        for gap in (verify.get("gaps") or [])[:10]:
            print(f"  gap: {gap}")

    events = ctx.store.events(limit=args.events)
    if events:
        print("\nrecent events")
        for event in reversed(events):
            print(f"  {event['stamp']}  {event['kind']:<16} {event['title']}")
    ctx.close()
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    cfg = make_config(args)
    ctx = Context(cfg)
    if args.action == "add":
        provider = (args.provider or "").strip().lower()
        if provider not in PROVIDERS:
            print(f"unknown provider '{provider}'. known: {', '.join(sorted(PROVIDERS))}")
            ctx.close()
            return 1
        env_path = Path(cfg.env_file)
        existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        slot = 1
        while f"{provider.upper()}_API_KEY{'' if slot == 1 else f'_{slot}'}=" in existing.replace(" ", ""):
            slot += 1
        name = f"{provider.upper()}_API_KEY" + ("" if slot == 1 else f"_{slot}")
        with env_path.open("a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(f"{name}={args.secret}\n")
        print(f"added {name} to {env_path}")
        added = ctx.pool.load()
        print(f"pool now sees {len(ctx.pool.live_keys())} live key(s) ({added} new)")
    elif args.action == "revive":
        target = args.provider or ""
        revived = 0
        for key in ctx.pool.keys.values():
            if target in (key.id, key.provider, "all") and key.status != "live":
                ctx.store.set_key_status(key.id, "live", "")
                key.status = "live"
                revived += 1
        print(f"revived {revived} key(s) — budgets are unchanged; use a new secret to reset a budget")
    else:
        for key in ctx.pool.summary():
            remaining = "∞" if key["remaining"] is None else f"{key['remaining']:.0f}"
            error = f"  ← {key['last_error'][:60]}" if key["last_error"] else ""
            print(f"{key['id']:<16} {key['provider']:<12} {key['status']:<10} remaining {remaining:<10}{error}")
        if not ctx.pool.summary():
            print(f"(no keys in {cfg.env_file})")
    ctx.close()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the full loop against the built-in fake provider. No keys, no network."""
    workdir = Path(args.dir).expanduser().resolve() if args.dir else Path(tempfile.mkdtemp(prefix="hive-demo-"))
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "GOAL.md").write_text(DEMO_GOAL, encoding="utf-8")
    import json as _json

    (workdir / GATES_FILE).write_text(_json.dumps(DEMO_GATES, indent=2) + "\n", encoding="utf-8")
    (workdir / ".env").write_text(
        "HIVE_ENABLE_MOCK=1\nHIVE_GIT_PUSH=0\nHIVE_MAX_PARALLEL=2\nHIVE_MAX_ITERATIONS=1\n"
        f"HIVE_PROJECT_DIR={workdir}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=workdir, check=False)

    print(f"demo project: {workdir}\n")
    cfg = Config.load(workdir / ".env")
    cfg.project_dir = workdir
    cfg.goal_file = workdir / "GOAL.md"
    cfg.state_dir = workdir / ".hive"
    cfg.verbose = args.verbose
    setup_logging(cfg.state_dir, cfg.verbose)
    ctx = Context(cfg)
    if not ctx.pool.live_keys():
        print("demo could not enable the mock provider")
        ctx.close()
        return 1
    orchestrator = Orchestrator(cfg, ctx.store, ctx.pool, ctx.notifier, ctx.engine)
    summary = orchestrator.run(max_iterations=1)
    print("\n" + "=" * 60)
    print(summary.as_text())
    print("=" * 60)
    log = subprocess.run(
        ["git", "log", "--oneline"], cwd=workdir, capture_output=True, text=True, check=False
    ).stdout.strip()
    print("\ngit log of the project the agents just built:\n" + (log or "(no commits)"))
    print("\nfiles:")
    for path in sorted(p for p in workdir.rglob("*") if p.is_file()):
        rel = path.relative_to(workdir)
        if rel.parts[0] in {".git", ".hive"}:
            continue
        print(f"  {rel}")
    print(f"\nfull report: {cfg.state_dir / 'REPORT.md'}")
    ctx.close()
    return 0 if summary.merged else 1


# ─────────────────────────────────────────────────────────────────── parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m hive", description="Hive — multi-agent build orchestrator")
    parser.add_argument("--version", action="version", version=f"hive {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--project", help="project directory (default: HIVE_PROJECT_DIR or .)")
        p.add_argument("--env", default=DEFAULT_ENV_FILE, help="path to the .env file")
        p.add_argument("--goal", help="path to the goal file")
        p.add_argument("-v", "--verbose", action="store_true")

    p_init = sub.add_parser("init", help="scaffold .env, GOAL.md, hive.gates.json")
    common(p_init)
    p_init.set_defaults(func=cmd_init)

    p_doctor = sub.add_parser("doctor", help="check environment, keys, models and gates")
    common(p_doctor)
    p_doctor.add_argument("--no-ping", dest="ping", action="store_false", help="skip the live API call per key")
    p_doctor.set_defaults(func=cmd_doctor, ping=True)

    p_plan = sub.add_parser("plan", help="print the task graph without building anything")
    common(p_plan)
    p_plan.add_argument("--save", action="store_true", help="store the tasks so `run` builds exactly these")
    p_plan.set_defaults(func=cmd_plan)

    p_run = sub.add_parser("run", help="plan → build → gate → review → merge → verify, until the goal is met")
    common(p_run)
    p_run.add_argument("--iterations", type=int, help="max plan/build/verify cycles (default HIVE_MAX_ITERATIONS)")
    p_run.add_argument("--once", action="store_true", help="a single iteration")
    p_run.add_argument("--parallel", type=int, help="agents building at the same time")
    push = p_run.add_mutually_exclusive_group()
    push.add_argument("--push", dest="push", action="store_true", help="push after every merge")
    push.add_argument("--no-push", dest="push", action="store_false")
    p_run.set_defaults(func=cmd_run, push=None)

    p_status = sub.add_parser("status", help="tasks, spend, key budgets, events")
    common(p_status)
    p_status.add_argument("--events", type=int, default=10)
    p_status.set_defaults(func=cmd_status)

    p_keys = sub.add_parser("keys", help="list / add / revive keys")
    common(p_keys)
    p_keys.add_argument("action", nargs="?", default="list", choices=["list", "add", "revive"])
    p_keys.add_argument("provider", nargs="?", help="provider name (or key id / 'all' for revive)")
    p_keys.add_argument("secret", nargs="?", help="the API key when adding")
    p_keys.set_defaults(func=cmd_keys)

    p_demo = sub.add_parser("demo", help="offline end-to-end run on a fake provider (no keys needed)")
    p_demo.add_argument("--dir", help="where to build the demo project (default: a temp dir)")
    p_demo.add_argument("-v", "--verbose", action="store_true")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", "") == "keys" and args.action == "add" and not (args.provider and args.secret):
        print("usage: python -m hive keys add <provider> <api-key>")
        return 2
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\ninterrupted — state is saved, rerun to resume")
        return 130


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    sys.exit(main())
