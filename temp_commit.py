import asyncio
from sdk.tools.github_tools import coworker_git

WT = "/work/repos/ergeshah/.worktrees/hive"
REPO = "/work/repos/ergeshah"

async def main():
    msg = """feat(hive): multi-agent build orchestrator with key rotation and token economics

Adds `hive/`, a self-contained Python 3.10+ (stdlib only, no Docker) orchestrator that
runs a pool of coding LLM agents against a goal in GOAL.md:

- 10 roles (architect, 7 builders, 2 reviewers) with cost-tiered model routing and
  per-role provider preference; reviewers never run on the author's provider
- providers: Anthropic (explicit prompt caching), OpenAI-compatible (OpenAI, DeepSeek,
  OpenRouter, Groq, Mistral, xAI, Together, Moonshot, local Ollama), Gemini, plus an
  in-process mock for offline end-to-end runs
- key pool with per-key credit accounting, 80% warning, retirement on quota/auth failure,
  rotation, and pause/resume that re-reads .env so a key swap needs no restart
- token economics: byte-stable cached prefix shared by all agents, SEARCH/REPLACE edit
  protocol with file-ownership enforcement, repo map instead of file dumps, spend caps
- isolation and safety: one git worktree per task, quality gates (auto-detected) plus a
  mandatory secret scan, gates re-run on the integrated tree with revert on failure
- SQLite state for resumable runs, REPORT.md/report.json artifacts, Slack/file/shell alerts
- CLI: init, doctor (validates keys with a real call), demo, plan, run, status, keys
- 101 unittest tests, no network required, plus an offline end-to-end loop test
"""
    for args in (["add", "-A"], ["commit", "-m", msg]):
        r = await coworker_git(args, working_dir=WT); print(args[:2], "->", r.stdout[-300:], r.stderr[-300:])
    for args in (["checkout", "main"], ["merge", "--no-ff", "-m", "Merge hive orchestrator into main", "feat/hive-orchestrator"], ["push", "origin", "main"]):
        r = await coworker_git(args, working_dir=REPO); print(args[:2], "->", r.stdout[-400:], r.stderr[-400:])

asyncio.run(main())
