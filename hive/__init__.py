"""Hive — a multi-agent build orchestrator.

A pool of coding LLM agents (Claude, GPT/Codex, Gemini, DeepSeek, local models, ...) that
plans a project, builds it in isolated git worktrees, reviews its own diffs, runs quality
gates and commits the result.

Design constraints (deliberate):

* **Python 3.12+, standard library only.** No pip install, no Docker, no daemon.
* **Every LLM call is metered.** Tokens and cost are recorded per key, per task, per agent.
* **Keys rotate.** When a key runs out of credits the work pauses, you get a message, you
  drop a new key into ``.env``, and the run continues exactly where it stopped.
* **Nothing reaches the main branch un-gated.** Build, tests, lint, secret scan and two
  independent reviewers run before a merge.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
