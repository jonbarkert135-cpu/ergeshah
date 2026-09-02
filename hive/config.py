"""Configuration: one ``.env`` file, no config framework.

Everything the operator needs to touch lives in ``.env``. Everything else has a sane
default. ``Config.load()`` merges (lowest → highest priority):

1. built-in defaults
2. ``.env`` in the current directory (or ``HIVE_ENV_FILE``)
3. real process environment
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ENV_FILE = ".env"

# Providers Hive knows how to talk to out of the box. `kind` selects the wire protocol.
PROVIDERS: dict[str, dict[str, str]] = {
    "anthropic": {"kind": "anthropic", "base_url": "https://api.anthropic.com"},
    "openai": {"kind": "openai", "base_url": "https://api.openai.com/v1"},
    "gemini": {"kind": "gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta"},
    "deepseek": {"kind": "openai", "base_url": "https://api.deepseek.com/v1"},
    "openrouter": {"kind": "openai", "base_url": "https://openrouter.ai/api/v1"},
    "groq": {"kind": "openai", "base_url": "https://api.groq.com/openai/v1"},
    "mistral": {"kind": "openai", "base_url": "https://api.mistral.ai/v1"},
    "xai": {"kind": "openai", "base_url": "https://api.x.ai/v1"},
    "together": {"kind": "openai", "base_url": "https://api.together.xyz/v1"},
    "moonshot": {"kind": "openai", "base_url": "https://api.moonshot.ai/v1"},
    "ollama": {"kind": "openai", "base_url": "http://localhost:11434/v1", "keyless": "1"},
    "mock": {"kind": "mock", "base_url": "mock://local", "keyless": "1"},
}


def parse_env_file(path: Path) -> dict[str, str]:
    """Minimal ``.env`` parser: KEY=VALUE, ``#`` comments, optional quotes, ``export`` prefix."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            # strip trailing inline comment for unquoted values
            hashpos = value.find(" #")
            if hashpos != -1:
                value = value[:hashpos].rstrip()
        if key:
            out[key] = value
    return out


def env_layers(env_file: Path | None = None) -> dict[str, str]:
    path = env_file or Path(os.environ.get("HIVE_ENV_FILE", DEFAULT_ENV_FILE))
    layered = dict(parse_env_file(Path(path)))
    layered.update({k: v for k, v in os.environ.items() if v != ""})
    return layered


@dataclass
class Config:
    # --- where the work happens -------------------------------------------------
    project_dir: Path = Path(".")
    goal_file: Path = Path("GOAL.md")
    state_dir: Path = Path(".hive")
    env_file: Path = Path(DEFAULT_ENV_FILE)

    # --- git --------------------------------------------------------------------
    git_enabled: bool = True
    git_push: bool = False
    git_remote: str = "origin"
    git_branch: str = "main"
    commit_prefix: str = "hive"

    # --- loop limits ------------------------------------------------------------
    max_parallel: int = 3
    max_attempts: int = 3
    max_iterations: int = 6
    max_tasks_per_iteration: int = 8
    review_count: int = 2
    blocking_severities: tuple[str, ...] = ("critical", "high")

    # --- budgets ----------------------------------------------------------------
    credit_unit: str = "usd_milli"  # usd_milli | tokens | requests
    default_key_budget: float = 45000.0
    max_spend_usd: float = 0.0  # 0 = unlimited
    task_token_cap: int = 120_000
    max_output_tokens: int = 8000
    repomap_char_limit: int = 18_000

    # --- behaviour --------------------------------------------------------------
    dry_run: bool = False
    verbose: bool = False
    key_wait_seconds: int = 20
    key_wait_timeout: int = 0  # 0 = wait forever for a fresh key
    http_timeout: int = 300
    slack_webhook: str = ""
    notify_cmd: str = ""
    forbidden_paths: tuple[str, ...] = (".git/", ".hive/", "hive/", ".env", ".worktrees/", "hive.gates.json")
    shared_dirs: tuple[str, ...] = ("node_modules", ".venv", "vendor")
    role_overrides: dict[str, str] = field(default_factory=dict)
    provider_overrides: dict[str, str] = field(default_factory=dict)
    raw_env: dict[str, str] = field(default_factory=dict)

    # ---------------------------------------------------------------------------
    @classmethod
    def load(cls, env_file: Path | None = None, **overrides: object) -> "Config":
        env = env_layers(env_file)
        cfg = cls()
        cfg.raw_env = env
        cfg.env_file = Path(env_file or env.get("HIVE_ENV_FILE", DEFAULT_ENV_FILE))

        def s(name: str, default: str) -> str:
            return str(env.get(name, default)).strip()

        def i(name: str, default: int) -> int:
            try:
                return int(float(s(name, str(default))))
            except ValueError:
                return default

        def f(name: str, default: float) -> float:
            try:
                return float(s(name, str(default)))
            except ValueError:
                return default

        def b(name: str, default: bool) -> bool:
            return s(name, "1" if default else "0").lower() in {"1", "true", "yes", "on"}

        cfg.project_dir = Path(s("HIVE_PROJECT_DIR", ".")).expanduser().resolve()
        cfg.goal_file = Path(s("HIVE_GOAL_FILE", "GOAL.md")).expanduser()
        if not cfg.goal_file.is_absolute():
            cfg.goal_file = cfg.project_dir / cfg.goal_file
        cfg.state_dir = Path(s("HIVE_STATE_DIR", str(cfg.project_dir / ".hive"))).expanduser()

        cfg.git_enabled = b("HIVE_GIT_ENABLED", True)
        cfg.git_push = b("HIVE_GIT_PUSH", False)
        cfg.git_remote = s("HIVE_GIT_REMOTE", "origin")
        cfg.git_branch = s("HIVE_GIT_BRANCH", "main")
        cfg.commit_prefix = s("HIVE_COMMIT_PREFIX", "hive")

        cfg.max_parallel = max(1, i("HIVE_MAX_PARALLEL", 3))
        cfg.max_attempts = max(1, i("HIVE_MAX_ATTEMPTS", 3))
        cfg.max_iterations = max(1, i("HIVE_MAX_ITERATIONS", 6))
        cfg.max_tasks_per_iteration = max(1, i("HIVE_MAX_TASKS_PER_ITERATION", 8))
        cfg.review_count = max(0, i("HIVE_REVIEW_COUNT", 2))
        sev = s("HIVE_BLOCKING_SEVERITIES", "critical,high")
        cfg.blocking_severities = tuple(x.strip().lower() for x in sev.split(",") if x.strip())

        cfg.credit_unit = s("HIVE_CREDIT_UNIT", "usd_milli").lower()
        cfg.default_key_budget = f("HIVE_KEY_BUDGET", 45000.0)
        cfg.max_spend_usd = f("HIVE_MAX_SPEND_USD", 0.0)
        cfg.task_token_cap = i("HIVE_TASK_TOKEN_CAP", 120_000)
        cfg.max_output_tokens = i("HIVE_MAX_OUTPUT_TOKENS", 8000)
        cfg.repomap_char_limit = i("HIVE_REPOMAP_CHARS", 18_000)

        cfg.dry_run = b("HIVE_DRY_RUN", False)
        cfg.verbose = b("HIVE_VERBOSE", False)
        cfg.key_wait_seconds = max(2, i("HIVE_KEY_WAIT_SECONDS", 20))
        cfg.key_wait_timeout = i("HIVE_KEY_WAIT_TIMEOUT", 0)
        cfg.http_timeout = i("HIVE_HTTP_TIMEOUT", 300)
        cfg.slack_webhook = s("HIVE_SLACK_WEBHOOK", "")
        cfg.notify_cmd = s("HIVE_NOTIFY_CMD", "")
        cfg.shared_dirs = tuple(
            x.strip() for x in s("HIVE_SHARED_DIRS", "node_modules,.venv,vendor").split(",") if x.strip()
        )
        extra_forbidden = [p.strip() for p in s("HIVE_FORBIDDEN_PATHS", "").split(",") if p.strip()]
        cfg.forbidden_paths = tuple(list(cfg.forbidden_paths) + extra_forbidden)

        cfg.role_overrides = {
            k[len("HIVE_ROLE_") :].lower(): v.strip()
            for k, v in env.items()
            if k.startswith("HIVE_ROLE_") and v.strip()
        }
        cfg.provider_overrides = {
            k[len("HIVE_BASE_URL_") :].lower(): v.strip()
            for k, v in env.items()
            if k.startswith("HIVE_BASE_URL_") and v.strip()
        }

        for key, value in overrides.items():
            if value is not None and hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg

    # ---------------------------------------------------------------------------
    def base_url(self, provider: str) -> str:
        if provider in self.provider_overrides:
            return self.provider_overrides[provider]
        return PROVIDERS.get(provider, {}).get("base_url", "")

    def provider_kind(self, provider: str) -> str:
        return PROVIDERS.get(provider, {}).get("kind", "openai")

    @property
    def db_path(self) -> Path:
        return self.state_dir / "hive.sqlite3"

    @property
    def patches_dir(self) -> Path:
        return self.state_dir / "patches"

    def ensure_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.patches_dir.mkdir(parents=True, exist_ok=True)
