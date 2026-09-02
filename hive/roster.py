"""The agent roster: ten specialists, each with a tier, a persona and a provider preference.

Two rules keep quality up and cost down:

* **Cost-tiered routing.** Architecture, cryptography and security review get the strongest
  (most expensive) tier. Boilerplate, tests, docs and devops get the cheap tier. Nobody pays
  opus prices to write a README.
* **Provider diversity.** Reviewers prefer a *different* provider than the author, so a model
  family's blind spots do not get rubber-stamped by itself.

Model ids drift constantly. Every choice is overridable from ``.env`` without touching code::

    HIVE_ROLE_ARCHITECT=anthropic:claude-opus-4-1     # pin one role
    HIVE_MODEL_ANTHROPIC_SMART=claude-sonnet-4-5      # pin one tier of one provider
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config

TIERS = ("ultra", "smart", "cheap")

# Default model per provider per tier.
CATALOG: dict[str, dict[str, str]] = {
    "anthropic": {
        "ultra": "claude-opus-4-1",
        "smart": "claude-sonnet-4-5",
        "cheap": "claude-3-5-haiku-latest",
    },
    "openai": {"ultra": "gpt-5", "smart": "gpt-5", "cheap": "gpt-5-mini"},
    "gemini": {"ultra": "gemini-2.5-pro", "smart": "gemini-2.5-pro", "cheap": "gemini-2.5-flash"},
    "deepseek": {"ultra": "deepseek-reasoner", "smart": "deepseek-chat", "cheap": "deepseek-chat"},
    "openrouter": {
        "ultra": "anthropic/claude-opus-4.1",
        "smart": "anthropic/claude-sonnet-4.5",
        "cheap": "deepseek/deepseek-chat",
    },
    "groq": {
        "ultra": "llama-3.3-70b-versatile",
        "smart": "llama-3.3-70b-versatile",
        "cheap": "llama-3.1-8b-instant",
    },
    "mistral": {"ultra": "mistral-large-latest", "smart": "mistral-large-latest", "cheap": "mistral-small-latest"},
    "xai": {"ultra": "grok-4", "smart": "grok-4", "cheap": "grok-3-mini"},
    "together": {
        "ultra": "Qwen/Qwen2.5-Coder-32B-Instruct",
        "smart": "Qwen/Qwen2.5-Coder-32B-Instruct",
        "cheap": "meta-llama/Llama-3.1-8B-Instruct-Turbo",
    },
    "moonshot": {"ultra": "kimi-k2-0905-preview", "smart": "kimi-k2-0905-preview", "cheap": "moonshot-v1-8k"},
    "ollama": {"ultra": "qwen2.5-coder:14b", "smart": "qwen2.5-coder:7b", "cheap": "qwen2.5-coder:7b"},
    "mock": {"ultra": "mock-ultra", "smart": "mock-smart", "cheap": "mock-cheap"},
}


@dataclass(frozen=True)
class Role:
    name: str
    tier: str
    persona: str
    prefer: tuple[str, ...] = ()  # provider preference order
    max_output: int = 8000


ROLES: dict[str, Role] = {
    "architect": Role(
        "architect",
        "ultra",
        "Principal software architect. You decompose goals into small, independently "
        "implementable tasks with explicit file ownership, dependencies and acceptance "
        "criteria. You detect conflicting requirements and resolve them explicitly. You never "
        "write application code yourself.",
        ("anthropic", "openai", "gemini", "deepseek"),
        max_output=12000,
    ),
    "backend": Role(
        "backend",
        "smart",
        "Senior backend engineer. Correctness, error handling, input validation, no dead code.",
        ("anthropic", "openai", "deepseek", "gemini"),
    ),
    "frontend": Role(
        "frontend",
        "smart",
        "Senior frontend engineer. Accessible, dependency-light UI; no tracking scripts; no "
        "third-party CDNs.",
        ("openai", "anthropic", "gemini", "deepseek"),
    ),
    "database": Role(
        "database",
        "smart",
        "Database architect. Explicit schemas and migrations, indexes for real query patterns, "
        "minimal retention of personal data.",
        ("deepseek", "anthropic", "openai", "gemini"),
    ),
    "crypto": Role(
        "crypto",
        "ultra",
        "Cryptography engineer. You never invent primitives or protocols: you use vetted "
        "libraries and standard constructions, and you state the security properties you rely on.",
        ("anthropic", "openai", "gemini"),
    ),
    "tests": Role(
        "tests",
        "cheap",
        "Test engineer. Deterministic tests that actually fail when the behaviour breaks; cover "
        "edge cases and abuse cases, not just the happy path.",
        ("deepseek", "gemini", "openai", "anthropic"),
    ),
    "devops": Role(
        "devops",
        "cheap",
        "DevSecOps engineer. Reproducible builds, pinned versions, least privilege, no secrets "
        "in the repo.",
        ("deepseek", "gemini", "openai", "anthropic"),
    ),
    "docs": Role(
        "docs",
        "cheap",
        "Technical writer. Short, exact, honest documentation. Never claim a property the code "
        "does not have.",
        ("gemini", "deepseek", "openai", "anthropic"),
    ),
    "reviewer_code": Role(
        "reviewer_code",
        "smart",
        "Staff code reviewer. You look for bugs, missing error handling, broken contracts, "
        "unmet acceptance criteria and accidental scope creep. You are terse and specific.",
        ("openai", "anthropic", "deepseek", "gemini"),
        max_output=4000,
    ),
    "reviewer_security": Role(
        "reviewer_security",
        "ultra",
        "Application security engineer. You hunt for injection, authz gaps, IDOR, unsafe "
        "crypto usage, secret leakage, privacy regressions and metadata leaks.",
        ("anthropic", "gemini", "openai", "deepseek"),
        max_output=4000,
    ),
}

WORKER_ROLES = ("backend", "frontend", "database", "crypto", "tests", "devops", "docs")
REVIEW_ROLES = ("reviewer_code", "reviewer_security")


@dataclass
class Candidate:
    provider: str
    model: str
    role: str
    tier: str


@dataclass
class Router:
    """Resolves role → ordered list of (provider, model) candidates."""

    cfg: Config
    available: list[str] = field(default_factory=list)

    def model_for(self, provider: str, tier: str) -> str:
        override = self.cfg.raw_env.get(f"HIVE_MODEL_{provider.upper()}_{tier.upper()}")
        if override:
            return override.strip()
        table = CATALOG.get(provider)
        if not table:
            generic = self.cfg.raw_env.get(f"HIVE_MODEL_{provider.upper()}")
            return (generic or "").strip()
        return table.get(tier, table.get("smart", ""))

    def candidates(self, role_name: str, avoid_provider: str | None = None) -> list[Candidate]:
        role = ROLES.get(role_name) or ROLES["backend"]
        available = [p for p in self.available]
        if not available:
            return []

        pinned = self.cfg.role_overrides.get(role_name)
        out: list[Candidate] = []
        if pinned:
            provider, _, model = pinned.partition(":")
            provider = provider.strip()
            if provider in available:
                out.append(
                    Candidate(provider, (model or self.model_for(provider, role.tier)).strip(), role_name, role.tier)
                )

        ordered = [p for p in role.prefer if p in available]
        ordered += [p for p in available if p not in ordered]
        if avoid_provider and len(ordered) > 1:
            ordered = [p for p in ordered if p != avoid_provider] + [
                p for p in ordered if p == avoid_provider
            ]
        for provider in ordered:
            model = self.model_for(provider, role.tier)
            if not model:
                continue
            if any(c.provider == provider and c.model == model for c in out):
                continue
            out.append(Candidate(provider, model, role_name, role.tier))
        return out

    def describe(self) -> list[dict]:
        rows = []
        for name in ROLES:
            cands = self.candidates(name)
            rows.append(
                {
                    "role": name,
                    "tier": ROLES[name].tier,
                    "primary": f"{cands[0].provider}:{cands[0].model}" if cands else "— none available —",
                    "fallbacks": ", ".join(f"{c.provider}:{c.model}" for c in cands[1:3]),
                }
            )
        return rows
