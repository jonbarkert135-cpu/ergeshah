"""Quality gates: the only thing allowed to say "this code may be merged".

No vote, no vibes. A change reaches the integration branch when the project's own commands
exit 0 and the built-in safety checks pass. Gates are auto-detected on first run and written
to ``hive.gates.json`` in the project so you can edit them::

    {
      "gates": [
        {"name": "tests", "cmd": "python -m unittest discover -s tests", "required": true,
         "timeout": 900}
      ]
    }
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .util import LOG, trim

GATES_FILE = "hive.gates.json"

SECRET_PATTERNS = [
    (re.compile(r"sk-ant-api\w{2}-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI-style API key"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{30,}"), "Google API key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
]
SECRET_ALLOWLIST_SUFFIXES = {".md", ".example", ".sample", ".lock"}


@dataclass
class GateResult:
    name: str
    ok: bool
    required: bool
    output: str = ""
    skipped: bool = False
    duration: float = 0.0

    def line(self) -> str:
        state = "SKIP" if self.skipped else ("PASS" if self.ok else "FAIL")
        return f"[{state}] {self.name} ({self.duration:.1f}s)"


@dataclass
class GateReport:
    results: list[GateResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.ok or not r.required or r.skipped for r in self.results)

    def summary(self) -> str:
        return "\n".join(r.line() for r in self.results) or "(no gates configured)"

    def failure_text(self, limit: int = 6000) -> str:
        chunks = [
            f"### GATE FAILED: {r.name}\n{trim(r.output, limit // max(1, self._failed_count()))}"
            for r in self.results
            if r.required and not r.ok and not r.skipped
        ]
        return "\n\n".join(chunks)

    def _failed_count(self) -> int:
        return max(1, sum(1 for r in self.results if r.required and not r.ok and not r.skipped))


def detect_gates(project: Path) -> list[dict]:
    """Guess sensible gates for whatever stack is in the repo."""
    project = Path(project)
    gates: list[dict] = []
    pkg = project / "package.json"
    if pkg.exists():
        try:
            scripts = json.loads(pkg.read_text(encoding="utf-8")).get("scripts", {}) or {}
        except Exception:
            scripts = {}
        runner = "npm"
        if (project / "pnpm-lock.yaml").exists():
            runner = "pnpm"
        elif (project / "yarn.lock").exists():
            runner = "yarn"
        for script, required in (("typecheck", True), ("lint", False), ("build", True), ("test", True)):
            if script in scripts:
                gates.append(
                    {
                        "name": f"{runner}:{script}",
                        "cmd": f"{runner} run {script}" + (" --silent" if runner == "npm" else ""),
                        "required": required,
                        "timeout": 1200,
                    }
                )
    if (project / "pyproject.toml").exists() or list(project.glob("**/test_*.py"))[:1]:
        if (project / "tests").exists() or list(project.glob("test*/**/*.py"))[:1]:
            gates.append(
                {
                    "name": "python:tests",
                    "cmd": "python -m unittest discover -s tests -t tests",
                    "required": True,
                    "timeout": 900,
                }
            )
    if (project / "Cargo.toml").exists():
        gates.append({"name": "cargo:test", "cmd": "cargo test --quiet", "required": True, "timeout": 1800})
    if (project / "go.mod").exists():
        gates.append({"name": "go:test", "cmd": "go test ./...", "required": True, "timeout": 1200})
    if not gates:
        # Unknown or empty project: at least compile the python that appears and run any tests
        # that show up later. Both commands are no-ops until the code exists.
        gates = [
            {"name": "python:compile", "cmd": "python -m compileall -q .", "required": True, "timeout": 300},
            {
                "name": "python:tests",
                "cmd": (
                    "python -c \"import os,subprocess,sys;"
                    "sys.exit(subprocess.call([sys.executable,'-m','unittest','discover','-s','tests','-t','tests'])"
                    " if os.path.isdir('tests') else 0)\""
                ),
                "required": True,
                "timeout": 900,
            },
        ]
    return gates


def load_gates(project: Path, write_default: bool = True) -> list[dict]:
    path = Path(project) / GATES_FILE
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            raw = data.get("gates", data if isinstance(data, list) else [])
            gates = [g for g in raw if isinstance(g, dict) and g.get("cmd")]
            if gates:
                return gates
            LOG.info("%s has no gates — re-detecting for the current stack", GATES_FILE)
        except Exception as exc:
            LOG.warning("%s is not valid JSON (%s) — falling back to auto-detection", GATES_FILE, exc)
    gates = detect_gates(project)
    if write_default:
        try:
            path.write_text(
                json.dumps(
                    {
                        "_comment": "Hive quality gates. Every required gate must exit 0 before a merge.",
                        "gates": gates,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            LOG.info("wrote %s with %d auto-detected gate(s)", GATES_FILE, len(gates))
        except OSError:
            pass
    return gates


def run_command(cmd: str, cwd: Path, timeout: int = 900) -> tuple[bool, str]:
    env = dict(os.environ)
    env.setdefault("CI", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PYTHONPATH", str(cwd))
    try:
        proc = subprocess.run(  # noqa: S602 - commands come from the project's own config
            cmd,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    except OSError as exc:
        return False, f"failed to start: {exc}"
    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    return proc.returncode == 0, output.strip()


def scan_secrets(root: Path, rel_paths: list[str]) -> tuple[bool, str]:
    problems: list[str] = []
    for rel in rel_paths:
        path = Path(root) / rel
        if not path.is_file() or path.suffix.lower() in SECRET_ALLOWLIST_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern, label in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                problems.append(f"{rel}: looks like a hardcoded {label} ({match.group(0)[:12]}…)")
    return (not problems), "\n".join(problems)


def run_gates(
    project: Path,
    gates: list[dict],
    *,
    changed: list[str] | None = None,
    only_required: bool = False,
) -> GateReport:
    report = GateReport()
    ok, detail = scan_secrets(project, changed or [])
    report.results.append(
        GateResult("secret-scan", ok, True, detail or "no hardcoded secrets in changed files")
    )
    for gate in gates:
        required = bool(gate.get("required", True))
        if only_required and not required:
            report.results.append(GateResult(gate.get("name", gate["cmd"]), True, required, skipped=True))
            continue
        name = gate.get("name") or gate["cmd"]
        timeout = int(gate.get("timeout", 900))
        import time

        started = time.time()
        passed, output = run_command(gate["cmd"], Path(project), timeout)
        report.results.append(
            GateResult(name, passed, required, trim(output, 8000), duration=time.time() - started)
        )
        LOG.info("gate %s → %s", name, "pass" if passed else "FAIL")
    return report
