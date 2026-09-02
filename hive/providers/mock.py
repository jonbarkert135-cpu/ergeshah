"""A scripted in-process provider.

Its whole purpose is that you can run the *entire* orchestration loop — planning, building,
patching, gating, reviewing, committing — with zero API keys and zero network, and see that
the machinery works before you spend a cent. Used by ``hive demo`` and by the test suite.

Behaviour is driven by the ``HIVE_ROLE:`` / ``HIVE_PHASE:`` markers Hive puts in every
prompt, so it stays in sync with the real prompt contract.
"""

from __future__ import annotations

import json
import re
import threading

from .base import Block, Completion, Message, Provider, Usage

_LOCK = threading.Lock()
_CALLS: list[dict] = []


def calls() -> list[dict]:
    with _LOCK:
        return list(_CALLS)


def reset() -> None:
    with _LOCK:
        _CALLS.clear()


class MockProvider(Provider):
    """Deterministic fake model.

    ``script``: optional list/callable to fully control replies (used by unit tests).
    Otherwise it plays a small but complete project: plan 3 tasks, write the files it was
    told to own, approve reviews, then declare the goal met.
    """

    kind = "mock"

    def __init__(self, name: str = "mock", base_url: str = "mock://local", timeout: int = 30):
        super().__init__(name, base_url, timeout)
        self.script: list[str] | None = None
        self.handler = None
        self._iteration_plans = 0

    def complete(
        self,
        *,
        model: str,
        system: list[Block],
        messages: list[Message],
        api_key: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> Completion:
        prompt = "\n\n".join(b.text for b in system) + "\n\n" + "\n\n".join(m.content for m in messages)
        with _LOCK:
            _CALLS.append({"model": model, "prompt": prompt})
        if self.handler is not None:
            text = self.handler(prompt)
        elif self.script:
            text = self.script.pop(0)
        else:
            text = self._auto_reply(prompt)
        usage = Usage(
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(text) // 4),
            cached_input_tokens=0,
            cost_usd=0.0,
        )
        return Completion(text=text, model=model, provider=self.name, usage=usage)

    # ------------------------------------------------------------------ scripted project
    def _auto_reply(self, prompt: str) -> str:
        phase = _marker(prompt, "HIVE_PHASE")
        if phase == "plan":
            return self._plan(prompt)
        if phase == "verify":
            built = "calc/core.py" in prompt and "tests/test_core.py" in prompt
            return json.dumps(
                {
                    "done": built,
                    "summary": (
                        "Calculator core, tests and usage docs are in place."
                        if built
                        else "The calculator core and its tests are still missing."
                    ),
                    "gaps": [] if built else ["calc/core.py with the four operations", "tests covering them"],
                }
            )
        if phase == "review":
            return json.dumps(
                {
                    "verdict": "approve",
                    "summary": "Implementation matches the task contract; no blocking issues.",
                    "findings": [],
                }
            )
        return self._build(prompt)

    def _plan(self, prompt: str) -> str:
        with _LOCK:
            self._iteration_plans += 1
        return json.dumps(
            {
                "tasks": [
                    {
                        "id": "core-calc",
                        "title": "Implement the calculator core",
                        "role": "backend",
                        "spec": "Create calc/core.py with add/sub/mul/div and a divide-by-zero guard.",
                        "files": ["calc/__init__.py", "calc/core.py"],
                        "depends_on": [],
                        "acceptance": ["python -m unittest discover -s tests passes"],
                    },
                    {
                        "id": "core-tests",
                        "title": "Unit tests for the calculator core",
                        "role": "tests",
                        "spec": "Create tests/test_core.py covering the four operations and the guard.",
                        "files": ["tests/test_core.py"],
                        "depends_on": ["core-calc"],
                        "acceptance": ["tests cover all four operations"],
                    },
                    {
                        "id": "docs",
                        "title": "Document usage",
                        "role": "docs",
                        "spec": "Create USAGE.md with a short example.",
                        "files": ["USAGE.md"],
                        "depends_on": [],
                        "acceptance": ["USAGE.md exists"],
                    },
                ]
            }
        )

    def _build(self, prompt: str) -> str:
        task_id = _marker(prompt, "HIVE_TASK") or "unknown"
        bodies = {
            "core-calc": (
                "### FILE calc/__init__.py\n```python\n"
                '"""Calculator package."""\n\nfrom .core import add, div, mul, sub\n\n'
                '__all__ = ["add", "sub", "mul", "div"]\n```\n'
                "### FILE calc/core.py\n```python\n"
                '"""Four operations, with an explicit divide-by-zero guard."""\n\n\n'
                "def add(a: float, b: float) -> float:\n    return a + b\n\n\n"
                "def sub(a: float, b: float) -> float:\n    return a - b\n\n\n"
                "def mul(a: float, b: float) -> float:\n    return a * b\n\n\n"
                "def div(a: float, b: float) -> float:\n"
                "    if b == 0:\n        raise ZeroDivisionError"
                '("refusing to divide by zero")\n    return a / b\n```\n'
                "### NOTES\nPure functions, no state, no dependencies.\n"
            ),
            "core-tests": (
                "### FILE tests/test_core.py\n```python\nimport unittest\n\n"
                "from calc.core import add, div, mul, sub\n\n\n"
                "class CoreTest(unittest.TestCase):\n"
                "    def test_ops(self):\n"
                "        self.assertEqual(add(2, 3), 5)\n"
                "        self.assertEqual(sub(5, 3), 2)\n"
                "        self.assertEqual(mul(2, 3), 6)\n"
                "        self.assertEqual(div(6, 3), 2)\n\n"
                "    def test_div_guard(self):\n"
                "        with self.assertRaises(ZeroDivisionError):\n"
                "            div(1, 0)\n```\n"
            ),
            "docs": (
                "### FILE USAGE.md\n```markdown\n# Usage\n\n"
                "```python\nfrom calc import add\n\nadd(2, 3)  # 5\n```\n```\n"
            ),
        }
        return bodies.get(task_id, f"### NOTES\nNothing to do for {task_id}.\n")


def _marker(prompt: str, name: str) -> str:
    match = re.search(rf"{name}:\s*([A-Za-z0-9_.\-]+)", prompt)
    return match.group(1).strip() if match else ""
