"""Gates (including the secret scan) and the repo map."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from hive import gates, repomap


class GateTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hive-gate-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_command_success_and_failure(self):
        ok, out = gates.run_command("python -c \"print('hello')\"", self.root)
        self.assertTrue(ok)
        self.assertIn("hello", out)
        ok, out = gates.run_command("python -c \"import sys; sys.exit(3)\"", self.root)
        self.assertFalse(ok)

    def test_command_timeout_is_reported_not_raised(self):
        ok, out = gates.run_command("python -c \"import time; time.sleep(5)\"", self.root, timeout=1)
        self.assertFalse(ok)
        self.assertIn("timed out", out)

    def test_secret_scan_catches_hardcoded_keys(self):
        self.write("app/config.py", 'KEY = "sk-ant-api03-' + "x" * 40 + '"\n')
        ok, detail = gates.scan_secrets(self.root, ["app/config.py"])
        self.assertFalse(ok)
        self.assertIn("Anthropic API key", detail)

    def test_secret_scan_ignores_docs_and_clean_code(self):
        self.write("README.md", "example: sk-ant-api03-" + "x" * 40 + "\n")
        self.write("app/ok.py", "TOKEN = os.environ['TOKEN']\n")
        ok, _ = gates.scan_secrets(self.root, ["README.md", "app/ok.py"])
        self.assertTrue(ok)

    def test_report_ok_ignores_advisory_failures(self):
        report = gates.GateReport(
            [
                gates.GateResult("tests", True, True),
                gates.GateResult("lint", False, False, "style"),
            ]
        )
        self.assertTrue(report.ok)
        report.results.append(gates.GateResult("build", False, True, "boom"))
        self.assertFalse(report.ok)
        self.assertIn("GATE FAILED: build", report.failure_text())

    def test_run_gates_includes_secret_scan_and_honours_only_required(self):
        report = gates.run_gates(
            self.root,
            [
                {"name": "fast", "cmd": "python -c \"print(1)\"", "required": True},
                {"name": "slow-advisory", "cmd": "python -c \"import sys; sys.exit(1)\"", "required": False},
            ],
            changed=[],
            only_required=True,
        )
        names = [r.name for r in report.results]
        self.assertEqual(names[0], "secret-scan")
        self.assertTrue(report.ok)
        self.assertTrue([r for r in report.results if r.name == "slow-advisory"][0].skipped)

    def test_detect_gates_for_node_and_python_projects(self):
        self.write("package.json", json.dumps({"scripts": {"test": "vitest run", "build": "tsc"}}))
        detected = gates.detect_gates(self.root)
        cmds = " ".join(g["cmd"] for g in detected)
        self.assertIn("npm run test", cmds)
        self.assertIn("npm run build", cmds)

    def test_load_gates_writes_a_config_file(self):
        self.write("package.json", json.dumps({"scripts": {"test": "vitest run"}}))
        loaded = gates.load_gates(self.root)
        self.assertTrue((self.root / gates.GATES_FILE).exists())
        self.assertTrue(loaded)
        # a second call reads the file back unchanged
        again = gates.load_gates(self.root)
        self.assertEqual([g["name"] for g in loaded], [g["name"] for g in again])

    def test_broken_gates_file_falls_back_to_detection(self):
        self.write(gates.GATES_FILE, "{not json")
        fallback = gates.load_gates(self.root, write_default=False)
        self.assertTrue(fallback, "a broken config must not leave the project ungated")
        self.assertEqual([g["name"] for g in fallback], ["python:compile", "python:tests"])

    def test_empty_gate_list_is_re_detected(self):
        self.write(gates.GATES_FILE, json.dumps({"gates": []}))
        self.write("package.json", json.dumps({"scripts": {"test": "vitest run"}}))
        self.assertTrue(any("npm run test" in g["cmd"] for g in gates.load_gates(self.root)))


class RepoMapTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hive-map-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_python_signatures(self):
        self.write("app/core.py", "def add(a, b):\n    return a + b\n\n\nclass Thing:\n    def run(self):\n        pass\n")
        text = repomap.build(self.root)
        self.assertIn("app/core.py", text)
        self.assertIn("def add(a, b)", text)
        self.assertIn("class Thing [run]", text)

    def test_typescript_signatures(self):
        self.write("src/api.ts", "export interface User { id: string }\nexport async function getUser(id: string) {}\n")
        text = repomap.build(self.root)
        self.assertIn("interface User", text)
        self.assertIn("function getUser", text)

    def test_skips_noise_directories(self):
        self.write("node_modules/pkg/index.js", "module.exports = 1\n")
        self.write("src/a.py", "x = 1\n")
        text = repomap.build(self.root)
        self.assertNotIn("node_modules", text)
        self.assertIn("src/a.py", text)

    def test_char_limit_truncates_but_keeps_focus_signatures(self):
        for i in range(60):
            self.write(f"pkg/mod{i}.py", f"def f{i}():\n    return {i}\n")
        text = repomap.build(self.root, char_limit=1200, focus=["pkg/mod3.py"])
        self.assertLessEqual(len(text), 1400)
        self.assertIn("pkg/mod3.py", text)

    def test_read_files_marks_missing_files(self):
        self.write("a.py", "x = 1\n")
        text = repomap.read_files(self.root, ["a.py", "missing.py"])
        self.assertIn("### CURRENT a.py", text)
        self.assertIn("does not exist yet", text)

    def test_syntax_error_does_not_break_the_map(self):
        self.write("bad.py", "def (:\n")
        text = repomap.build(self.root)
        self.assertIn("bad.py", text)


if __name__ == "__main__":
    unittest.main()
