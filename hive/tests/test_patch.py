"""The edit protocol is the agents' only write path — it gets the most tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hive import patch


class ParseTest(unittest.TestCase):
    def test_parses_file_edit_delete_and_notes(self):
        reply = """
### FILE app/main.py
```python
print("hi")
```
### EDIT app/other.py
<<<<<<< SEARCH
old line
=======
new line
>>>>>>> REPLACE
### DELETE app/dead.py
### NOTES
kept it minimal
"""
        parsed = patch.parse(reply)
        self.assertEqual([e.kind for e in parsed.edits], ["file", "edit", "delete"])
        self.assertEqual(parsed.edits[0].content, 'print("hi")\n')
        self.assertEqual(parsed.edits[1].replacements, [("old line", "new line")])
        self.assertEqual(parsed.edits[2].path, "app/dead.py")
        self.assertIn("kept it minimal", parsed.notes)
        self.assertEqual(parsed.errors, [])

    def test_keeps_nested_fences_inside_a_file_block(self):
        reply = "### FILE README.md\n```markdown\n# Title\n\n```python\nx = 1\n```\n```\n"
        parsed = patch.parse(reply)
        self.assertEqual(len(parsed.edits), 1)
        self.assertIn("```python", parsed.edits[0].content)
        self.assertTrue(parsed.edits[0].content.rstrip().endswith("```"))

    def test_reports_missing_protocol(self):
        parsed = patch.parse("Sure! I would start by refactoring the module.")
        self.assertTrue(parsed.is_empty)
        self.assertIn("edit protocol", parsed.errors[0])

    def test_rejects_unsafe_paths(self):
        parsed = patch.parse("### FILE ../../etc/passwd\n```\nx\n```\n")
        self.assertTrue(parsed.is_empty)
        self.assertIn("unsafe path", parsed.errors[0])

    def test_edit_without_search_block_is_an_error(self):
        parsed = patch.parse("### EDIT a.py\njust do it please\n")
        self.assertTrue(parsed.is_empty)
        self.assertIn("SEARCH/REPLACE", parsed.errors[0])

    def test_strips_diff_style_prefixes(self):
        parsed = patch.parse("### FILE b/src/app.py\n```\nx = 1\n```\n")
        self.assertEqual(parsed.edits[0].path, "src/app.py")


class ApplyTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hive-patch-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root, ignore_errors=True))

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_creates_and_edits_owned_files(self):
        self.write("src/app.py", "def a():\n    return 1\n")
        parsed = patch.parse(
            "### FILE src/new.py\n```\nX = 2\n```\n"
            "### EDIT src/app.py\n<<<<<<< SEARCH\n    return 1\n=======\n    return 42\n>>>>>>> REPLACE\n"
        )
        result = patch.apply(parsed, self.root, allowed=["src/app.py", "src/new.py"])
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(sorted(result.changed), ["src/app.py", "src/new.py"])
        self.assertIn("return 42", (self.root / "src/app.py").read_text())

    def test_ownership_is_enforced(self):
        parsed = patch.parse("### FILE other/file.py\n```\nx\n```\n")
        result = patch.apply(parsed, self.root, allowed=["src/app.py"])
        self.assertFalse(result.ok)
        self.assertIn("file ownership", result.errors[0])
        self.assertFalse((self.root / "other/file.py").exists())

    def test_ownership_accepts_globs_and_dirs(self):
        parsed = patch.parse("### FILE src/deep/thing.py\n```\nx = 1\n```\n")
        result = patch.apply(parsed, self.root, allowed=["src/"])
        self.assertTrue(result.ok, result.errors)

    def test_protected_paths_are_refused(self):
        parsed = patch.parse("### FILE .env\n```\nOPENAI_API_KEY=leak\n```\n")
        result = patch.apply(parsed, self.root, allowed=[".env"], forbidden=(".env", ".git/"))
        self.assertFalse(result.ok)
        self.assertIn("protected path", result.errors[0])

    def test_ambiguous_search_is_rejected(self):
        self.write("a.py", "x = 1\nx = 1\n")
        parsed = patch.parse("### EDIT a.py\n<<<<<<< SEARCH\nx = 1\n=======\nx = 2\n>>>>>>> REPLACE\n")
        result = patch.apply(parsed, self.root, allowed=["a.py"])
        self.assertFalse(result.ok)
        self.assertIn("matches 2 times", result.errors[0])
        self.assertEqual((self.root / "a.py").read_text(), "x = 1\nx = 1\n")

    def test_missing_search_is_reported_without_writing(self):
        self.write("a.py", "x = 1\n")
        parsed = patch.parse("### EDIT a.py\n<<<<<<< SEARCH\ny = 9\n=======\ny = 10\n>>>>>>> REPLACE\n")
        result = patch.apply(parsed, self.root, allowed=["a.py"])
        self.assertFalse(result.ok)
        self.assertIn("not found", result.errors[0])
        self.assertEqual((self.root / "a.py").read_text(), "x = 1\n")

    def test_tolerates_indentation_drift(self):
        self.write("a.py", "def f():\n        return 1\n")
        parsed = patch.parse("### EDIT a.py\n<<<<<<< SEARCH\n    return 1\n=======\n    return 2\n>>>>>>> REPLACE\n")
        result = patch.apply(parsed, self.root, allowed=["a.py"])
        self.assertTrue(result.ok, result.errors)
        self.assertIn("return 2", (self.root / "a.py").read_text())

    def test_delete_and_missing_delete(self):
        self.write("gone.py", "x")
        parsed = patch.parse("### DELETE gone.py\n### DELETE never.py\n")
        result = patch.apply(parsed, self.root, allowed=["gone.py", "never.py"])
        self.assertEqual(result.deleted, ["gone.py"])
        self.assertIn("does not exist", result.errors[0])

    def test_edit_of_missing_file_tells_the_agent_to_use_file(self):
        parsed = patch.parse("### EDIT new.py\n<<<<<<< SEARCH\na\n=======\nb\n>>>>>>> REPLACE\n")
        result = patch.apply(parsed, self.root, allowed=["new.py"])
        self.assertIn("use '### FILE'", result.errors[0])

    def test_no_op_edit_is_an_error(self):
        self.write("a.py", "same\n")
        parsed = patch.parse("### EDIT a.py\n<<<<<<< SEARCH\nsame\n=======\nsame\n>>>>>>> REPLACE\n")
        result = patch.apply(parsed, self.root, allowed=["a.py"])
        self.assertFalse(result.ok)
        self.assertIn("no change", result.errors[0])


if __name__ == "__main__":
    unittest.main()
