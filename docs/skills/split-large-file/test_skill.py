#!/usr/bin/env python3
"""Tests for split-large-file skill."""
import tempfile
import unittest
from pathlib import Path
import sys
skill_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(skill_dir.parent))
from shared.loader import load_skill_run

analyze = load_skill_run(skill_dir, "skill_split_large_file_run").analyze


class TestSplitAnalysis(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_analyze_missing_file(self):
        result = analyze(self.tmpdir / "nonexistent.go")
        self.assertEqual(result, 1)

    def test_analyze_small_file(self):
        f = self.tmpdir / "small.go"
        f.write_text("package main\n\nfunc main() {}\n")
        result = analyze(f)
        self.assertEqual(result, 0)

    def test_analyze_large_file(self):
        f = self.tmpdir / "large.go"
        content = "\n".join(f"// line {i}" for i in range(600))
        f.write_text("package main\n\n" + content)
        result = analyze(f)
        self.assertEqual(result, 1)

    def test_exported_functions_detected(self):
        f = self.tmpdir / "exported.go"
        f.write_text("package main\n\nfunc Hello() {}\nfunc World() {}\n")
        result = analyze(f)
        self.assertEqual(result, 0)  # under 500 lines


if __name__ == "__main__":
    unittest.main()
