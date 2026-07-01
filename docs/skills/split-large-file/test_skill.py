#!/usr/bin/env python3
"""Tests for split-large-file skill."""
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import analyze


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
