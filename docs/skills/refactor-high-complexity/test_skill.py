#!/usr/bin/env python3
"""Tests for refactor-high-complexity skill."""
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import analyze


class TestComplexityAnalysis(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_analyze_missing_file(self):
        result = analyze(self.tmpdir / "nonexistent.go")
        self.assertEqual(result, 1)

    def test_analyze_small_file_passes(self):
        f = self.tmpdir / "simple.go"
        f.write_text("package main\n\nfunc Hello() string { return \"hi\" }\n")
        result = analyze(f)
        self.assertEqual(result, 0)

    def test_complexity_under_limit(self):
        """Simple file with one function should pass."""
        f = self.tmpdir / "simple.go"
        f.write_text("package main\n\nfunc Add(a, b int) int { return a + b }\n")
        result = analyze(f)
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
