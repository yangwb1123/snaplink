#!/usr/bin/env python3
"""Tests for root file count gate."""
import unittest
from checks.root_files import EXEMPT, run as root_files_run


class TestRootFilesExempt(unittest.TestCase):
    def test_exempt_list_non_empty(self):
        self.assertGreater(len(EXEMPT), 0)

    def test_critical_files_in_exempt(self):
        critical = {"go.mod", "go.sum", "Makefile", "Dockerfile", "AGENTS.md",
                    "README.md", "LICENSE", ".golangci.yml", "cli.py"}
        for c in critical:
            self.assertIn(c, EXEMPT, f"{c} should be in root file EXEMPT list")

    def test_no_duplicates(self):
        self.assertEqual(len(EXEMPT), len(set(EXEMPT)))

    def test_all_exempt_are_strings(self):
        for e in EXEMPT:
            self.assertIsInstance(e, str)


class TestRootFilesRun(unittest.TestCase):
    def test_run_executes(self):
        try:
            result = root_files_run()
            self.assertIn(result, (0, 1))
        except Exception as e:
            self.fail(f"root_files.run() raised {e}")


if __name__ == "__main__":
    unittest.main()
