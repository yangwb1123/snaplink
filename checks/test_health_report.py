#!/usr/bin/env python3
"""Tests for health report."""
import unittest
from checks.health_report import ROOT


class TestHealthReportStructure(unittest.TestCase):
    def test_root_is_path(self):
        from pathlib import Path
        self.assertIsInstance(ROOT, Path)

    def test_docs_exist(self):
        self.assertTrue((ROOT / "docs").is_dir(), "docs/ should exist")


if __name__ == "__main__":
    unittest.main()
