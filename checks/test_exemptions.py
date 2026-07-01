#!/usr/bin/env python3
"""Tests for exemptions sync check."""
import unittest
from pathlib import Path
from checks.exemptions import run as exemptions_run
from checks.filesize import EXEMPTIONS


class TestExemptionsList(unittest.TestCase):
    def test_exemptions_is_list(self):
        self.assertIsInstance(EXEMPTIONS, list)

    def test_exemptions_non_empty(self):
        self.assertGreater(len(EXEMPTIONS), 0)

    def test_all_exemptions_are_strings(self):
        for e in EXEMPTIONS:
            self.assertIsInstance(e, str)

    def test_key_files_in_exemptions(self):
        """Critical file exemptions must be present."""
        key_files = [
            "interfaces/sso/sso.go",
            "interfaces/sso/accessors.go",
            "cmd/sso-server/main.go",
            "config/config.go",
        ]
        exempt_str = " ".join(EXEMPTIONS)
        for kf in key_files:
            self.assertIn(kf, exempt_str,
                          f"Key file {kf} should be in EXEMPTIONS")

    def test_no_empty_exemptions(self):
        for e in EXEMPTIONS:
            self.assertTrue(len(e) > 0)

    def test_exemption_paths_are_relative(self):
        for e in EXEMPTIONS:
            self.assertFalse(e.startswith("/"),
                             f"Exemption {e} should be a relative path")


class TestExemptionsRun(unittest.TestCase):
    def test_run_executes(self):
        try:
            result = exemptions_run()
            self.assertIn(result, (0, 1))
        except Exception as e:
            self.fail(f"exemptions.run() raised {e}")


if __name__ == "__main__":
    unittest.main()
