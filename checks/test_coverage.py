#!/usr/bin/env python3
"""Tests for coverage check."""
import subprocess
import unittest
from unittest.mock import patch

import checks.coverage as coverage
from checks.coverage import (
    TARGETS, parse_package_coverage, parse_total_coverage,
    resolve_package_path,
)


class TestCoverageTargets(unittest.TestCase):
    def test_targets_non_empty(self):
        self.assertGreater(len(TARGETS), 0)

    def test_all_targets_are_positive(self):
        for pkg, target in TARGETS.items():
            self.assertGreater(target, 0,
                               f"Target for {pkg} should be positive")

    def test_core_packages_present(self):
        expected = {".", "core", "oauth", "oidc", "security", "defaultimpl"}
        for e in expected:
            self.assertIn(e, TARGETS, f"Package {e} should have coverage target")

    def test_all_targets_reasonable(self):
        """Coverage targets should be between 1 and 100."""
        for pkg, target in TARGETS.items():
            self.assertLessEqual(target, 100,
                                 f"Target for {pkg} ({target}) exceeds 100")
            self.assertGreater(target, 0,
                               f"Target for {pkg} ({target}) should be > 0")

    def test_targets_resolve_to_full_import_paths(self):
        self.assertEqual(resolve_package_path("core"),
                         "github.com/yangwb1123/snaplink/shared/core")
        self.assertEqual(resolve_package_path("protocols/oauth"),
                         "github.com/yangwb1123/snaplink/protocols/oauth")

    def test_parse_aggregate_coverage(self):
        self.assertEqual(parse_total_coverage("total: (statements) 42.5%"), 42.5)

    def test_parse_package_coverage(self):
        output = "ok github.com/example/pkg 0.123s coverage: 67.8% of statements"
        self.assertEqual(parse_package_coverage(output), 67.8)

    def test_missing_coverage_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_package_coverage("ok github.com/example/pkg 0.123s")

    def test_runner_propagates_go_test_failure(self):
        def failed_run(args, _root):
            return subprocess.CompletedProcess(args, 1, "test output", "test error")

        with patch.object(coverage, "TARGETS", {".": 10}), \
                patch.object(coverage, "_run", side_effect=failed_run):
            self.assertEqual(coverage.run(), 1)


if __name__ == "__main__":
    unittest.main()
