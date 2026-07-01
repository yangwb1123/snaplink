#!/usr/bin/env python3
"""Tests for coverage check."""
import unittest
from checks.coverage import TARGETS


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


if __name__ == "__main__":
    unittest.main()
