#!/usr/bin/env python3
"""Tests for security invariants check."""
import unittest
from checks.invariants import grep, run as invariants_run


class TestGrep(unittest.TestCase):
    def test_grep_finds_pattern(self):
        n = grep("tokenNoStoreHeaders", "no-store", count_only=True)
        self.assertGreater(n, 0, "tokenNoStoreHeaders should exist in codebase")

    def test_grep_finds_bearer_challenge(self):
        n = grep("setBearerChallenge", "bearer", count_only=True)
        self.assertGreater(n, 0, "setBearerChallenge should exist in codebase")

    def test_grep_finds_invalid_grant(self):
        n = grep('"invalid_grant"', "grant", count_only=False)
        self.assertGreater(n, 0, "invalid_grant should appear in codebase")

    def test_grep_finds_bcrypt(self):
        n = grep("bcrypt", "bcrypt", count_only=True)
        self.assertGreater(n, 0, "bcrypt should exist in codebase")


class TestInvariantsStructure(unittest.TestCase):
    def test_run_executes_without_error(self):
        """invariants.run() should complete without exception."""
        try:
            result = invariants_run()
            self.assertIn(result, (0, 1))
        except Exception as e:
            self.fail(f"invariants.run() raised {e}")

    def test_docs_exist(self):
        """Verify error-codes.md and openapi.yaml exist."""
        from pathlib import Path
        root = Path.cwd()
        self.assertTrue((root / "docs" / "error-codes.md").exists(),
                        "error-codes.md should exist")
        self.assertTrue((root / "docs" / "openapi.yaml").exists(),
                        "openapi.yaml should exist")


if __name__ == "__main__":
    unittest.main()
