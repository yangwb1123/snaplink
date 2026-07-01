#!/usr/bin/env python3
"""Tests for root business code gate."""
import unittest
from checks.root_business_code import BANNED_PATTERNS, BANNED_FILES, EXEMPT


class TestBannedPatterns(unittest.TestCase):
    def test_patterns_non_empty(self):
        self.assertGreater(len(BANNED_PATTERNS), 0)

    def test_all_patterns_use_wildcards(self):
        for p in BANNED_PATTERNS:
            self.assertIn("*", p, f"Pattern {p} should use wildcard")

    def test_core_patterns_present(self):
        core_patterns = ["*_handler.go", "*_service.go", "*_store.go", "*_grant.go"]
        for cp in core_patterns:
            self.assertIn(cp, BANNED_PATTERNS,
                          f"{cp} should be in banned patterns")


class TestBannedFiles(unittest.TestCase):
    def test_banned_files_non_empty(self):
        self.assertGreater(len(BANNED_FILES), 0)

    def test_banned_files_are_go(self):
        for f in BANNED_FILES:
            self.assertTrue(f.endswith(".go"),
                            f"Banned file {f} should be a .go file")

    def test_no_duplicate_banned_files(self):
        self.assertEqual(len(BANNED_FILES), len(set(BANNED_FILES)))


class TestExempt(unittest.TestCase):
    def test_exempt_non_empty(self):
        self.assertGreater(len(EXEMPT), 0)

    def test_core_server_files_in_exempt(self):
        core_server = [
            "interfaces/sso/sso.go",
            "interfaces/sso/handler.go",
            "interfaces/sso/handlers.go",
            "interfaces/sso/accessors.go",
        ]
        for cs in core_server:
            self.assertIn(cs, EXEMPT, f"{cs} should be exempt")


if __name__ == "__main__":
    unittest.main()
