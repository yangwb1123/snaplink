#!/usr/bin/env python3
"""Tests for architecture-fix skill."""
import unittest
import re
from pathlib import Path
import sys
skill_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(skill_dir.parent))
from shared.loader import load_skill_run

VIOLATION_FIXES = load_skill_run(skill_dir, "skill_architecture_fix_run").VIOLATION_FIXES


class TestArchitectureFixes(unittest.TestCase):
    def test_violation_fixes_non_empty(self):
        self.assertGreater(len(VIOLATION_FIXES), 0)

    def test_all_fixes_have_source_target_and_action(self):
        for fix in VIOLATION_FIXES:
            self.assertEqual(len(fix), 3,
                             f"Fix {fix} should have 3 elements: (source, target, action)")
            self.assertIsInstance(fix[0], re.Pattern,
                                  f"First element should be a compiled regex")
            self.assertIsInstance(fix[1], str,
                                  f"Second element should be a string (target)")
            self.assertIsInstance(fix[2], str,
                                  f"Third element should be a string (action)")

    def test_oauth_to_oidc_fix_present(self):
        """The most critical fix: oauth importing oidc."""
        found = False
        for pattern, target, action in VIOLATION_FIXES:
            if "oauth" in str(pattern.pattern).lower() and "oidc" in target:
                found = True
                break
        self.assertTrue(found, "Should have a fix for oauth → oidc violations")

    def test_oidc_to_oauth_fix_present(self):
        """The second most critical fix: oidc importing oauth."""
        found = False
        for pattern, target, action in VIOLATION_FIXES:
            if "oidc" in str(pattern.pattern).lower() and "oauth" in target:
                found = True
                break
        self.assertTrue(found, "Should have a fix for oidc → oauth violations")


if __name__ == "__main__":
    unittest.main()
