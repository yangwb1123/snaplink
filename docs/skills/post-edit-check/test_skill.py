#!/usr/bin/env python3
"""Tests for post-edit-check skill."""
import unittest
from pathlib import Path
import sys
skill_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(skill_dir.parent))
from shared.loader import load_skill_run

check = load_skill_run(skill_dir, "skill_post_edit_check_run").check


class TestPostEditCheck(unittest.TestCase):
    def test_check_executes(self):
        """post-edit-check.run.check() should complete without crashing."""
        try:
            result = check()
            self.assertIn(result, (0, 1))
        except Exception as e:
            self.fail(f"post-edit-check raised {e}")


if __name__ == "__main__":
    unittest.main()
