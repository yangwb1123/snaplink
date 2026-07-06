#!/usr/bin/env python3
"""Tests for the directory fan-out gate."""
import unittest

from checks.directory_fanout import check, run, MAX_SUBDIRS, EXEMPT_DIRS


class TestDirectoryFanout(unittest.TestCase):
    def test_max_subdirs_reasonable(self):
        self.assertEqual(MAX_SUBDIRS, 15)

    def test_exempt_dirs_cover_system_dirs(self):
        self.assertIn(".git", EXEMPT_DIRS)
        self.assertIn("vendor", EXEMPT_DIRS)
        self.assertIn("gen", EXEMPT_DIRS)
        self.assertIn("testdata", EXEMPT_DIRS)

    def test_check_no_crash(self):
        violations = check()
        self.assertIsInstance(violations, list)

    def test_run_executes(self):
        try:
            result = run()
            self.assertIn(result, (0, 1))
        except Exception as e:
            self.fail(f"directory_fanout.run() raised {e}")


if __name__ == "__main__":
    unittest.main()
