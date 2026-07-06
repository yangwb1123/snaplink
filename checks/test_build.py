#!/usr/bin/env python3
"""Tests for the build gate config wiring (does not invoke `go build` —
that's exercised by `python cli.py build` / CI, not the fast unit suite)."""
import unittest

from checks.config import get_config


class TestBuildConfig(unittest.TestCase):
    def test_binaries_non_empty(self):
        cfg = get_config().build
        self.assertGreater(len(cfg.binaries), 0)

    def test_binaries_have_name_and_path(self):
        for b in get_config().build.binaries:
            self.assertIn("name", b)
            self.assertIn("path", b)

    def test_output_dir_set(self):
        self.assertTrue(get_config().build.output_dir)


if __name__ == "__main__":
    unittest.main()
