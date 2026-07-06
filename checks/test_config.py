#!/usr/bin/env python3
"""Tests for the engineering.yaml config loader."""
import tempfile
import unittest
from pathlib import Path

from checks.config import Config, load, get_config


class TestLoad(unittest.TestCase):
    def test_loads_real_engineering_yaml(self):
        cfg = load("engineering.yaml")
        self.assertIsInstance(cfg, Config)
        self.assertEqual(cfg.project.name, "snaplink")
        self.assertEqual(cfg.filesize.max_lines, 500)
        self.assertIn("oidc", cfg.architecture.forbidden.get("oauth", []))

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            load("/nonexistent/engineering.yaml")

    def test_partial_yaml_falls_back_to_defaults(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            tmp.write("project:\n  name: demo\n")
            path = tmp.name
        try:
            cfg = load(path)
            self.assertEqual(cfg.project.name, "demo")
            self.assertEqual(cfg.filesize.max_lines, 500)  # dataclass default
            self.assertEqual(cfg.filesize.exemptions, [])
        finally:
            Path(path).unlink()


class TestGetConfig(unittest.TestCase):
    def test_get_config_is_cached(self):
        self.assertIs(get_config(), get_config())


if __name__ == "__main__":
    unittest.main()
