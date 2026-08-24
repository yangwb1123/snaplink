#!/usr/bin/env python3
"""Tests for add-new-handler skill."""
import unittest
from pathlib import Path

# Load run.py's templates by importing directly
import sys
skill_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(skill_dir.parent))
from shared.loader import load_skill_run

skill_run = load_skill_run(skill_dir, "skill_add_new_handler_run")


class TestHandlerTemplate(unittest.TestCase):
    def test_handler_tmpl_contains_package(self):
        self.assertIn("package {m}", skill_run.HANDLER_TMPL)

    def test_handler_tmpl_has_expected_imports(self):
        self.assertIn("net/http", skill_run.HANDLER_TMPL)
        self.assertIn("core", skill_run.HANDLER_TMPL)

    def test_handler_tmpl_has_wiring_comment(self):
        self.assertIn("tokenNoStoreHeaders", skill_run.HANDLER_TMPL)
        self.assertIn("setBearerChallenge", skill_run.HANDLER_TMPL)


class TestStoreTemplate(unittest.TestCase):
    def test_store_tmpl_contains_package(self):
        self.assertIn("package {m}", skill_run.STORE_TMPL)

    def test_store_tmpl_has_context_import(self):
        self.assertIn("context", skill_run.STORE_TMPL)


if __name__ == "__main__":
    unittest.main()
