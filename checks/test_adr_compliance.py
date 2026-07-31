#!/usr/bin/env python3
"""Tests for ADR compliance checker."""
import unittest
from pathlib import Path
from checks.adr_compliance import (
    check_adr0003, check_adr0004, check_adr0007, run,
    KNOWN_PROTOCOL_PACKAGES, MEMORY_PROVIDERS, MAX_SUBDIRS, EXEMPT_DIRS,
    KNOWN_NESTED_PROTOCOL_MODULES, RECOGNIZED_LAYER_DIRS, ROOT
)


class TestADR0003(unittest.TestCase):
    def test_known_protocols_non_empty(self):
        self.assertGreater(len(KNOWN_PROTOCOL_PACKAGES), 0)

    def test_known_nested_modules_non_empty(self):
        self.assertGreater(len(KNOWN_NESTED_PROTOCOL_MODULES), 0)

    def test_protocols_dir_exists(self):
        """protocols/ layer directory should exist."""
        self.assertTrue((ROOT / "protocols").is_dir())

    def test_oauth_oidc_under_protocols(self):
        """OAuth and OIDC should live under protocols/."""
        self.assertTrue((ROOT / "protocols/oauth").is_dir())
        self.assertTrue((ROOT / "protocols/oidc").is_dir())

    def test_no_protocol_dirs_at_root(self):
        """Known protocol packages should not be at root level."""
        for pkg in KNOWN_PROTOCOL_PACKAGES:
            self.assertFalse(
                (ROOT / pkg).is_dir(),
                f"Protocol package '{pkg}/' should not be at root level"
            )

    def test_check_adr0003_runs(self):
        violations = check_adr0003()
        self.assertIsInstance(violations, list)
        # Should not flag known nested modules (they're in infrastructure/)
        for v in violations:
            self.assertNotIn("saml/", v)

    def test_recognized_layer_dirs_cover_key_layers(self):
        expected = {"shared", "domains", "protocols", "platform",
                    "interfaces", "infrastructure", "cmd", "dist"}
        for exp in expected:
            self.assertIn(exp, RECOGNIZED_LAYER_DIRS)


class TestADR0004(unittest.TestCase):
    def test_memory_providers_non_empty(self):
        self.assertGreater(len(MEMORY_PROVIDERS), 0)

    def test_run_does_not_crash(self):
        try:
            violations = check_adr0004()
            self.assertIsInstance(violations, list)
        except Exception as e:
            self.fail(f"check_adr0004 raised {e}")


class TestADR0007(unittest.TestCase):
    def test_max_subdirs_reasonable(self):
        self.assertEqual(MAX_SUBDIRS, 15)

    def test_exempt_dirs_cover_system_dirs(self):
        self.assertIn(".git", EXEMPT_DIRS)
        self.assertIn("vendor", EXEMPT_DIRS)
        self.assertIn("gen", EXEMPT_DIRS)
        self.assertIn("testdata", EXEMPT_DIRS)

    def test_check_adr0007_no_crash(self):
        try:
            violations = check_adr0007()
            self.assertIsInstance(violations, list)
        except Exception as e:
            self.fail(f"check_adr0007 raised {e}")


class TestADRComplianceRun(unittest.TestCase):
    def test_run_executes(self):
        try:
            result = run()
            self.assertIn(result, (0, 1))
        except Exception as e:
            self.fail(f"adr_compliance.run() raised {e}")


if __name__ == "__main__":
    unittest.main()
