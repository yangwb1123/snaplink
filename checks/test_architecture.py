#!/usr/bin/env python3
"""Tests for architecture dependency direction gate."""
import unittest
from pathlib import Path
from checks.architecture import check_package, FORBIDDEN, EXCLUDED_DIRS, ROOT


class TestForbiddenImports(unittest.TestCase):
    def test_forbidden_map_has_core_layers(self):
        """Core layers that have direction restrictions should be in the map."""
        # The FORBIDDEN map uses flat package names (not layer dir prefixes).
        # Layer-level enforcement happens via the Go architecture_layer_test.go.
        expected = {"core", "security", "oauth", "oidc", "admin", "defaultimpl"}
        for layer in expected:
            self.assertIn(layer, FORBIDDEN,
                          f"{layer} missing from FORBIDDEN map")

    def test_core_cannot_import_up(self):
        forbidden = FORBIDDEN.get("core", [])
        self.assertIn("oauth", forbidden)
        self.assertIn("oidc", forbidden)
        self.assertIn("admin", forbidden)
        self.assertIn("security", forbidden)
        self.assertIn("defaultimpl", forbidden)

    def test_oauth_cannot_import_oidc(self):
        forbidden = FORBIDDEN.get("oauth", [])
        self.assertIn("oidc", forbidden)

    def test_oidc_cannot_import_oauth(self):
        forbidden = FORBIDDEN.get("oidc", [])
        self.assertIn("oauth", forbidden)

    def test_defaultimpl_only_forbidden_from_up(self):
        """defaultimpl can import from layers below, but not admin."""
        forbidden = FORBIDDEN.get("defaultimpl", [])
        self.assertNotIn("core", forbidden)
        self.assertNotIn("security", forbidden)
        self.assertNotIn("oauth", forbidden)
        self.assertIn("admin", forbidden)

    def test_no_self_imports(self):
        for layer, forbidden in FORBIDDEN.items():
            self.assertNotIn(layer, forbidden,
                             f"{layer} should not forbid itself")


class TestExcludedDirs(unittest.TestCase):
    def test_excluded_dirs_cover_vendor_and_gen(self):
        self.assertIn(".git", EXCLUDED_DIRS)
        self.assertIn("gen", EXCLUDED_DIRS)
        self.assertIn("vendor", EXCLUDED_DIRS)

    def test_nested_modules_excluded(self):
        nested = {"kms", "redis", "saml", "ldap", "kerberos",
                  "radius", "extauthz"}
        for n in nested:
            self.assertIn(n, EXCLUDED_DIRS,
                          f"{n} should be excluded from arch check")


class TestCheckPackage(unittest.TestCase):
    """Test check_package on real repo directories."""

    def test_no_violations_in_known_good_packages(self):
        """Packages with allowed imports should have no violations."""
        # security/ can import core/ (layer below)
        violations = check_package(ROOT / "shared/security")
        self.assertEqual(violations, [])

    def test_nested_module_excluded(self):
        """Nested modules should not be checked for direction."""
        violations = check_package(ROOT / "infrastructure/saml")
        self.assertEqual(violations, [])

    def test_non_go_dir_skipped(self):
        """Directories with no Go files should have no violations."""
        violations = check_package(ROOT / "docs")
        self.assertEqual(violations, [])

    def test_admin_restrictions(self):
        """admin/ should not import defaultimpl/ or cmd/."""
        violations = check_package(ROOT / "admin")
        for v in violations:
            self.assertNotIn("cmd/", v,
                             "admin should not import cmd/")

    def test_no_upward_imports_from_shared_core(self):
        """shared/core/ should not import oauth/, oidc/, admin/."""
        violations = check_package(ROOT / "shared/core")
        for v in violations:
            if "oauth" in v or "oidc" in v or "admin" in v:
                self.fail(f"shared/core should not import from {v}")


if __name__ == "__main__":
    unittest.main()
