#!/usr/bin/env python3
"""Regression tests for the SDK package-naming gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sdk_naming  # noqa: E402 — path is prepared above


CONVENTIONS = {c.id: c for c in sdk_naming.CONVENTIONS}


class SchemeTests(unittest.TestCase):
    def test_the_canonical_tree_is_green(self):
        self.assertEqual([], sdk_naming.check())

    def test_every_platform_declares_a_distinct_manifest(self):
        manifests = [c.manifest for c in sdk_naming.CONVENTIONS]
        ids = [c.id for c in sdk_naming.CONVENTIONS]
        self.assertEqual(len(manifests), len(set(manifests)))
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_brand_and_capability_tokens_are_explicit(self):
        self.assertEqual("snaplink", sdk_naming.BRAND)
        self.assertEqual("sso", sdk_naming.CAPABILITY)

    def test_namespaces_own_the_brand_and_names_own_the_capability(self):
        """A platform that has a namespace slot must not repeat the brand in the name."""
        for convention in sdk_naming.CONVENTIONS:
            namespace, _, name_slot = convention.expected.rpartition("/")
            if convention.id == "kotlin":
                namespace, _, name_slot = convention.expected.rpartition(":")
            if convention.namespace_slot == "none":
                self.assertEqual("", namespace, convention.id)
                self.assertTrue(convention.expected.lower().startswith("snaplink"), convention.id)
                continue
            self.assertIn("snaplink", namespace, convention.id)
            self.assertNotIn("snaplink", name_slot, convention.id)
            self.assertEqual("sso", name_slot, convention.id)

    def test_the_swift_module_keeps_the_brand_and_drops_the_client_token(self):
        self.assertTrue(sdk_naming.SWIFT_MODULE.startswith("Snaplink"))
        self.assertNotIn("Client", sdk_naming.SWIFT_MODULE)


class PlatformGrammarTests(unittest.TestCase):
    def assertRejected(self, platform: str, name: str) -> None:
        errors = sdk_naming.check_name(CONVENTIONS[platform], name)
        self.assertTrue(errors, f"{platform} accepted {name!r}")

    def test_npm_rejects_uppercase_and_a_missing_scope(self):
        self.assertRejected("typescript", "Snaplink/sso")
        self.assertRejected("typescript", "sso")
        self.assertRejected("typescript", "@snaplink/Sso-Client")

    def test_pypi_rejects_unnormalized_separators_and_underscores(self):
        self.assertRejected("python", "snaplink_sso")
        self.assertRejected("python", "snaplink--sso")
        self.assertRejected("python", "Snaplink-Sso-Client")

    def test_crates_rejects_mixed_separators_and_trailing_dash(self):
        self.assertRejected("rust", "snaplink_sso_client")
        self.assertRejected("rust", "snaplink-sso_client")
        self.assertRejected("rust", "snaplink-sso-")
        self.assertRejected("rust", "1snaplink-sso")

    def test_packagist_requires_a_lowercase_vendor_and_no_doubled_dash(self):
        self.assertRejected("php", "Snaplink/sso")
        self.assertRejected("php", "snaplink/ss--o")
        self.assertRejected("php", "snaplink")

    def test_maven_requires_a_reverse_dns_group(self):
        self.assertRejected("kotlin", "sso")
        self.assertRejected("kotlin", "snaplink:sso")
        self.assertRejected("kotlin", "com.snaplink:Sso")
        self.assertEqual([], sdk_naming.check_name(CONVENTIONS["kotlin"], "com.snaplink:sso"))

    def test_swift_requires_pascal_case(self):
        self.assertRejected("swift", "snaplinkSSO")
        self.assertRejected("swift", "snaplink-sso")
        self.assertRejected("swift", "SnaplinkSSOClient")

    def test_a_legal_name_off_scheme_is_still_rejected(self):
        """Platform-valid but off-scheme: the gate holds the house rule too."""
        errors = sdk_naming.check_name(CONVENTIONS["python"], "acme-sso")
        self.assertEqual(1, len(errors))
        self.assertIn("does not match the canonical name", errors[0])
        self.assertIn("brand token", errors[0])

    def test_an_off_scheme_name_reports_both_defects(self):
        errors = sdk_naming.check_name(CONVENTIONS["python"], "Snaplink_SSO")
        self.assertEqual(2, len(errors), errors)
        self.assertTrue(any("platform rule" in e for e in errors), errors)
        self.assertTrue(any("canonical name" in e for e in errors), errors)


class CommandTests(unittest.TestCase):
    def test_check_is_zero_on_the_canonical_tree(self):
        self.assertEqual(0, sdk_naming.run(["check"]))

    def test_list_documents_every_platform(self):
        self.assertEqual(0, sdk_naming.run(["list"]))

    def test_unknown_action_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as raised:
            sdk_naming.run(["publish"])
        self.assertEqual(2, raised.exception.code)

    def test_a_manifest_missing_from_the_version_gate_fails_closed(self):
        ghost = type(CONVENTIONS["python"])(
            "python",
            Path("sdks/ghost/pyproject.toml"),
            "snaplink-sso",
            sdk_naming._PYPI,
            "r",
            "none",
        )
        with self.assertRaises(sdk_naming.SDKNamingError):
            sdk_naming.declared_name(Path("/nonexistent"), ghost)


if __name__ == "__main__":
    unittest.main()
