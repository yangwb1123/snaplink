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
        """A namespace slot holds the brand unless the platform needs a domain."""
        for convention in sdk_naming.CONVENTIONS:
            namespace, _, name_slot = convention.expected.rpartition("/")
            if convention.id == "kotlin":
                namespace, _, name_slot = convention.expected.rpartition(":")
            if convention.namespace_slot == "none":
                self.assertEqual("", namespace, convention.id)
                self.assertTrue(convention.expected.lower().startswith("snaplink"), convention.id)
                continue
            if convention.namespace_is_domain:
                # Maven Central verifies the group against a domain, so the brand
                # moves into the artifactId instead of the groupId.
                self.assertNotIn("snaplink", namespace, convention.id)
                self.assertEqual("snaplink", name_slot, convention.id)
                continue
            self.assertIn("snaplink", namespace, convention.id)
            self.assertNotIn("snaplink", name_slot, convention.id)
            self.assertEqual(sdk_naming.CAPABILITY, name_slot, convention.id)

    def test_the_maven_group_is_the_reverse_dns_product_host(self):
        """A Central groupId must name a host the publisher controls."""
        group = sdk_naming.MAVEN_GROUP
        self.assertEqual("sso.ywbsd.site", ".".join(reversed(group.split("."))))
        self.assertEqual(f"{group}:snaplink", CONVENTIONS["kotlin"].expected)
        self.assertTrue(CONVENTIONS["kotlin"].namespace_is_domain)

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
        self.assertRejected("kotlin", "snaplink")
        self.assertRejected("kotlin", "snaplink:snaplink")
        self.assertRejected("kotlin", "site.ywbsd:snaplink")
        self.assertRejected("kotlin", "site.ywbsd.sso:SNAPLINK")
        self.assertEqual([], sdk_naming.check_name(CONVENTIONS["kotlin"], "site.ywbsd.sso:snaplink"))

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


class UniquenessTests(unittest.TestCase):
    """One registry allows one owner per name; different registries do not clash."""

    def test_the_canonical_tree_has_no_duplicate_claim(self):
        self.assertEqual([], sdk_naming.check_uniqueness(sdk_naming.ROOT, self._claims()))

    def _claims(self) -> list[tuple[str, str, str]]:
        claims = []
        for convention in sdk_naming.CONVENTIONS:
            claims.append(
                (
                    sdk_naming.REGISTRIES[convention.id],
                    convention.id,
                    sdk_naming.declared_name(sdk_naming.ROOT, convention),
                )
            )
        claims.append(
            ("PyPI", sdk_naming.ENGINEERING_CLI_LABEL, sdk_naming._engineering_cli_name(sdk_naming.ROOT))
        )
        return claims

    def test_the_engineering_cli_does_not_squat_on_a_published_name(self):
        """The bug this exists for: the CLI was named snaplink-sso, like the SDK."""
        cli = sdk_naming._engineering_cli_name(sdk_naming.ROOT)
        python_sdk = sdk_naming.declared_name(
            sdk_naming.ROOT, CONVENTIONS["python"]
        )
        self.assertNotEqual(
            sdk_naming._normalize(cli), sdk_naming._normalize(python_sdk), cli
        )
        self.assertTrue(cli.startswith(sdk_naming.BRAND), cli)

    def test_the_same_name_on_two_registries_is_allowed(self):
        """PyPI and crates.io both carry snaplink-sso; that is not a collision."""
        self.assertEqual(
            [],
            sdk_naming.check_uniqueness(
                sdk_naming.ROOT,
                [("PyPI", "python", "snaplink-sso"), ("crates.io", "rust", "snaplink-sso")],
            ),
        )

    def test_two_claims_on_one_registry_fail(self):
        errors = sdk_naming.check_uniqueness(
            sdk_naming.ROOT,
            [("PyPI", "engineering-cli", "snaplink-sso"), ("PyPI", "python", "snaplink-sso")],
        )
        self.assertEqual(1, len(errors), errors)
        self.assertIn("PyPI", errors[0])
        self.assertIn("engineering-cli", errors[0])

    def test_a_three_way_collision_reports_every_claimant(self):
        errors = sdk_naming.check_uniqueness(
            sdk_naming.ROOT,
            [
                ("PyPI", "engineering-cli", "snaplink-sso"),
                ("PyPI", "python", "Snaplink_SSO"),
                ("PyPI", "python-extra", "snaplink.sso"),
            ],
        )
        self.assertEqual(1, len(errors), errors)
        for label in ("engineering-cli", "python", "python-extra"):
            self.assertIn(label, errors[0])

    def test_normalization_follows_pep_503_for_equality(self):
        for spelling in ("Snaplink_SSO", "snaplink.sso", "SNAPLINK--SSO", " snaplink-sso "):
            self.assertEqual("snaplink-sso", sdk_naming._normalize(spelling), spelling)

    def test_every_sdk_package_declares_its_registry(self):
        self.assertEqual(
            sorted(c.id for c in sdk_naming.CONVENTIONS), sorted(sdk_naming.REGISTRIES)
        )

    def test_the_engineering_cli_is_not_gated_by_the_sdk_scheme(self):
        """It is a developer tool: uniqueness applies, the registry scheme does not."""
        cli = sdk_naming._engineering_cli_name(sdk_naming.ROOT)
        self.assertFalse(cli.endswith(f"-{sdk_naming.CAPABILITY}"), cli)
        self.assertNotIn(cli, {c.expected for c in sdk_naming.CONVENTIONS}, cli)


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
