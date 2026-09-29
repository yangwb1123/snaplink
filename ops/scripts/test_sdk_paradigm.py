#!/usr/bin/env python3
"""Unit tests for the hand-written SDK-layer paradigm registry gate."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "scripts"))

import sdk_paradigm  # noqa: E402
from sdk_paradigm import SDKParadigmError  # noqa: E402


def _registry() -> dict:
    return json.loads((ROOT / "ops" / "build" / "sdk-paradigm.json").read_text(encoding="utf-8"))


def _language_ids() -> list[str]:
    return [entry["id"] for entry in _registry()["compatibility"]["languages"]]


def _onboarded_ids() -> set[str]:
    return {
        entry["id"]
        for entry in _registry()["compatibility"]["languages"]
        if entry["onboarded"]
    }


def _capability(document: dict, capability_id: str) -> dict:
    for entry in document["capabilities"]:
        if entry["id"] == capability_id:
            return entry
    raise AssertionError(f"capability {capability_id} is not in the registry")


class RegistryShapeTest(unittest.TestCase):
    """The committed registry must satisfy every structural rule."""

    def test_committed_registry_is_valid(self) -> None:
        document = _registry()
        languages, onboarded = sdk_paradigm.validate_languages(document["compatibility"], "registry")
        sdk_paradigm.validate_package_coverage(languages, "registry")
        sdk_paradigm.validate_capabilities(
            document["capabilities"], "registry", languages, onboarded
        )
        self.assertEqual([], sdk_paradigm.validate_symbol_presence(document["capabilities"], "registry"))
        self.assertEqual([], sdk_paradigm.validate_conformance())

    def test_check_reports_pass(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(0, sdk_paradigm.check())
        self.assertIn("verdict: PASS", stdout.getvalue())

    def test_every_capability_declares_every_language(self) -> None:
        document = _registry()
        languages = {entry["id"] for entry in document["compatibility"]["languages"]}
        for entry in document["capabilities"]:
            self.assertEqual(languages, set(entry["languages"]), entry["id"])

    def test_parity_capabilities_are_fully_covered_by_onboarded_languages(self) -> None:
        """Parity is the floor for a reviewed SDK.

        A language still onboarding is allowed to miss it, but only if it is
        marked as such: that is the difference between a visible debt and a
        capability quietly downgraded to make the gate green.
        """
        document = _registry()
        onboarded = _onboarded_ids()
        parity = [entry for entry in document["capabilities"] if entry["parity"] == "parity"]
        self.assertTrue(parity, "the registry must retain parity-enforced capabilities")
        for entry in parity:
            for language_id, declaration in entry["languages"].items():
                if language_id in onboarded:
                    self.assertEqual("present", declaration["status"], f"{entry['id']}.{language_id}")

    def test_an_onboarding_language_still_declares_every_capability(self) -> None:
        document = _registry()
        languages = set(_language_ids())
        onboarding = languages - _onboarded_ids()
        self.assertTrue(onboarding, "the repository has SDKs still onboarding")
        for entry in document["capabilities"]:
            self.assertEqual(languages, set(entry["languages"]), entry["id"])

    def test_at_least_one_language_is_onboarded(self) -> None:
        self.assertTrue(_onboarded_ids())

    def test_layer_prefix_matches_declared_layer(self) -> None:
        for entry in _registry()["capabilities"]:
            self.assertTrue(entry["id"].startswith(f"{entry['layer']}."), entry["id"])

    def test_missing_declarations_all_carry_a_plan(self) -> None:
        for entry in _registry()["capabilities"]:
            for language_id, declaration in entry["languages"].items():
                if declaration["status"] == "missing":
                    self.assertTrue(declaration.get("plan"), f"{entry['id']}.{language_id}")

    def test_shipped_paradigm_doc_exists(self) -> None:
        self.assertTrue((ROOT / "docs" / "sdk-paradigm.md").is_file())


class DeclarationValidationTest(unittest.TestCase):
    """One language's claim about one capability."""

    def _declaration(self, **overrides) -> dict:
        base = {"status": "present", "file": "sdks/rust/src/lib.rs", "symbol": "pub fn login("}
        base.update(overrides)
        return base

    def test_present_requires_file_and_symbol(self) -> None:
        for field in ("file", "symbol"):
            declaration = self._declaration()
            del declaration[field]
            with self.assertRaises(SDKParadigmError) as caught:
                sdk_paradigm._validate_declaration(declaration, "where", "divergent", "rust")
            self.assertIn(field, str(caught.exception))

    def test_present_must_not_carry_plan(self) -> None:
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm._validate_declaration(
                self._declaration(plan="W3"), "where", "divergent", "rust"
            )

    def test_missing_must_not_name_a_symbol(self) -> None:
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm._validate_declaration(
                {"status": "missing", "plan": "W3", "symbol": "x"}, "where", "divergent", "rust"
            )

    def test_missing_requires_plan(self) -> None:
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm._validate_declaration({"status": "missing"}, "where", "divergent", "rust")

    def test_missing_under_parity_is_rejected(self) -> None:
        """The ratchet: a parity capability cannot quietly lose a language."""
        with self.assertRaises(SDKParadigmError) as caught:
            sdk_paradigm._validate_declaration(
                {"status": "missing", "plan": "W3"}, "where", "parity", "rust"
            )
        self.assertIn("parity", str(caught.exception))

    def test_unknown_status_and_parity_are_rejected(self) -> None:
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm._validate_declaration({"status": "maybe"}, "where", "divergent", "rust")
        document = _registry()
        _capability(document, "session.start")["parity"] = "eventually"
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm.validate_capabilities(
            document["capabilities"], "registry", _language_ids(), _onboarded_ids()
        )

    def test_unknown_keys_are_rejected(self) -> None:
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm._validate_declaration(
                self._declaration(will_do="later"), "where", "divergent", "rust"
            )


class CapabilityValidationTest(unittest.TestCase):
    """Whole-capability rules: layer agreement, language completeness, uniqueness."""

    def test_duplicate_capability_id_is_rejected(self) -> None:
        document = _registry()
        document["capabilities"].append(dict(_capability(document, "session.start")))
        with self.assertRaises(SDKParadigmError) as caught:
            sdk_paradigm.validate_capabilities(
            document["capabilities"], "registry", _language_ids(), _onboarded_ids()
        )
        self.assertIn("duplicate", str(caught.exception))

    def test_id_layer_mismatch_is_rejected(self) -> None:
        document = _registry()
        _capability(document, "session.start")["layer"] = "transport"
        with self.assertRaises(SDKParadigmError) as caught:
            sdk_paradigm.validate_capabilities(
            document["capabilities"], "registry", _language_ids(), _onboarded_ids()
        )
        self.assertIn("does not match its layer", str(caught.exception))

    def test_unqualified_id_is_rejected(self) -> None:
        document = _registry()
        _capability(document, "session.start")["id"] = "refresh"
        with self.assertRaises(SDKParadigmError):
            sdk_paradigm.validate_capabilities(
            document["capabilities"], "registry", _language_ids(), _onboarded_ids()
        )

    def test_silent_language_is_rejected(self) -> None:
        document = _registry()
        del _capability(document, "session.start")["languages"]["php"]
        with self.assertRaises(SDKParadigmError) as caught:
            sdk_paradigm.validate_capabilities(
                document["capabilities"], "registry", _language_ids(), _onboarded_ids()
            )
        self.assertIn("silent", str(caught.exception))

    def test_undeclared_language_is_rejected(self) -> None:
        document = _registry()
        _capability(document, "session.start")["languages"]["golang"] = {
            "status": "present", "file": "sdks/go/login.go", "symbol": "x",
        }
        with self.assertRaises(SDKParadigmError) as caught:
            sdk_paradigm.validate_capabilities(
            document["capabilities"], "registry", _language_ids(), _onboarded_ids()
        )
        self.assertIn("undeclared", str(caught.exception))


class SymbolResolutionTest(unittest.TestCase):
    """A present declaration must resolve against the real tree."""

    def test_absent_file_is_reported(self) -> None:
        document = _registry()
        _capability(document, "session.logout")["languages"]["rust"] = {
            "status": "present", "file": "sdks/rust/src/absent.rs", "symbol": "x",
        }
        problems = sdk_paradigm.validate_symbol_presence(document["capabilities"], "registry")
        self.assertTrue(any("does not exist" in problem for problem in problems))

    def test_absent_symbol_is_reported(self) -> None:
        document = _registry()
        _capability(document, "session.logout")["languages"]["rust"] = {
            "status": "present", "file": "sdks/rust/src/lib.rs", "symbol": "pub fn not_real()",
        }
        problems = sdk_paradigm.validate_symbol_presence(document["capabilities"], "registry")
        self.assertTrue(any("is not present" in problem for problem in problems))

    def test_missing_declarations_are_not_resolved(self) -> None:
        problems = sdk_paradigm.validate_symbol_presence(_registry()["capabilities"], "registry")
        self.assertEqual([], [p for p in problems if "session.refresh" in p])

    def test_check_fails_when_a_symbol_disappears(self) -> None:
        """End to end: renaming a real symbol without updating the registry must fail."""
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory) / "sdks" / "rust" / "src"
            sandbox.mkdir(parents=True)
            (sandbox / "lib.rs").write_text("pub fn renamed(\n", encoding="utf-8")
            original_root, original_path = sdk_paradigm.ROOT, sdk_paradigm.PARADIGM_PATH
            document = _registry()
            for entry in document["capabilities"]:
                for declaration in entry["languages"].values():
                    if declaration.get("file", "").startswith("sdks/rust/"):
                        declaration["file"] = str(Path("sdks/rust/src/lib.rs"))
            registry = Path(directory) / "sdk-paradigm.json"
            registry.write_text(json.dumps(document), encoding="utf-8")
            try:
                sdk_paradigm.ROOT = Path(directory)
                sdk_paradigm.PARADIGM_PATH = registry
                sdk_paradigm.SCHEMA_PATH = ROOT / "ops" / "build" / "sdk-paradigm.schema.json"
                sdk_paradigm.CONFORMANCE_DIR_RELATIVE_PATH = Path("ops/build/sdk-conformance")
                shutil.copytree(
                    ROOT / "ops" / "build" / "sdk-conformance",
                    Path(directory) / "ops" / "build" / "sdk-conformance",
                )
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(1, sdk_paradigm.check())
                self.assertIn("is not present", stderr.getvalue())
            finally:
                sdk_paradigm.ROOT, sdk_paradigm.PARADIGM_PATH = original_root, original_path
                sdk_paradigm.SCHEMA_PATH = ROOT / "ops" / "build" / "sdk-paradigm.schema.json"
                sdk_paradigm.CONFORMANCE_DIR_RELATIVE_PATH = Path("ops/build/sdk-conformance")


class ConformanceTest(unittest.TestCase):
    """The shared cross-language fixtures are part of the contract."""

    def test_all_fixtures_present_and_well_formed(self) -> None:
        self.assertEqual([], sdk_paradigm.validate_conformance())

    def test_missing_fixture_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_root = sdk_paradigm.ROOT
            original_relative = sdk_paradigm.CONFORMANCE_DIR_RELATIVE_PATH
            try:
                sdk_paradigm.ROOT = Path(directory)
                sdk_paradigm.CONFORMANCE_DIR_RELATIVE_PATH = Path("ops/build/sdk-conformance")
                problems = sdk_paradigm.validate_conformance()
            finally:
                sdk_paradigm.ROOT = original_root
                sdk_paradigm.CONFORMANCE_DIR_RELATIVE_PATH = original_relative
            self.assertEqual(
                len(sdk_paradigm.REQUIRED_CONFORMANCE_FILES), len(problems)
            )
            self.assertTrue(all("missing conformance fixture" in problem for problem in problems))

    def test_entitlement_fixture_covers_the_expiry_boundary(self) -> None:
        """The whole point of the fixture is the second-level boundary."""
        document = json.loads(
            (ROOT / "ops" / "build" / "sdk-conformance" / "entitlement.json").read_text(
                encoding="utf-8"
            )
        )
        ids = {case["id"] for case in document["cases"]}
        self.assertIn("one_second_before_expiry", ids)
        self.assertIn("exactly_at_expiry", ids)
        self.assertIn("one_second_after_expiry", ids)
        self.assertIn("never_activated", ids)

    def test_license_fixture_never_downgrades_to_active(self) -> None:
        document = json.loads(
            (ROOT / "ops" / "build" / "sdk-conformance" / "license_file.json").read_text(
                encoding="utf-8"
            )
        )
        for case in document["cases"]:
            if case.get("signature") == "valid" and case.get("payload_mutation"):
                self.assertNotEqual("active", case["expect"], case["id"])


class ListActionTest(unittest.TestCase):
    """The human-facing matrix output."""

    def test_list_prints_every_capability(self) -> None:
        document = _registry()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(0, sdk_paradigm.list_capabilities())
        output = stdout.getvalue()
        for entry in document["capabilities"]:
            self.assertIn(entry["id"], output)
        for language in document["compatibility"]["languages"]:
            self.assertIn(language["id"], output)


if __name__ == "__main__":
    unittest.main()
