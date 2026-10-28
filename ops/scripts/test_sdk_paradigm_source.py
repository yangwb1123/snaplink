#!/usr/bin/env python3
"""Narrow Swift declaration/source audit; this does not execute Swift fixtures."""

import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sdk_paradigm


class SwiftDeclarationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((ROOT / "ops/build/sdk-paradigm.json").read_text())
        cls.swift = {c["id"]: c["languages"]["swift"] for c in cls.document["capabilities"]}
        cls.client = (ROOT / "sdks/swift/Sources/SnaplinkAuthClient.swift").read_text()
        cls.errors = (ROOT / "sdks/swift/Sources/Errors.swift").read_text()

    def test_internal_seams_are_not_declared_as_public_injection(self):
        for capability, protocol in [("transport.injection", "OAuthTransport"), ("session.state_store", "SnaplinkSecureStore")]:
            with self.subTest(capability=capability):
                self.assertRegex(self.errors, rf"(?m)^protocol {protocol}: Sendable")
                declaration = self.swift[capability]
                self.assertEqual(declaration["status"], "missing")
                self.assertNotIn("file", declaration)
                self.assertNotIn("symbol", declaration)
                self.assertIn("internal", declaration["note"])
                self.assertIn("public", declaration["plan"])
        public_initializers = re.findall(r"public init\((.*?)\)\s*\{", self.client, re.S)
        self.assertEqual(public_initializers, ["configuration: SnaplinkConfiguration"])
        actor_source = self.client.split("private struct AuthorizationTransaction:", 1)[0]
        self.assertEqual(len(re.findall(r"(?m)^    init\(", actor_source)), 2)
        self.assertIn("@testable import SnaplinkSSO", (ROOT / "sdks/swift/Tests/SnaplinkAuthClientTests.swift").read_text())

    def test_five_existing_implementations_remain_validation_debt_not_absent_source(self):
        cases = {
            "session.clear": ("SnaplinkAuthClient.swift", "public func clear() throws", "SnaplinkAuthClientTests.swift", "testClearDropsLocalSessionAndPendingTransactionWithoutRevocation"),
            "entitlement.setup": ("SnaplinkAuthClient.swift", "public func setup(_ options:", "SnaplinkAuthClientTests.swift", "testSetupSendsOnlyTheCredentialAndStoresTheTicket"),
            "entitlement.account_context": ("SnaplinkAuthClient.swift", "public func accountContext(productID:", "SnaplinkAuthClientTests.swift", "testAccountContextUsesTheCurrentBearerAndRequiresLogin"),
            "entitlement.typed_keys": ("Entitlement.swift", "public enum SnaplinkFeature:", "EntitlementConformanceTests.swift", "entitlement.json"),
            "entitlement.license_file": ("LicenseFile.swift", "public enum SnaplinkLicenseFileVerifier", "LicenseFileConformanceTests.swift", "license_file.json"),
        }
        for capability, (source, symbol, test, test_symbol) in cases.items():
            with self.subTest(capability=capability):
                source_path = "sdks/swift/Sources/" + source
                test_path = "sdks/swift/Tests/" + test
                self.assertIn(symbol, (ROOT / source_path).read_text())
                self.assertIn(test_symbol, (ROOT / test_path).read_text())
                declaration = self.swift[capability]
                self.assertEqual(declaration["status"], "missing")
                self.assertNotIn("file", declaration)
                self.assertIn(source_path, declaration["note"])
                self.assertIn(test_path, declaration["note"])
                self.assertIn("source exists", declaration["note"])
                self.assertIn("not executed", declaration["note"])
                self.assertIn("validation", declaration["plan"])

    def test_preferences_helper_does_not_prove_authorization_url_wiring(self):
        preferences = (ROOT / "sdks/swift/Sources/PresentationPreferences.swift").read_text()
        protocol = (ROOT / "sdks/swift/Sources/OAuthProtocol.swift").read_text()
        self.assertIn("public static func buildLoginHandoff(", preferences)
        self.assertNotIn("buildLoginHandoff", protocol)
        self.assertNotIn('URLQueryItem(name: "presentation_locale"', protocol)
        declaration = self.swift["preferences.handoff"]
        self.assertEqual(declaration["status"], "missing")
        self.assertIn("buildLoginHandoff", declaration["note"])
        self.assertIn("not wired", declaration["note"])

    def test_all_sixteen_dispositions_keep_onboarding_and_parity_floor(self):
        expected_present = {"session.start", "session.access_token", "session.logout", "session.refresh", "runtime.native_async"}
        self.assertEqual(len(self.swift), 16)
        self.assertEqual({c for c, d in self.swift.items() if d["status"] == "present"}, expected_present)
        for capability, declaration in self.swift.items():
            self.assertIn("not executed", declaration["note"], capability)
        swift = next(l for l in self.document["compatibility"]["languages"] if l["id"] == "swift")
        self.assertFalse(swift["onboarded"])
        self.assertEqual(sum(c["parity"] == "parity" for c in self.document["capabilities"]), 8)
        self.assertEqual(sum(d["status"] == "present" for c in self.document["capabilities"] for d in c["languages"].values()), 100)
        languages, onboarded = sdk_paradigm.validate_languages(self.document["compatibility"], "registry")
        sdk_paradigm.validate_capabilities(self.document["capabilities"], "registry", languages, onboarded)

    def test_go_sdk_independent_module_ownership_is_not_root_versioning(self):
        go = next(l for l in self.document["compatibility"]["languages"] if l["id"] == "go")
        self.assertIn("independent module", go["notes"])
        self.assertIn("sdks/go/v", go["notes"])
        self.assertNotIn("versioned by the root", go["notes"])
        module = (ROOT / "sdks/go/go.mod").read_text()
        self.assertIn("module github.com/yangwb1123/snaplink/sdks/go", module)
        doc = (ROOT / "docs/sdk-paradigm.md").read_text()
        self.assertNotIn("Go SDK is versioned by the root module", doc)


if __name__ == "__main__":
    unittest.main()
