"""Cross-language conformance for entitlement-file verification.

The cases in ``ops/build/sdk-conformance/license_file.json`` are the shared
contract. This suite supplies a deterministic test verifier, deliberately not a
vendor key: the point is the verification outcome, not the provenance of the
trust root.

The verifier is injected rather than imported because this package is
stdlib-only and the standard library has no Ed25519.
"""

from __future__ import annotations

import base64
import json
import unittest
from typing import Iterable, Optional

from snaplink_sso import (
    EntitlementFile,
    LicenseError,
    LicenseTrust,
    license_trust_from_key,
    vendor_pinned_trust,
    verify_license_file,
)
from snaplink_sso.license_file import fixture_case_ids

REFERENCE_NOW = 1_700_000_000
KEY_ID = "vendor-2026"


class TestVerifier:
    """A deterministic stand-in for a real Ed25519 implementation.

    It "verifies" by exact byte equality against a known signature, which is
    enough to exercise every branch of the surrounding policy. A real
    deployment passes a ``cryptography``-backed verifier.
    """

    def __init__(self) -> None:
        self.calls: list = []
        self.expected_payload: Optional[bytes] = None

    def __call__(self, public_key: bytes, payload: bytes, signature: bytes) -> bool:
        self.calls.append((public_key, payload, signature))
        # A real signature covers the payload as well as being made by the key,
        # so both are compared; otherwise a tampered payload would still pass.
        return (
            public_key == base64.b64decode(EXPECTED_PUBLIC)
            and signature == base64.b64decode(EXPECTED_SIGNATURE[0])
            and (self.expected_payload is None or payload == self.expected_payload)
        )

    def __repr__(self) -> str:
        return f"<TestVerifier calls={len(self.calls)}>"


def _payload(expires_at=None) -> bytes:
    value = {
        "tenant_id": "tenant-a",
        "subscription_id": "sub-a",
        "plan": {"id": "enterprise", "version": 1},
        "revision": 1,
        "active": True,
        "features": {"core_sso": True, "scim": True, "high_availability": True},
        "limits": {"storage_bytes": {"soft": 0, "hard": 0, "unlimited": True}},
        "effective_at": 1_600_000_000,
        "generated_at": 1_600_000_000,
    }
    if expires_at is not None:
        value["expires_at"] = expires_at
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


# A fixed 32-byte public key and its matching 64-byte signature are supplied by
# the fixture so no randomness or cryptography is needed at test time.
_FIXTURE_PUBLIC = base64.b64encode(bytes(range(32))).decode("ascii")
_FIXTURE_SIGNATURE = base64.b64encode(bytes(range(64))).decode("ascii")
EXPECTED_PUBLIC = _FIXTURE_PUBLIC
EXPECTED_SIGNATURE = (_FIXTURE_SIGNATURE,)


def envelope(payload: bytes, signature: bytes, key_id: str, algorithm: str, version: int = 1) -> bytes:
    return json.dumps(
        {
            "version": version,
            "algorithm": algorithm,
            "key_id": key_id,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ).encode("utf-8")


def signature_bytes() -> bytes:
    return base64.b64decode(_FIXTURE_SIGNATURE)


def _trust_for(
    signed: bytes, key_id: str = KEY_ID, verifier: TestVerifier = None
) -> LicenseTrust:
    """A trust root whose verifier accepts exactly this payload and signature."""
    verifier = verifier or TestVerifier()
    verifier.expected_payload = signed
    return license_trust_from_key(key_id, _FIXTURE_PUBLIC, verifier)


def _raw(expires_at=None, key_id: str = KEY_ID, algorithm: str = "Ed25519") -> bytes:
    return envelope(_payload(expires_at), signature_bytes(), key_id, algorithm)


class EntitlementFileConformanceTest(unittest.TestCase):
    def test_a_correctly_signed_file_verifies_offline(self):
        verifier = TestVerifier()
        trust = _trust_for(_payload(1_900_000_000), verifier=verifier)
        file = verify_license_file(_raw(1_900_000_000), trust)
        self.assertIsInstance(file, EntitlementFile)
        self.assertEqual(KEY_ID, file.key_id)
        self.assertTrue(file.state_at(REFERENCE_NOW).is_active)
        self.assertTrue(file.entitlement.has(FEATURE_SCIM, REFERENCE_NOW))
        self.assertEqual(1, len(verifier.calls), "the verifier must be consulted exactly once")

    def test_a_tampered_payload_never_verifies(self):
        # The signer saw one payload; the envelope ships a different one.
        signed = _payload(1_900_000_000)
        tampered = signed.replace(b'"scim"', b'"SCIM"')
        self.assertNotEqual(signed, tampered, "the payload must actually differ")
        verifier = TestVerifier()
        trust = _trust_for(signed, verifier=verifier)
        raw = envelope(tampered, signature_bytes(), KEY_ID, "Ed25519")
        with self.assertRaises(LicenseError) as caught:
            verify_license_file(raw, trust)
        self.assertEqual("license_signature_invalid", caught.exception.code)

    def test_an_untrusted_key_is_refused(self):
        verifier = TestVerifier()
        trust = _trust_for(_payload(1_900_000_000), verifier=verifier)
        with self.assertRaises(LicenseError) as caught:
            verify_license_file(_raw(1_900_000_000, key_id="someone-elses-key"), trust)
        self.assertEqual("license_untrusted_key", caught.exception.code)

    def test_a_caller_pinned_key_is_accepted(self):
        verifier = TestVerifier()
        trust = _trust_for(_payload(1_900_000_000), key_id="oem-2026", verifier=verifier)
        file = verify_license_file(_raw(1_900_000_000, key_id="oem-2026"), trust)
        self.assertEqual("oem-2026", file.key_id)

    def test_an_expired_file_is_inactive_rather_than_an_error(self):
        trust = _trust_for(_payload(1_800_000_000))
        file = verify_license_file(_raw(1_800_000_000), trust)
        self.assertFalse(file.state_at(1_800_000_001).is_active)
        self.assertEqual("expired", file.state_at(1_800_000_001).inactive_reason.value)
        self.assertTrue(file.state_at(1_799_999_999).is_active, "one second earlier it granted")

    def test_a_malformed_envelope_is_an_error_not_an_empty_entitlement(self):
        trust = _trust_for(_payload())
        for raw in [b"", b"not json", b"{}", b'{"version":1}', b"[]"]:
            with self.assertRaises(LicenseError) as caught:
                verify_license_file(raw, trust)
            self.assertEqual("license_malformed", caught.exception.code, f"for {raw!r}")

    def test_an_unsupported_algorithm_is_rejected_before_verification(self):
        verifier = TestVerifier()
        trust = _trust_for(_payload(1_900_000_000), verifier=verifier)
        for algorithm in ["none", "HS256", "Ed448", ""]:
            with self.assertRaises(LicenseError) as caught:
                verify_license_file(_raw(1_900_000_000, algorithm=algorithm), trust)
            self.assertEqual("license_algorithm_unsupported", caught.exception.code, algorithm)
        self.assertEqual([], verifier.calls, "no signature work may happen before the algorithm gate")

    def test_an_unsupported_envelope_version_is_rejected(self):
        trust = _trust_for(_payload())
        with self.assertRaises(LicenseError) as caught:
            verify_license_file(envelope(_payload(), signature_bytes(), KEY_ID, "Ed25519", 99), trust)
        self.assertEqual("license_algorithm_unsupported", caught.exception.code)

    def test_an_empty_or_unconfigured_trust_root_never_verifies(self):
        for trust in [LicenseTrust(), LicenseTrust(verifier=TestVerifier())]:
            with self.assertRaises(LicenseError) as caught:
                verify_license_file(_raw(), trust)
            self.assertEqual("license_trust_unconfigured", caught.exception.code)
        with self.assertRaises(LicenseError) as caught:
            vendor_pinned_trust()
        self.assertEqual("license_trust_unconfigured", caught.exception.code)

    def test_a_malformed_trust_key_is_rejected_rather_than_stored(self):
        trust = LicenseTrust(verifier=TestVerifier())
        with self.assertRaises(LicenseError):
            trust.add_base64_key("bad", "not base64!!")
        with self.assertRaises(LicenseError):
            trust.add_key("short", b"\x01" * 8)
        self.assertTrue(trust.is_empty(), "a rejected key must not widen trust")

    def test_a_raising_verifier_is_treated_as_not_verified(self):
        def explode(public_key, payload, signature):
            raise RuntimeError("backend unavailable")

        trust = license_trust_from_key(KEY_ID, _FIXTURE_PUBLIC, explode)
        with self.assertRaises(LicenseError) as caught:
            verify_license_file(_raw(), trust)
        self.assertEqual("license_signature_invalid", caught.exception.code)

    def test_trust_diagnostics_expose_only_key_ids(self):
        self.assertEqual([KEY_ID], _trust_for(_payload()).key_ids())

    def test_every_fixture_case_is_implemented_here(self):
        implemented = {
            "valid_signature",
            "tampered_payload",
            "signature_from_wrong_key",
            "caller_pinned_key",
            "expired_entitlement",
            "malformed_envelope",
            "unsupported_algorithm",
        }
        ids = set(fixture_case_ids())
        for case in implemented:
            self.assertIn(case, ids, f"fixture case {case} disappeared")
        for case in ids:
            self.assertIn(case, implemented, f"fixture case {case} has no test here")


FEATURE_SCIM = "scim"

if __name__ == "__main__":
    unittest.main()
