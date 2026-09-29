"""Cross-language conformance for the entitlement layer.

The cases in ``ops/build/sdk-conformance/entitlement.json`` are the shared
contract, so a change to the fixture changes what every SDK is held to. The
fixture stores Unix seconds and string-keyed maps to stay readable from any
language; :func:`Entitlement.from_wire` is the only place that mapping happens.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import unittest

from snaplink_sso import (
    Entitlement,
    Feature,
    InactiveReason,
    Limit,
    LicenseState,
    LicenseStateKind,
    Snaplink,
    entitlement_from_account_context,
    has_feature,
    license_state_from_account_context,
)

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "ops"
    / "build"
    / "sdk-conformance"
    / "entitlement.json"
)
REFERENCE_NOW = 1_700_000_000


def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def cases() -> list:
    return fixture()["cases"]


def context_for(case: dict) -> dict:
    return {"product_id": "product-a", "tenant_id": "tenant-a", "entitlement": case["entitlement"]}


class EntitlementConformanceTest(unittest.TestCase):
    def test_fixture_is_reachable_and_populated(self) -> None:
        self.assertTrue(cases(), "the shared fixture must not be empty")

    def test_every_case_classifies_as_the_contract_requires(self) -> None:
        for case in cases():
            with self.subTest(case=case["id"]):
                now = case.get("now", REFERENCE_NOW)
                state = license_state_from_account_context(context_for(case), now)
                self.assertEqual(case["expect_state"], state.kind.value)
                if "expect_inactive_reason" in case:
                    self.assertEqual(
                        case["expect_inactive_reason"], state.inactive_reason.value
                    )

    def test_a_present_entitlement_is_not_necessarily_effective(self) -> None:
        """The defect this layer exists to prevent."""
        for case in cases():
            with self.subTest(case=case["id"]):
                now = case.get("now", REFERENCE_NOW)
                present = case["entitlement"] is not None
                grants = license_state_from_account_context(context_for(case), now).is_active
                if present and not grants:
                    self.assertNotEqual("active", case["expect_state"])

    def test_the_expiry_boundary_is_exclusive(self) -> None:
        case = next(c for c in cases() if c["id"] == "exactly_at_expiry")
        expires_at = case["entitlement"]["expires_at"]
        self.assertTrue(
            license_state_from_account_context(context_for(case), expires_at - 1).is_active,
            "one second before expiry must still grant",
        )
        self.assertFalse(
            license_state_from_account_context(context_for(case), expires_at).is_active,
            "the expiry second itself must not grant",
        )

    def test_feature_lookups_match_the_contract(self) -> None:
        for case in cases():
            now = case.get("now", REFERENCE_NOW)
            for key, want in case.get("expect_features", {}).items():
                with self.subTest(case=case["id"], feature=key):
                    self.assertEqual(
                        want,
                        has_feature(context_for(case), Feature(key), now),
                    )

    def test_limit_lookups_match_the_contract(self) -> None:
        for case in cases():
            now = case.get("now", REFERENCE_NOW)
            for key, want in case.get("expect_limits", {}).items():
                with self.subTest(case=case["id"], limit=key):
                    entitlement = entitlement_from_account_context(context_for(case))
                    grant = entitlement.limit(Limit(key), now) if entitlement else None
                    if grant is None:
                        self.assertFalse(
                            license_state_from_account_context(context_for(case), now).is_active,
                            f"case {case['id']} lost an active limit {key}",
                        )
                        continue
                    self.assertEqual(want.get("soft", 0), grant.soft)
                    self.assertEqual(want.get("hard", 0), grant.hard)
                    self.assertEqual(want.get("unlimited", False), grant.unlimited)

    def test_an_absent_entitlement_is_never_unlimited(self) -> None:
        context = {"product_id": "p", "tenant_id": "t", "entitlement": None}
        state = license_state_from_account_context(context, REFERENCE_NOW)
        self.assertIs(LicenseStateKind.NOT_ACTIVATED, state.kind)
        self.assertFalse(state.is_active)
        self.assertIsNone(state.entitlement)
        self.assertFalse(has_feature(context, Feature.CORE_SSO, REFERENCE_NOW))


class EntitlementUnitTest(unittest.TestCase):
    def test_every_defined_key_exists_on_the_enum(self) -> None:
        for feature in Feature:
            self.assertIs(Feature(feature.value), feature)
        for limit in Limit:
            self.assertIs(Limit(limit.value), limit)
        self.assertEqual(10, len(list(Feature)), "the server defines ten feature keys")
        self.assertEqual(6, len(list(Limit)), "the server defines six limit keys")

    def test_rfc3339_and_unix_seconds_parse_identically(self) -> None:
        """Go serialises time.Time as RFC 3339; fixtures use Unix seconds."""
        stamp = datetime.datetime.fromtimestamp(1_700_000_000, tz=datetime.timezone.utc)
        wire = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual("2023-11-14T22:13:20Z", wire)
        base = {"active": True, "features": {}, "limits": {}}
        from_string = Entitlement.from_wire({**base, "effective_at": wire})
        from_number = Entitlement.from_wire({**base, "effective_at": 1_700_000_000})
        self.assertEqual(from_number.effective_at, from_string.effective_at)
        self.assertEqual(from_number.state_at(1_700_000_005), from_string.state_at(1_700_000_005))

    def test_a_missing_or_malformed_timestamp_is_treated_as_absent(self) -> None:
        base = {"active": True, "features": {}, "limits": {}}
        self.assertIsNone(Entitlement.from_wire(base).expires_at)
        self.assertIsNone(Entitlement.from_wire({**base, "expires_at": "nonsense"}).expires_at)
        self.assertEqual(0, Entitlement.from_wire({**base, "effective_at": None}).effective_at)

    def test_an_unrecognised_key_is_preserved_but_grants_nothing(self) -> None:
        entitlement = Entitlement.from_wire(
            {
                "active": True,
                "effective_at": 1_600_000_000,
                "features": {"core_sso": True, "telemetry_magic": True},
                "limits": {},
            }
        )
        self.assertEqual(["telemetry_magic"], list(entitlement.unknown_features()))
        self.assertTrue(entitlement.has(Feature.CORE_SSO, REFERENCE_NOW))
        with self.assertRaises(ValueError):
            Feature("telemetry_magic")

    def test_a_state_cannot_be_mutated_into_granting(self) -> None:
        state = LicenseState.not_activated()
        with self.assertRaises(Exception):
            state.kind = LicenseStateKind.ACTIVE

    def test_the_inactive_reason_is_presentation_only(self) -> None:
        case = next(c for c in cases() if c["id"] == "inactive_flag_with_no_expiry")
        state = license_state_from_account_context(context_for(case), REFERENCE_NOW)
        self.assertIs(InactiveReason.SUSPENDED, state.inactive_reason)
        self.assertIsNone(state.entitlement)
        self.assertFalse(state.is_active)


class FacadeTest(unittest.TestCase):
    """The Snaplink facade exposes the typed view without changing its wire view."""

    def _snaplink_with(self, entitlement: object) -> Snaplink:
        client = Snaplink()
        client._activation_context = {
            "product_id": "product-a",
            "tenant_id": "tenant-a",
            "entitlement": entitlement,
        }
        return client

    def test_the_raw_context_is_still_available(self) -> None:
        case = next(c for c in cases() if c["id"] == "active_within_window")
        client = self._snaplink_with(case["entitlement"])
        self.assertIsInstance(client.account_context, dict)
        self.assertEqual("product-a", client.account_context["product_id"])

    def test_the_typed_view_classifies_the_same_way(self) -> None:
        case = next(c for c in cases() if c["id"] == "one_second_after_expiry")
        client = self._snaplink_with(case["entitlement"])
        self.assertIsNotNone(client.entitlement, "the entitlement is still present")
        self.assertFalse(client.license_state(case["now"]).is_active)
        self.assertFalse(client.has_feature(Feature.SCIM, case["now"]))

    def test_never_activated_is_distinguishable_from_lapsed(self) -> None:
        never = self._snaplink_with(None)
        self.assertIsNone(never.entitlement)
        self.assertIs(LicenseStateKind.NOT_ACTIVATED, never.license_state().kind)
        lapsed = next(c for c in cases() if c["id"] == "one_second_after_expiry")
        self.assertIsNotNone(self._snaplink_with(lapsed["entitlement"]).entitlement)


if __name__ == "__main__":
    unittest.main()
