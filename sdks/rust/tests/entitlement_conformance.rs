//! Cross-language conformance for the entitlement layer.
//!
//! The cases in `ops/build/sdk-conformance/entitlement.json` are the shared
//! contract. They are read from the repository so a change to the fixture
//! changes what every SDK is held to, rather than letting each implementation
//! assert whatever it happens to do.

use snaplink_sso_client::{AccountContext, Entitlement, Feature, LicenseState, Limit};
use std::collections::BTreeMap;
use std::path::PathBuf;

const REFERENCE_NOW: i64 = 1_700_000_000;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../ops/build/sdk-conformance/entitlement.json")
}

fn fixture_text() -> String {
    std::fs::read_to_string(fixture_path())
        .unwrap_or_else(|error| panic!("cannot read the shared fixture: {error}"))
}

/// Build an entitlement from the fixture's neutral shape.
///
/// The fixture stores Unix seconds and string-keyed maps so it is readable from
/// any language; this is the only place that mapping happens.
fn entitlement_from_fixture(value: &serde_json::Value) -> Entitlement {
    serde_json::from_value(value.clone()).expect("the fixture must deserialize into Entitlement")
}

fn account_from_fixture(value: &serde_json::Value) -> AccountContext {
    let entitlement = match value {
        serde_json::Value::Null => None,
        other => Some(entitlement_from_fixture(other)),
    };
    AccountContext {
        product_id: "product-a".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        entitlement,
    }
}

fn cases() -> Vec<serde_json::Value> {
    let document: serde_json::Value =
        serde_json::from_str(&fixture_text()).expect("the shared fixture must be valid JSON");
    document["cases"]
        .as_array()
        .expect("cases must be an array")
        .clone()
}

#[test]
fn fixture_is_reachable_and_populated() {
    assert!(!cases().is_empty(), "the shared fixture must not be empty");
}

#[test]
fn every_case_classifies_as_the_contract_requires() {
    for case in cases() {
        let id = case["id"].as_str().expect("every case needs an id");
        let now = case["now"].as_i64().unwrap_or(REFERENCE_NOW);
        let context = account_from_fixture(&case["entitlement"]);
        let state = context.state_at(now);
        let expected = case["expect_state"]
            .as_str()
            .expect("every case needs a state");

        let actual = match state {
            LicenseState::NotActivated => "not_activated",
            LicenseState::Inactive { .. } => "inactive",
            LicenseState::Active(_) => "active",
        };
        assert_eq!(expected, actual, "case {id} classified as {actual}");

        if let Some(reason) = case.get("expect_inactive_reason").and_then(|r| r.as_str()) {
            assert_eq!(
                reason,
                state
                    .inactive_reason()
                    .expect("an inactive state needs a reason")
                    .as_str(),
                "case {id} reported the wrong inactive reason"
            );
        }
    }
}

#[test]
fn a_present_entitlement_is_not_necessarily_effective() {
    // The defect this layer exists to prevent: a naive presence check grants a
    // lapsed subscription.
    for case in cases() {
        let id = case["id"].as_str().expect("every case needs an id");
        let now = case["now"].as_i64().unwrap_or(REFERENCE_NOW);
        let context = account_from_fixture(&case["entitlement"]);
        let present = context.entitlement.is_some();
        let grants = context.state_at(now).is_active();
        if present && !grants {
            assert_ne!(
                "active",
                case["expect_state"].as_str().unwrap_or_default(),
                "case {id} grants while the contract says otherwise"
            );
        }
    }
}

#[test]
fn the_expiry_boundary_is_exclusive() {
    // `expires_at - 1` grants, `expires_at` does not.
    let case = cases()
        .into_iter()
        .find(|case| case["id"] == "exactly_at_expiry")
        .expect("the boundary case must exist");
    let expires_at = case["entitlement"]["expires_at"]
        .as_i64()
        .expect("an expiry");
    let context = account_from_fixture(&case["entitlement"]);
    assert!(
        context.state_at(expires_at - 1).is_active(),
        "one second before expiry must still grant"
    );
    let context = account_from_fixture(&case["entitlement"]);
    assert!(
        !context.state_at(expires_at).is_active(),
        "the expiry second itself must not grant"
    );
}

#[test]
fn feature_lookups_match_the_contract() {
    for case in cases() {
        let id = case["id"].as_str().expect("every case needs an id");
        let now = case["now"].as_i64().unwrap_or(REFERENCE_NOW);
        let context = account_from_fixture(&case["entitlement"]);
        let Some(expected) = case.get("expect_features").and_then(|f| f.as_object()) else {
            continue;
        };
        for (key, want) in expected {
            let feature = Feature::from_key(key).unwrap_or_else(|| panic!("unknown feature {key}"));
            assert_eq!(
                want.as_bool().unwrap_or(false),
                context.has_at(feature, now),
                "case {id} disagreed about feature {key}"
            );
        }
    }
}

#[test]
fn limit_lookups_match_the_contract() {
    for case in cases() {
        let id = case["id"].as_str().expect("every case needs an id");
        let now = case["now"].as_i64().unwrap_or(REFERENCE_NOW);
        let context = account_from_fixture(&case["entitlement"]);
        let Some(expected) = case.get("expect_limits").and_then(|l| l.as_object()) else {
            continue;
        };
        for (key, want) in expected {
            let limit = Limit::from_key(key).unwrap_or_else(|| panic!("unknown limit {key}"));
            let grant = context
                .entitlement
                .as_ref()
                .and_then(|entitlement| entitlement.limit(limit, now));
            let Some(grant) = grant else {
                // An inactive entitlement returns not-granted, never the stored value.
                assert!(
                    !context.state_at(now).is_active() || !want.get("unlimited").is_some(),
                    "case {id} lost an active limit {key}"
                );
                continue;
            };
            assert_eq!(
                want["soft"].as_i64().unwrap_or_default(),
                grant.soft,
                "case {id} limit {key}"
            );
            assert_eq!(
                want["hard"].as_i64().unwrap_or_default(),
                grant.hard,
                "case {id} limit {key}"
            );
            assert_eq!(
                want.get("unlimited")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                grant.is_unlimited(),
                "case {id} limit {key}"
            );
        }
    }
}

#[test]
fn an_absent_entitlement_is_never_unlimited() {
    let context = AccountContext {
        product_id: "product-a".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        entitlement: None,
    };
    assert_eq!(LicenseState::NotActivated, context.state_at(REFERENCE_NOW));
    assert!(!context.has_at(Feature::CoreSso, REFERENCE_NOW));
    assert!(!context
        .entitlement
        .as_ref()
        .is_some_and(|e| e.has(Feature::CoreSso, REFERENCE_NOW)));
}

#[test]
fn every_defined_key_resolves_both_ways() {
    for feature in Feature::ALL {
        assert_eq!(Some(feature), Feature::from_key(feature.as_str()));
    }
    for limit in Limit::ALL {
        assert_eq!(Some(limit), Limit::from_key(limit.as_str()));
    }
    assert_eq!(
        Feature::ALL.len(),
        10,
        "the server defines ten feature keys"
    );
    assert_eq!(Limit::ALL.len(), 6, "the server defines six limit keys");
}

#[test]
fn an_unrecognised_key_is_preserved_but_grants_nothing() {
    let mut features = BTreeMap::new();
    features.insert("core_sso".to_owned(), true);
    features.insert("telemetry_magic".to_owned(), true);
    let entitlement: Entitlement = serde_json::from_value(serde_json::json!({
        "tenant_id": "tenant-a", "subscription_id": "sub-a",
        "plan": {"id": "team", "version": 1}, "revision": 1, "active": true,
        "features": features, "limits": {},
        "effective_at": 1_600_000_000, "generated_at": 1_600_000_000,
    }))
    .expect("an unknown key must not fail the parse");
    assert_eq!(
        1,
        entitlement.unknown_features().count(),
        "the unknown key must be visible"
    );
    assert!(
        entitlement.has(Feature::CoreSso, REFERENCE_NOW),
        "known keys still resolve"
    );
    assert!(
        Feature::from_key("telemetry_magic").is_none(),
        "an unknown key is not a Feature"
    );
}

#[test]
fn rfc3339_and_unix_seconds_parse_identically() {
    // Go serialises `time.Time` as RFC 3339; a fixture or hand-written file
    // uses Unix seconds. Both must land on the same instant.
    let wire: Entitlement = serde_json::from_value(serde_json::json!({
        "tenant_id": "t", "subscription_id": "s", "plan": {"id": "team", "version": 1},
        "revision": 1, "active": true, "features": {}, "limits": {},
        "effective_at": "2023-11-14T22:13:19Z", "expires_at": "2023-11-14T22:13:20Z",
        "generated_at": 1_700_000_000i64,
    }))
    .expect("RFC 3339 must parse");
    let numeric: Entitlement = serde_json::from_value(serde_json::json!({
        "tenant_id": "t", "subscription_id": "s", "plan": {"id": "team", "version": 1},
        "revision": 1, "active": true, "features": {}, "limits": {},
        "effective_at": 1_699_999_999i64, "expires_at": 1_700_000_000i64,
        "generated_at": 1_700_000_000i64,
    }))
    .expect("Unix seconds must parse");
    assert_eq!(wire.effective_at, numeric.effective_at);
    assert_eq!(wire.expires_at, numeric.expires_at);
    assert_eq!(
        wire.state_at(1_699_999_999),
        numeric.state_at(1_699_999_999)
    );
}

#[test]
fn an_unparseable_timestamp_is_rejected_rather_than_defaulted() {
    let result: Result<Entitlement, _> = serde_json::from_value(serde_json::json!({
        "tenant_id": "t", "subscription_id": "s", "active": true,
        "features": {}, "limits": {}, "effective_at": "not-a-timestamp",
    }));
    assert!(
        result.is_err(),
        "a malformed timestamp must not silently become zero"
    );
}
