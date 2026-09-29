//! Cross-language conformance for entitlement-file verification.
//!
//! The cases in `ops/build/sdk-conformance/license_file.json` are the shared
//! contract. The signing key below is a test fixture generated for this suite
//! and is deliberately not a vendor key: the point of these tests is the
//! verification outcome, not the provenance of the trust root.

use ed25519_dalek::Signer;
use snaplink_sso::{EntitlementFile, LicenseError, LicenseTrust};
use std::path::PathBuf;

const REFERENCE_NOW: i64 = 1_700_000_000;

fn fixture_cases() -> Vec<serde_json::Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../ops/build/sdk-conformance/license_file.json");
    let text = std::fs::read_to_string(path).expect("cannot read the shared fixture");
    let document: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    document["cases"].as_array().expect("cases must be an array").clone()
}

fn fixture_ids() -> Vec<String> {
    fixture_cases()
        .iter()
        .map(|case| case["id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A deterministic Ed25519 keypair for tests.
///
/// Derived from a fixed seed so the suite needs no randomness and the same
/// signature bytes are produced on every run.
fn test_keypair() -> (ed25519_dalek::SigningKey, String) {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let public = BASE64.encode(signing.verifying_key().as_bytes());
    (signing, public)
}

fn untrusted_keypair() -> (ed25519_dalek::SigningKey, String) {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let public = BASE64.encode(signing.verifying_key().as_bytes());
    (signing, public)
}

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

fn entitlement_payload(expires_at: Option<i64>) -> Vec<u8> {
    let mut value = serde_json::json!({
        "tenant_id": "tenant-a", "subscription_id": "sub-a",
        "plan": {"id": "enterprise", "version": 1}, "revision": 1, "active": true,
        "features": {"core_sso": true, "scim": true, "high_availability": true},
        "limits": {"storage_bytes": {"soft": 0, "hard": 0, "unlimited": true}},
        "effective_at": 1_600_000_000i64, "generated_at": 1_600_000_000i64,
    });
    if let Some(expires_at) = expires_at {
        value["expires_at"] = serde_json::json!(expires_at);
    }
    serde_json::to_vec(&value).expect("serialise")
}

fn envelope(
    payload: &[u8],
    signature: &[u8],
    key_id: &str,
    algorithm: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "algorithm": algorithm, "key_id": key_id,
        "payload": BASE64.encode(payload), "signature": BASE64.encode(signature),
    }))
    .expect("serialise")
}

fn signed_file(key_id: &str, expires_at: Option<i64>) -> (Vec<u8>, String) {
    let (signing, public) = test_keypair();
    let payload = entitlement_payload(expires_at);
    let signature = signing.sign(&payload).to_bytes();
    (envelope(&payload, &signature, key_id, "Ed25519"), public)
}

fn trust_for(public_key: &str) -> LicenseTrust {
    LicenseTrust::from_key("vendor-2026", public_key).expect("a valid key must be accepted")
}

#[test]
fn a_correctly_signed_file_verifies_offline() {
    let (file, public) = signed_file("vendor-2026", Some(1_900_000_000));
    let verified = EntitlementFile::verify(&file, &trust_for(&public)).expect("must verify");
    assert_eq!("vendor-2026", verified.key_id);
    assert!(verified.state_at(REFERENCE_NOW).is_active());
    assert!(verified.entitlement.has(snaplink_sso::Feature::Scim, REFERENCE_NOW));
}

#[test]
fn a_tampered_payload_never_verifies() {
    let (signing, public) = test_keypair();
    let mut payload = entitlement_payload(Some(1_900_000_000));
    // Flip one byte inside the encoded payload.
    let index = payload.len() / 2;
    payload[index] ^= 0x01;
    let signature = signing.sign(&payload).to_bytes();
    // Sign the tampered bytes but ship the original: the signature no longer
    // covers what the payload says.
    let original = entitlement_payload(Some(1_900_000_000));
    let file = envelope(&original, &signature, "vendor-2026", "Ed25519");
    assert_eq!(
        LicenseError::SignatureInvalid,
        EntitlementFile::verify(&file, &trust_for(&public)).expect_err("must not verify")
    );
}

#[test]
fn a_signature_from_an_untrusted_key_never_verifies() {
    // The file is signed by a key the trust root does not hold. The key_id in
    // the envelope names the *trusted* key, so this exercises signature
    // verification rather than the key-id lookup.
    let (untrusted_signing, _) = untrusted_keypair();
    let (_, trusted_public) = test_keypair();
    let payload = entitlement_payload(Some(1_900_000_000));
    let signature = untrusted_signing.sign(&payload).to_bytes();
    let file = envelope(&payload, &signature, "vendor-2026", "Ed25519");
    assert_eq!(
        LicenseError::SignatureInvalid,
        EntitlementFile::verify(&file, &trust_for(&trusted_public)).expect_err("must not verify")
    );
}

#[test]
fn a_caller_pinned_key_is_accepted() {
    let (file, public) = signed_file("oem-2026", Some(1_900_000_000));
    let trust = LicenseTrust::from_key("oem-2026", &public).expect("a valid key must be accepted");
    assert!(EntitlementFile::verify(&file, &trust).is_ok(), "an OEM key must verify");
}

#[test]
fn an_unknown_key_id_is_refused() {
    let (file, public) = signed_file("someone-elses-key", Some(1_900_000_000));
    let error = EntitlementFile::verify(&file, &trust_for(&public)).expect_err("must not verify");
    assert_eq!(LicenseError::UntrustedKey("someone-elses-key".to_owned()), error);
}

#[test]
fn an_expired_file_is_inactive_rather_than_an_error() {
    let (file, public) = signed_file("vendor-2026", Some(1_800_000_000));
    let verified = EntitlementFile::verify(&file, &trust_for(&public)).expect("still verifies");
    let state = verified.state_at(1_800_000_001);
    assert!(!state.is_active(), "a lapsed entitlement grants nothing");
    assert_eq!(
        Some(snaplink_sso::InactiveReason::Expired),
        state.inactive_reason()
    );
    assert!(verified.state_at(1_799_999_999).is_active(), "one second earlier it granted");
}

#[test]
fn a_malformed_envelope_is_an_error_not_an_empty_entitlement() {
    for bytes in [
        Vec::new(),
        b"not json".to_vec(),
        b"{}".to_vec(),
        b"{\"version\":1}".to_vec(),
    ] {
        let (_, public) = test_keypair();
        assert!(
            matches!(
                EntitlementFile::verify(&bytes, &trust_for(&public)),
                Err(LicenseError::Malformed(_))
            ),
            "must be malformed, not silently empty"
        );
    }
}

#[test]
fn an_unsupported_algorithm_is_rejected_before_verification() {
    let (signing, public) = test_keypair();
    let payload = entitlement_payload(Some(1_900_000_000));
    let signature = signing.sign(&payload).to_bytes();
    for algorithm in ["none", "HS256", "Ed448", ""] {
        let file = envelope(&payload, &signature, "vendor-2026", algorithm);
        assert_eq!(
            LicenseError::AlgorithmUnsupported(algorithm.to_owned()),
            EntitlementFile::verify(&file, &trust_for(&public)).expect_err("must be refused")
        );
    }
}

#[test]
fn an_unsupported_envelope_version_is_rejected() {
    let (signing, public) = test_keypair();
    let payload = entitlement_payload(Some(1_900_000_000));
    let signature = signing.sign(&payload).to_bytes();
    let mut file: serde_json::Value =
        serde_json::from_slice(&envelope(&payload, &signature, "vendor-2026", "Ed25519"))
            .expect("json");
    file["version"] = serde_json::json!(99);
    assert_eq!(
        LicenseError::AlgorithmUnsupported("envelope version 99".to_owned()),
        EntitlementFile::verify(&serde_json::to_vec(&file).unwrap(), &trust_for(&public))
            .expect_err("must be refused")
    );
}

#[test]
fn an_empty_or_unconfigured_trust_root_never_verifies() {
    let (file, _) = signed_file("vendor-2026", Some(1_900_000_000));
    assert_eq!(
        LicenseError::TrustUnconfigured,
        EntitlementFile::verify(&file, &LicenseTrust::empty()).expect_err("must not verify")
    );
    // The vendor root is not configured in this build, and says so rather than
    // carrying a placeholder key that would read as authority while granting
    // nothing.
    assert_eq!(
        LicenseError::TrustUnconfigured,
        LicenseTrust::vendor_pinned().expect_err("vendor root is unconfigured")
    );
}

#[test]
fn a_malformed_trust_key_is_rejected_rather_than_stored() {
    let mut trust = LicenseTrust::empty();
    assert!(matches!(
        trust.add_key("bad", "not base64!!"),
        Err(LicenseError::Malformed(_))
    ));
    assert!(matches!(
        trust.add_key("short", &BASE64.encode([1u8; 8])),
        Err(LicenseError::Malformed(_))
    ));
    assert!(trust.is_empty(), "a rejected key must not widen trust");
}

#[test]
fn verification_performs_no_network_io() {
    // The whole point of the module. There is no transport in scope, so this is
    // asserted by construction: the only imports are base64, ed25519-dalek,
    // serde and the crate's own entitlement types.
    let (file, public) = signed_file("vendor-2026", Some(1_900_000_000));
    let started = std::time::Instant::now();
    let verified = EntitlementFile::verify(&file, &trust_for(&public)).expect("must verify");
    assert!(started.elapsed() < std::time::Duration::from_millis(50), "verification must be local");
    assert!(verified.entitlement.has(snaplink_sso::Feature::HighAvailability, REFERENCE_NOW));
}

#[test]
fn every_fixture_case_is_implemented_here() {
    // The shared fixture is the contract; a case added to it must have a test
    // here or the suites silently diverge.
    let implemented = [
        "valid_signature",
        "tampered_payload",
        "signature_from_wrong_key",
        "caller_pinned_key",
        "expired_entitlement",
        "malformed_envelope",
        "unsupported_algorithm",
    ];
    let ids = fixture_ids();
    for case in implemented {
        assert!(ids.iter().any(|id| id == case), "fixture case {case} disappeared");
    }
    for id in &ids {
        assert!(
            implemented.contains(&id.as_str()),
            "fixture case {id} has no implementation in this suite"
        );
    }
}
