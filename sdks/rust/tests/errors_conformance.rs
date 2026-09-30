//! The error taxonomy is a cross-language contract, not a per-language detail:
//! a caller branches on the code, so the hosted-login SDKs must classify the
//! same response identically. The cases come from the shared fixture, which is
//! what makes drift detectable.

use snaplink_sso::{error_from_response, SnaplinkError, UNCLASSIFIED_ERROR};

fn fixture() -> serde_json::Value {
    let path = concat!(
        "../../ops/build/sdk-conformance/errors.json"
    );
    let text = std::fs::read_to_string(path).expect("cannot read the shared error fixture");
    serde_json::from_str(&text).expect("the shared error fixture is invalid")
}

fn code_of(error: &SnaplinkError) -> &str {
    match error {
        SnaplinkError::OAuth { code, .. } => code,
        other => panic!("a protocol failure must classify as an OAuth error: {other}"),
    }
}

#[test]
fn every_fixture_error_code_survives_verbatim() {
    let document = fixture();
    let cases = document["cases"]
        .as_array()
        .expect("the fixture must carry cases");
    for case in cases {
        let code = case["code"].as_str().expect("a case needs a code");
        // A null status marks a locally originated case (license verification),
        // which is never a wire response.
        let Some(status) = case["status"].as_u64() else {
            continue;
        };
        let body = serde_json::json!({
            "error": code,
            "error_description": "any wording",
        })
        .to_string();

        let error = error_from_response(status as u16, &body);

        assert_eq!(code_of(&error), code, "the code must survive verbatim");
        match error {
            SnaplinkError::OAuth {
                status: got, code, ..
            } => {
                assert_eq!(u64::from(got), status);
                assert_eq!(code, case_code(case));
            }
            _ => unreachable!(),
        }
    }
}

fn case_code(case: &serde_json::Value) -> &str {
    case["code"].as_str().expect("a case needs a code")
}

#[test]
fn a_response_without_a_code_is_never_invented_into_a_server_code() {
    let document = fixture();
    let fallback = document["shape"]["fallback"]["code"]
        .as_str()
        .expect("the fixture must pin a fallback code");
    for body in [
        "{}",
        r#"{"error_description":"no code here"}"#,
        "not json at all",
        "",
    ] {
        let error = error_from_response(500, body);

        assert_eq!(code_of(&error), fallback, "body {body:?}");
        assert_eq!(code_of(&error), UNCLASSIFIED_ERROR);
        assert_ne!(code_of(&error), "invalid_grant", "an unreadable 500 is not a terminal grant");
        match error {
            SnaplinkError::OAuth { status, .. } => assert_eq!(status, 500),
            _ => unreachable!(),
        }
    }
}

#[test]
fn the_public_classifier_matches_the_internal_one() {
    // A caller injecting a Transport needs the same classification the built-in
    // transport produces, including the fallback.
    let error = error_from_response(400, r#"{"error":"invalid_grant"}"#);
    assert_eq!(code_of(&error), "invalid_grant");
    let error = error_from_response(503, "");
    assert_eq!(code_of(&error), UNCLASSIFIED_ERROR);
}
