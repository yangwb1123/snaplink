//! Conformance for the authorization read.
//!
//! The cases in `ops/build/sdk-conformance/authorization.json` are the shared
//! contract. They exist because a consumer that re-implements the permission
//! rule instead of calling the SDK's is how two implementations end up
//! disagreeing about the same token.

use snaplink_sso::{Authorization, holds};
use std::path::PathBuf;

fn cases() -> Vec<serde_json::Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../ops/build/sdk-conformance/authorization.json");
    let text = std::fs::read_to_string(path).expect("cannot read the shared fixture");
    let document: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    document["cases"].as_array().expect("cases must be an array").clone()
}

#[test]
fn every_permission_case_is_decided_as_the_contract_requires() {
    for case in cases() {
        let id = case["id"].as_str().expect("id");
        let held: Vec<String> = case["held"]
            .as_array()
            .expect("held")
            .iter()
            .map(|value| value.as_str().unwrap_or_default().to_owned())
            .collect();
        let required = case["required"].as_str().unwrap_or_default();
        let expect = case["expect"].as_bool().expect("expect");
        assert_eq!(
            expect,
            holds(&held, required),
            "case {id}: holds({held:?}, {required:?}) disagreed"
        );
    }
}

#[test]
fn the_fixture_covers_the_cases_that_actually_bite() {
    let ids: Vec<String> = cases()
        .iter()
        .map(|case| case["id"].as_str().unwrap_or_default().to_owned())
        .collect();
    for required in [
        "exact_match",
        "domain_wildcard_covers_a_narrower_permission",
        "domain_wildcard_does_not_cross_domains",
        "domain_wildcard_does_not_match_a_similar_looking_domain",
        "domain_wildcard_is_a_prefix_rule",
        "a_bare_star_grants_everything",
        "a_bare_star_grants_an_unqualified_permission",
        "an_unqualified_permission_is_never_a_prefix",
    ] {
        assert!(ids.iter().any(|id| id == required), "fixture lost {required}");
    }
}

// --- the shape -------------------------------------------------------------

fn authorization(permissions: &[&str]) -> Authorization {
    Authorization {
        subject: "user-alice".to_owned(),
        email: Some("alice@example.test".to_owned()),
        name: Some("Alice".to_owned()),
        roles: vec!["viewer".to_owned()],
        permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
        menus: vec![snaplink_sso::MenuNode {
            id: "m-inbound".to_owned(),
            name: "Inbounds".to_owned(),
            path: "/inbounds".to_owned(),
            icon: "server".to_owned(),
            permission: "panel:read".to_owned(),
            buttons: vec![
                snaplink_sso::MenuButton {
                    code: "btn-save".to_owned(),
                    name: "Save".to_owned(),
                    permission: "panel:config:write".to_owned(),
                },
                snaplink_sso::MenuButton {
                    code: "btn-help".to_owned(),
                    name: "Help".to_owned(),
                    permission: String::new(),
                },
            ],
            children: vec![snaplink_sso::MenuNode {
                id: "m-nested".to_owned(),
                name: "Nested".to_owned(),
                permission: "panel:admin:only".to_owned(),
                ..snaplink_sso::MenuNode::default()
            }],
        }],
    }
}

#[test]
fn allows_mirrors_the_contract_on_a_typed_authorization() {
    let grants = authorization(&["panel:*"]);
    assert!(grants.allows("panel:read"));
    assert!(grants.allows("panel:config:apply"));
    assert!(!grants.allows("billing:read"));
    assert!(grants.has_role("viewer"));
    assert!(!grants.has_role("owner"));
}

#[test]
fn a_bare_star_is_global_exactly_as_the_server_treats_it() {
    // The server grants anything for a held "*", including a code with no
    // domain at all. A client that denied here would hide controls the server
    // actually allows.
    let grants = authorization(&["*"]);
    assert!(grants.allows("panel:read"));
    assert!(grants.allows("superuser"));
    assert!(grants.allows("anything:at:all"));
}

#[test]
fn a_menu_is_found_at_any_depth() {
    let grants = authorization(&["panel:*"]);
    assert!(grants.menu("m-inbound").is_some());
    assert!(grants.menu("m-nested").is_some());
    assert!(grants.menu("absent").is_none());
}

#[test]
fn an_unpermitted_node_is_filtered_out_and_its_button_is_hidden() {
    let grants = authorization(&["panel:read"]);
    let visible = grants.visible_menus();
    assert_eq!(1, visible.len(), "the permitted node stays");
    let actions = visible[0].actions(&grants.permissions);
    let codes: Vec<&str> = actions.iter().map(|button| button.code.as_str()).collect();
    // The empty-permission button is always offered; the withheld one is not.
    assert_eq!(vec!["btn-help"], codes);
}

#[test]
fn an_empty_permission_on_a_node_or_button_means_always_shown() {
    let grants = Authorization {
        subject: "s".to_owned(),
        menus: vec![snaplink_sso::MenuNode {
            id: "always".to_owned(),
            name: "Always".to_owned(),
            permission: String::new(),
            buttons: vec![snaplink_sso::MenuButton {
                code: "b".to_owned(),
                name: "B".to_owned(),
                permission: String::new(),
            }],
            ..snaplink_sso::MenuNode::default()
        }],
        ..Authorization::default()
    };
    assert_eq!(1, grants.visible_menus().len(), "an empty permission must not hide a node");
    assert_eq!(1, grants.visible_menus()[0].actions(&[]).len());
}

// --- the real path ---------------------------------------------------------
//
// Authorization is assembled from four responses, so it is verified by driving
// `authorize()` against a local server rather than by parsing a document that
// never exists on the wire.


use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

/// What the fake identity server was asked for.
type Log = Arc<Mutex<Vec<String>>>;

/// Serve the four endpoints `authorize()` reads, then answer the token exchange.
fn fake_identity_server(log: Log) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let login_log = Arc::clone(&log);
    thread::spawn(move || {
        for _ in 0..5 {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut buffer = [0_u8; 8192];
            let Ok(size) = stream.read(&mut buffer) else { return };
            let request = String::from_utf8_lossy(&buffer[..size]).to_string();
            // Record the raw target, but route on the path only: the /me
            // endpoints carry ?client_id=..., so matching the raw target would
            // silently send every scoped call to the catch-all.
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_owned();
            login_log.lock().expect("log").push(target.clone());
            let path = target.split('?').next().unwrap_or_default().to_owned();
            let body = match path.as_str() {
                "/token" => r#"{"access_token":"access-1","expires_in":3600,"token_type":"Bearer"}"#,
                "/userinfo" => r#"{"sub":"user-alice","email":"alice@example.test","name":"Alice"}"#,
                "/permissions/me" => r#"{"client_id":"singbox-panel","permissions":[{"code":"panel:read","name":"Read"},{"code":"panel:config:apply"}]}"#,
                "/roles/me" => r#"{"client_id":"singbox-panel","roles":[{"code":"viewer","name":"Viewer"}]}"#,
                "/menus/me" => r#"{"menus":[{"id":"m-inbound","name":"Inbounds","path":"/inbounds","permission":"panel:read","buttons":[{"code":"btn-save","name":"Save","permission":"panel:config:write"}]}]}"#,
                _ => r#"{"error":"not_found"}"#,
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
        }
    });
    base_url
}

/// A signed-in client, without driving the login redirect by hand.
async fn signed_in(base_url: &str) -> snaplink_sso::SnaplinkClient {
    snaplink_sso::SnaplinkClient::resume(
        base_url,
        "singbox-panel",
        snaplink_sso::TokenResponse {
            access_token: "access-1".into(),
            refresh_token: None,
            expires_in: Some(3600),
            id_token: None,
            scope: None,
            token_type: "Bearer".into(),
        },
    )
    .expect("resume")
}

#[tokio::test]
async fn authorize_assembles_identity_permissions_roles_and_menus() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let base_url = fake_identity_server(Arc::clone(&log));
    let client = signed_in(&base_url).await;

    let authorization = client.authorize("singbox-panel").await.expect("authorize");

    assert_eq!("user-alice", authorization.subject);
    assert_eq!(Some("alice@example.test".to_owned()), authorization.email);
    assert_eq!(Some("Alice".to_owned()), authorization.name);
    assert_eq!(vec!["viewer".to_owned()], authorization.roles);
    assert_eq!(
        vec!["panel:read".to_owned(), "panel:config:apply".to_owned()],
        authorization.permissions
    );
    assert_eq!(1, authorization.menus.len());
    assert_eq!("m-inbound", authorization.menus[0].id);
    assert_eq!("btn-save", authorization.menus[0].buttons[0].code);

    // Every projection was read for the requested client.
    let raw_targets = log.lock().expect("log").clone();
    let paths: Vec<String> = raw_targets
        .iter()
        .map(|target| target.split('?').next().unwrap_or_default().to_owned())
        .collect();
    for endpoint in ["/userinfo", "/permissions/me", "/roles/me", "/menus/me"] {
        assert!(
            paths.iter().any(|path| path.starts_with(endpoint)),
            "{endpoint} was never read; read {paths:?}"
        );
    }
    // The log records the bare path, so re-read the raw targets to confirm the
    // scope parameter was actually sent on every projection.
    for projection in ["/permissions/me", "/roles/me", "/menus/me"] {
        assert!(
            raw_targets
                .iter()
                .any(|target| target.starts_with(projection) && target.contains("client_id=singbox-panel")),
            "{projection} was read without a client scope; targets were {raw_targets:?}"
        );
    }
}

#[tokio::test]
async fn authorize_requires_a_login() {
    let client = snaplink_sso::SnaplinkClient::new();
    let error = client.authorize("singbox-panel").await.expect_err("must fail");
    assert!(error.to_string().contains("login"), "{error}");
}

#[tokio::test]
async fn authorize_requires_a_client_id() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let base_url = fake_identity_server(log);
    let client = signed_in(&base_url).await;
    let error = client.authorize("  ").await.expect_err("must fail");
    assert!(error.to_string().contains("client_id"), "{error}");
}

#[tokio::test]
async fn userinfo_alone_needs_no_client_scope() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let base_url = fake_identity_server(log);
    let client = signed_in(&base_url).await;
    let only = client.userinfo().await.expect("userinfo");
    assert_eq!("user-alice", only.subject);
    // It must not quietly pull the permission projection too.
    assert!(only.permissions.is_empty());
}

#[test]
fn an_assembled_authorization_with_no_grants_allows_nothing() {
    // The decisive property: absent permissions must deny, never default to
    // granted because a field was missing.
    let empty = Authorization { subject: "s".to_owned(), ..Authorization::default() };
    assert!(!empty.allows("panel:read"));
    assert!(empty.permissions.is_empty());
    assert!(empty.roles.is_empty());
    assert!(empty.menus.is_empty());
    assert!(empty.email.is_none());
    assert!(empty.visible_menus().is_empty());
}
