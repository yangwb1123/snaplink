//! Conformance for the explicit session lifecycle.
//!
//! The behaviour is pinned against a real local HTTP server rather than a
//! transport double, because the point of these tests is the wire shape: the
//! grant, the absence of a code verifier, the bearer on logout, and the fact
//! that logout clears local state even when the server call fails.

use snaplink_sso_client::{SnaplinkClient, TokenResponse};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use url::form_urlencoded;

/// One canned server response, recorded so a test can assert what was sent.
#[derive(Clone)]
struct Captured {
    path: String,
    authorization: String,
    cache_control: String,
    pragma: String,
    form: HashMap<String, String>,
}

struct Harness {
    base_url: String,
    sink: Arc<Mutex<Vec<Captured>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Harness {
    /// The requests the server recorded so far.
    fn requests(&self) -> Vec<Captured> {
        self.sink.lock().expect("sink").clone()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Serve `responses` in order, one connection each, recording every request.
fn serve(responses: Vec<(&'static str, u16, &'static str)>) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let sink: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&sink);
    // Non-blocking accept with an idle deadline. A test that ends without
    // issuing every queued request (e.g. refresh() short-circuits because the
    // session was cleared) must still let the server thread exit, otherwise
    // Harness::drop joins a thread parked in accept() forever.
    listener
        .set_nonblocking(true)
        .expect("listener must support non-blocking accept");
    let handle = thread::spawn(move || {
        for (body, status, payload) in responses {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            let mut accepted = None;
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok(pair) => {
                        accepted = Some(pair);
                        break;
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
            let Some((mut stream, _)) = accepted else {
                return;
            };
            let mut buffer = [0_u8; 8192];
            let Ok(size) = stream.read(&mut buffer) else {
                return;
            };
            let request = String::from_utf8_lossy(&buffer[..size]).to_string();
            let head = request
                .split("\r\n\r\n")
                .next()
                .unwrap_or_default()
                .to_string();
            let raw_body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let header_value = |name: &str| {
                head.lines()
                    .find(|line| {
                        line.split_once(':')
                            .is_some_and(|(key, _)| key.eq_ignore_ascii_case(name))
                    })
                    .and_then(|line| line.split_once(':'))
                    .map(|(_, value)| value.trim().to_owned())
                    .unwrap_or_default()
            };
            let authorization = header_value("authorization");
            let cache_control = header_value("cache-control");
            let pragma = header_value("pragma");
            let form = form_urlencoded::parse(raw_body.as_bytes())
                .into_owned()
                .collect::<HashMap<_, _>>();
            writer.lock().expect("sink").push(Captured {
                path,
                authorization,
                cache_control,
                pragma,
                form,
            });
            let reason = if status == 200 { "OK" } else { "Bad Request" };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                payload.len()
            );
        }
    });
    Harness {
        base_url,
        sink,
        handle: Some(handle),
    }
}

impl Harness {
    /// A client already holding tokens, so the refresh grant can rotate them.
    fn client(&self) -> SnaplinkClient {
        SnaplinkClient::resume(
            &self.base_url,
            "spa-client",
            TokenResponse {
                access_token: "access-1".into(),
                refresh_token: Some("refresh-1".into()),
                expires_in: Some(900),
                id_token: None,
                scope: None,
                token_type: "Bearer".into(),
            },
        )
        .expect("a well-formed token set must resume")
    }
}

const ROTATED: &str = r#"{"access_token":"access-2","refresh_token":"refresh-2","expires_in":900,"token_type":"Bearer"}"#;

#[tokio::test]
async fn refresh_renews_the_access_token_and_rotates_the_refresh_token() {
    let harness = serve(vec![(ROTATED, 200, ROTATED)]);
    let mut client = harness.client();

    let tokens = client.refresh().await.expect("refresh must succeed");
    assert_eq!("access-2", tokens.access_token);
    assert_eq!("access-2", client.access_token().unwrap_or_default());
    assert_eq!(900, client.expires_in().as_secs());
    assert!(client.can_refresh());
}

#[tokio::test]
async fn refresh_sends_the_grant_without_a_code_verifier() {
    let harness = serve(vec![(ROTATED, 200, ROTATED)]);
    let mut client = harness.client();
    client.refresh().await.expect("refresh must succeed");

    let request = harness.requests().first().cloned().expect("one request");
    assert_eq!("/token", request.path);
    assert_eq!(
        Some("refresh_token"),
        request.form.get("grant_type").map(String::as_str)
    );
    assert_eq!(
        Some("refresh-1"),
        request.form.get("refresh_token").map(String::as_str)
    );
    assert_eq!(
        Some("spa-client"),
        request.form.get("client_id").map(String::as_str)
    );
    assert!(
        !request.form.contains_key("code_verifier"),
        "a refresh must never carry a code verifier"
    );
    assert_eq!("no-store", request.cache_control);
    assert_eq!("no-cache", request.pragma);
}

#[tokio::test]
async fn refresh_keeps_the_previous_token_when_the_server_does_not_rotate() {
    let body = r#"{"access_token":"access-2","expires_in":900,"token_type":"Bearer"}"#;
    let harness = serve(vec![(body, 200, body)]);
    let mut client = harness.client();

    client.refresh().await.expect("refresh must succeed");
    assert!(
        client.can_refresh(),
        "a non-rotating response must not lose the ability to refresh"
    );
}

#[tokio::test]
async fn refresh_without_a_refresh_token_makes_no_request() {
    let harness = serve(vec![]);
    let mut client = harness.client();
    client.clear();
    assert!(
        client.refresh().await.is_err(),
        "a session without a refresh token cannot refresh"
    );
    assert!(harness.requests().is_empty());
}

#[tokio::test]
async fn refresh_surfaces_an_invalid_grant() {
    let body = r#"{"error":"invalid_grant","error_description":"unknown refresh token"}"#;
    let harness = serve(vec![(body, 400, body)]);
    let mut client = harness.client();
    // Keep a valid local session but let the server reject its refresh token.
    let error = client
        .refresh()
        .await
        .expect_err("unknown refresh token must fail");
    assert!(matches!(
        error,
        snaplink_sso_client::SnaplinkError::OAuth { status: 400, ref code, .. }
            if code == "invalid_grant"
    ));
}

#[tokio::test]
async fn logout_revokes_server_side_then_clears_local_state() {
    let harness = serve(vec![(r#"{"ok":true}"#, 200, r#"{"ok":true}"#)]);
    let mut client = harness.client();

    client.logout().await.expect("logout must succeed");
    assert!(!client.is_logged_in());
    let request = harness.requests().first().cloned().expect("one request");
    assert_eq!("/logout", request.path);
    assert_eq!("Bearer access-1", request.authorization);
}

#[tokio::test]
async fn logout_clears_local_state_even_when_the_server_call_fails() {
    let harness = serve(vec![(
        r#"{"error":"server_error"}"#,
        500,
        r#"{"error":"server_error"}"#,
    )]);
    let mut client = harness.client();

    assert!(
        client.logout().await.is_err(),
        "the server outcome must be reported"
    );
    assert!(
        !client.is_logged_in(),
        "a caller asking to log out must end up logged out locally regardless"
    );
}

#[tokio::test]
async fn logout_without_a_session_is_a_no_op() {
    let harness = serve(vec![]);
    let mut client = harness.client();
    client.clear();
    client
        .logout()
        .await
        .expect("logout without a session must succeed");
    assert!(harness.requests().is_empty());
}

#[test]
fn clear_is_local_only_and_distinct_from_logout() {
    let harness = serve(vec![]);
    let mut client = harness.client();

    client.clear();
    assert!(!client.is_logged_in());
    assert!(
        harness.requests().is_empty(),
        "clear must not contact the server; that is what logout is for"
    );
}

#[test]
fn resume_rejects_cleartext_remote_issuers_before_retaining_tokens() {
    let tokens = TokenResponse {
        access_token: "access-1".into(),
        refresh_token: Some("refresh-1".into()),
        expires_in: Some(900),
        id_token: None,
        scope: None,
        token_type: "Bearer".into(),
    };

    assert!(matches!(
        SnaplinkClient::resume("http://sso.example.test", "spa-client", tokens),
        Err(snaplink_sso_client::SnaplinkError::InvalidRequest(_))
    ));
}

#[test]
fn expires_in_is_zero_without_an_access_token() {
    let harness = serve(vec![]);
    let mut client = harness.client();
    client.clear();
    assert_eq!(0, client.expires_in().as_secs());
}
