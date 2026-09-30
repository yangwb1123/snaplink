//! Conformance for the L0 transport seam.
//!
//! Two properties matter to every consumer, and neither is visible in the rest
//! of the suite:
//!
//! 1. The client never names a concrete HTTP client, so a server can inject one
//!    configured with its own timeouts and pools. Before the seam, the field was
//!    `reqwest::blocking::Client` and a caller could not pass an async client —
//!    which is what made the crate uncallable from a Tokio handler.
//! 2. Every request the SDK issues carries the no-store cache headers the
//!    credential endpoints require.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

use snaplink_sso::{
    LoginOptions, Method, ReqwestTransport, SnaplinkClient, Transport, TransportError,
    TransportRequest, TransportResponse,
};

#[derive(Default)]
struct Recorder {
    requests: Mutex<Vec<TransportRequest>>,
}

#[async_trait::async_trait]
impl Transport for Recorder {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError> {
        self.requests
            .lock()
            .expect("recorder")
            .push(request.clone());
        Ok(TransportResponse::new(
            200,
            r#"{"access_token":"a","token_type":"Bearer"}"#,
        ))
    }
}

/// A client that already holds a session, so a call reaches the transport
/// instead of short-circuiting on "login is required".
fn logged_in(recorder: Arc<Recorder>) -> SnaplinkClient {
    SnaplinkClient::resume_with_transport(
        "https://sso.example.test",
        "spa-client",
        snaplink_sso::TokenResponse {
            access_token: "access-1".to_owned(),
            expires_in: None,
            id_token: None,
            refresh_token: None,
            scope: None,
            token_type: "Bearer".to_owned(),
        },
        recorder,
    )
    .expect("resume")
}

#[tokio::test]
async fn a_caller_supplied_transport_receives_every_request() {
    let recorder = Arc::new(Recorder::default());
    let store: Arc<dyn snaplink_sso::StateStore> = Arc::new(snaplink_sso::MemoryStateStore::new());
    let mut client = SnaplinkClient::with_transport(store, recorder.clone());

    // login() with no callback URL returns a redirect and performs no I/O.
    let options = LoginOptions::new(
        "https://sso.example.test",
        "spa-client",
        "https://app.example.test/callback",
    );
    let started = client.login(&options).await.expect("start");
    assert!(matches!(
        started,
        snaplink_sso::LoginResult::Redirect { .. }
    ));

    // Starting a login is local-only, so nothing has been sent yet.
    assert!(recorder.requests.lock().expect("recorder").is_empty());

    // A call that needs the network goes through the injected transport.
    let _ = logged_in(Arc::clone(&recorder))
        .get_account_context("pro")
        .await;
    let requests = recorder.requests.lock().expect("recorder").clone();
    assert_eq!(requests.len(), 1, "exactly one request expected");
    assert_eq!(requests[0].method, Method::Get);
    assert!(requests[0].url.contains("/api/v1/me/account-context"));
}

#[tokio::test]
async fn default_reqwest_transport_does_not_follow_token_endpoint_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let endpoint = format!("http://{}/token", listener.local_addr().expect("address"));
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).expect("read request");
        stream
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .expect("write redirect");
    });

    let response = ReqwestTransport::new()
        .send(TransportRequest::new(Method::Post, endpoint).form([("code", "authorization-code")]))
        .await
        .expect("the transport should return the redirect response, not follow it");
    assert_eq!(302, response.status);
    server.join().expect("server");
}

#[tokio::test]
async fn credential_requests_carry_no_store_cache_headers() {
    let recorder = Arc::new(Recorder::default());
    let mut client = logged_in(Arc::clone(&recorder));
    let _ = client.get_account_context("pro").await;

    let requests = recorder.requests.lock().expect("recorder").clone();
    assert_eq!(requests.len(), 1, "one request expected");
    let headers: Vec<String> = requests[0]
        .headers
        .iter()
        .map(|(name, value)| format!("{}: {}", name.to_lowercase(), value.to_lowercase()))
        .collect();
    assert!(
        headers.iter().any(|h| h == "cache-control: no-store"),
        "credential endpoints must not be cached, got {headers:?}"
    );
    assert!(
        headers.iter().any(|h| h == "pragma: no-cache"),
        "legacy intermediaries must not cache, got {headers:?}"
    );
}

#[tokio::test]
async fn a_bearer_token_is_attached_when_the_session_has_one() {
    let recorder = Arc::new(Recorder::default());
    let mut client = logged_in(Arc::clone(&recorder));

    let _ = client.get_account_context("pro").await;
    let requests = recorder.requests.lock().expect("recorder").clone();
    assert_eq!(
        requests[0].bearer.as_deref(),
        Some("access-1"),
        "the session token must reach the transport as a bearer"
    );
}

#[cfg(feature = "blocking")]
#[test]
fn blocking_transport_implements_the_async_seam_when_enabled() {
    let _: Arc<dyn Transport> = Arc::new(snaplink_sso::BlockingTransport::default());
}
