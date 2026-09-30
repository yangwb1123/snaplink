//! L0 Transport — the single seam every network call goes through.
//!
//! The seam is **async by default**. `BlockingTransport` is an optional backend
//! for environments that need reqwest's blocking client; it dispatches network
//! work to Tokio's blocking pool so it does not park an executor worker. It still
//! requires a Tokio runtime to drive the async SDK API.
//!
//! Timeout and retry policy deliberately stay with the caller. The SDK performs
//! one-shot token exchanges; a retry inside the SDK would replay an
//! authorization code that the server has already consumed.

use std::fmt;

/// HTTP verbs the SDK issues. Deliberately minimal — a hosted-login client
/// never needs anything beyond GET and POST, and a closed enum keeps every
/// backend implementation honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// A fully-formed request. Built by the SDK, executed by a [`Transport`].
#[derive(Clone, Debug)]
pub struct TransportRequest {
    pub method: Method,
    pub url: String,
    /// Extra headers. The SDK always sets `Accept: application/json` and the
    /// no-store cache headers for credential endpoints; a backend may add more.
    pub headers: Vec<(String, String)>,
    /// `application/x-www-form-urlencoded` body (token endpoint).
    pub form: Option<Vec<(String, String)>>,
    /// `application/json` body (activation, account context).
    pub json: Option<serde_json::Value>,
    /// `Authorization: Bearer …`.
    pub bearer: Option<String>,
}

impl TransportRequest {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            form: None,
            json: None,
            bearer: None,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn form<I, K, V>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.form = Some(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        );
        self
    }

    pub fn json(mut self, body: serde_json::Value) -> Self {
        self.json = Some(body);
        self
    }

    pub fn bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }
}

/// A backend-agnostic response. Only the status and body are surfaced: the SDK
/// never needs redirects, cookies, or streaming.
#[derive(Clone, Debug)]
pub struct TransportResponse {
    pub status: u16,
    pub body: String,
}

impl TransportResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

/// Transport failure. Kept distinct from [`crate::SnaplinkError`] so a backend
/// can be swapped without the error taxonomy changing underneath callers.
#[derive(Debug)]
pub struct TransportError {
    message: String,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

/// The injectable network seam. `send` is the whole contract, which is what
/// makes the shape portable across the five SDKs.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError>;
}

/// Default backend: `reqwest`'s async client over rustls.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build with reqwest defaults. Use [`Self::with_client`] when the
    /// embedding application needs custom timeouts, proxies, or pool limits.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest default client configuration must be valid");
        Self::with_client(client)
    }

    /// Adopt a caller-configured client so timeouts, proxies, and connection
    /// pools are owned by the embedding application. Configure it not to follow
    /// redirects: authorization codes and bearer tokens must remain on-origin.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transport for ReqwestTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError> {
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(pairs) = &request.form {
            builder = builder.form(pairs);
        }
        if let Some(body) = &request.json {
            builder = builder.json(body);
        }
        if let Some(token) = &request.bearer {
            builder = builder.bearer_auth(token.as_str());
        }
        let response = builder
            .send()
            .await
            .map_err(|error| TransportError::new(error.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|error| TransportError::new(error.to_string()))?;
        Ok(TransportResponse::new(status, body))
    }
}

/// Optional reqwest blocking backend for CLI and script integrations. Calls
/// execute on Tokio's blocking pool; a Tokio runtime is still required to drive
/// this async transport. Behind the `blocking` feature only.
#[cfg(feature = "blocking")]
pub struct BlockingTransport {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "blocking")]
impl BlockingTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest default client configuration must be valid"),
        }
    }
}

#[cfg(feature = "blocking")]
impl Default for BlockingTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "blocking")]
#[async_trait::async_trait]
impl Transport for BlockingTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError> {
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(pairs) = &request.form {
            builder = builder.form(pairs);
        }
        if let Some(body) = &request.json {
            builder = builder.json(body);
        }
        if let Some(token) = &request.bearer {
            builder = builder.bearer_auth(token.as_str());
        }
        // The whole point of the adapter: get off the async runtime's thread
        // before blocking, so `blocking` and an async runtime can coexist.
        let task = tokio::task::spawn_blocking(move || {
            builder
                .send()
                .map_err(|error| TransportError::new(error.to_string()))
                .and_then(|response| {
                    let status = response.status().as_u16();
                    response
                        .text()
                        .map(|body| TransportResponse::new(status, body))
                        .map_err(|error| TransportError::new(error.to_string()))
                })
        });
        match task.await {
            Ok(result) => result,
            Err(error) => Err(TransportError::new(format!(
                "blocking transport task failed: {error}"
            ))),
        }
    }
}
