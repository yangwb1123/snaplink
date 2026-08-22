//! Framework-neutral Snaplink hosted login for public OAuth clients.
//!
//! The first login call returns the existing Console /login/ URL. The
//! callback call validates state and issuer, then exchanges the authorization
//! code with S256 PKCE. A web framework only needs to issue the redirect and
//! pass the callback URL back to this client; no BFF is required.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use url::{form_urlencoded, Url};

const DEFAULT_TRANSACTION_TTL: Duration = Duration::from_secs(600);

/// Public-client login configuration. There is deliberately no client secret.
#[derive(Clone, Debug)]
pub struct LoginOptions {
    pub base_url: String,
    pub client_id: String,
    pub login_page_url: Option<String>,
    pub redirect_uri: String,
    pub return_to: Option<String>,
    pub scope: Vec<String>,
    pub resource: Vec<String>,
    pub prompt: Option<String>,
    pub max_age: Option<u64>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
    pub ui_locales: Option<String>,
    pub callback_url: Option<String>,
    pub allow_insecure_http_for_development: bool,
    pub transaction_ttl: Option<Duration>,
}

impl LoginOptions {
    /// Create the minimum configuration for the hosted-login flow.
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            client_id: client_id.into(),
            login_page_url: None,
            redirect_uri: redirect_uri.into(),
            return_to: None,
            scope: Vec::new(),
            resource: Vec::new(),
            prompt: None,
            max_age: None,
            login_hint: None,
            acr_values: None,
            ui_locales: None,
            callback_url: None,
            allow_insecure_http_for_development: false,
            transaction_ttl: None,
        }
    }

    pub fn login_page_url(mut self, value: impl Into<String>) -> Self {
        self.login_page_url = Some(value.into());
        self
    }

    pub fn return_to(mut self, value: impl Into<String>) -> Self {
        self.return_to = Some(value.into());
        self
    }

    pub fn scope<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scope = values.into_iter().map(Into::into).collect();
        self
    }

    pub fn resource<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resource = values.into_iter().map(Into::into).collect();
        self
    }

    pub fn prompt(mut self, value: impl Into<String>) -> Self {
        self.prompt = Some(value.into());
        self
    }

    pub fn max_age(mut self, value: u64) -> Self {
        self.max_age = Some(value);
        self
    }

    pub fn login_hint(mut self, value: impl Into<String>) -> Self {
        self.login_hint = Some(value.into());
        self
    }

    pub fn acr_values(mut self, value: impl Into<String>) -> Self {
        self.acr_values = Some(value.into());
        self
    }

    pub fn ui_locales(mut self, value: impl Into<String>) -> Self {
        self.ui_locales = Some(value.into());
        self
    }

    pub fn callback_url(mut self, value: impl Into<String>) -> Self {
        self.callback_url = Some(value.into());
        self
    }

    pub fn allow_insecure_http_for_development(mut self, value: bool) -> Self {
        self.allow_insecure_http_for_development = value;
        self
    }

    pub fn transaction_ttl(mut self, value: Duration) -> Self {
        self.transaction_ttl = Some(value);
        self
    }
}

/// Successful OAuth/OIDC token response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    pub token_type: String,
}

/// Result of starting or completing hosted login.
#[derive(Clone, Debug)]
pub enum LoginResult {
    Redirect {
        url: String,
        return_to: String,
    },
    Complete {
        tokens: TokenResponse,
        return_to: String,
    },
}

impl LoginResult {
    pub fn redirect_url(&self) -> Option<&str> {
        match self {
            Self::Redirect { url, .. } => Some(url),
            Self::Complete { .. } => None,
        }
    }

    pub fn tokens(&self) -> Option<&TokenResponse> {
        match self {
            Self::Redirect { .. } => None,
            Self::Complete { tokens, .. } => Some(tokens),
        }
    }

    pub fn return_to(&self) -> &str {
        match self {
            Self::Redirect { return_to, .. } | Self::Complete { return_to, .. } => return_to,
        }
    }
}

/// Atomic short-lived transaction storage.
pub trait StateStore: Send + Sync {
    fn take(&self, key: &str) -> Result<Option<Vec<u8>>, SnaplinkError>;
    fn save(&self, key: &str, value: &[u8]) -> Result<(), SnaplinkError>;
}

/// In-process state storage for development and single-process examples.
#[derive(Clone, Default)]
pub struct MemoryStateStore {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStateStore {
    fn take(&self, key: &str) -> Result<Option<Vec<u8>>, SnaplinkError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| SnaplinkError::State("state store lock was poisoned".into()))?;
        Ok(values.remove(key))
    }

    fn save(&self, key: &str, value: &[u8]) -> Result<(), SnaplinkError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| SnaplinkError::State("state store lock was poisoned".into()))?;
        values.insert(key.to_owned(), value.to_vec());
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SnaplinkError {
    #[error("invalid hosted-login request: {0}")]
    InvalidRequest(String),
    #[error("state storage failed: {0}")]
    State(String),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OAuth token endpoint returned {status}: {code}: {description}")]
    OAuth {
        status: u16,
        code: String,
        description: String,
    },
}

/// Public-client hosted-login session.
pub struct SnaplinkClient {
    store: Arc<dyn StateStore>,
    http_client: HttpClient,
    base_url: Option<Url>,
    client_id: Option<String>,
    tokens: Option<TokenResponse>,
}

impl Default for SnaplinkClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SnaplinkClient {
    pub fn new() -> Self {
        Self::with_store(Arc::new(MemoryStateStore::new()))
    }

    pub fn with_store(store: Arc<dyn StateStore>) -> Self {
        Self::with_http_client(store, HttpClient::new())
    }

    pub fn with_http_client(store: Arc<dyn StateStore>, http_client: HttpClient) -> Self {
        Self {
            store,
            http_client,
            base_url: None,
            client_id: None,
            tokens: None,
        }
    }

    /// Start hosted login or complete a callback supplied in the options.
    pub fn login(&mut self, options: &LoginOptions) -> Result<LoginResult, SnaplinkError> {
        let resolved = resolve_options(options)?;
        if self.base_url.as_ref() != Some(&resolved.base_url)
            || self.client_id.as_deref() != Some(resolved.client_id.as_str())
        {
            self.tokens = None;
            self.base_url = Some(resolved.base_url.clone());
            self.client_id = Some(resolved.client_id.clone());
        }
        if let Some(callback_url) = options.callback_url.as_deref() {
            return self.finish(&resolved, callback_url);
        }
        if let Some(tokens) = &self.tokens {
            return Ok(LoginResult::Complete {
                tokens: tokens.clone(),
                return_to: resolved.return_to.to_string(),
            });
        }
        self.start(&resolved)
    }

    pub fn access_token(&self) -> Option<&str> {
        self.tokens
            .as_ref()
            .map(|value| value.access_token.as_str())
    }

    pub fn is_logged_in(&self) -> bool {
        self.tokens
            .as_ref()
            .is_some_and(|value| !value.access_token.is_empty())
    }

    pub fn clear(&mut self) {
        self.tokens = None;
    }

    fn start(&self, options: &ResolvedOptions) -> Result<LoginResult, SnaplinkError> {
        let (code_verifier, code_challenge) = create_pkce();
        let transaction = LoginTransaction {
            base_url: canonical_url(&options.base_url),
            client_id: options.client_id.clone(),
            code_verifier,
            created_at: now_seconds()?,
            redirect_uri: options.redirect_uri.to_string(),
            return_to: options.return_to.to_string(),
            state: random_urlsafe(32),
        };
        let key = store_key(&options.client_id);
        self.store.save(&key, &serde_json::to_vec(&transaction)?)?;
        let url = match build_login_url(options, &transaction.state, &code_challenge) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.store.take(&key);
                return Err(error);
            }
        };
        Ok(LoginResult::Redirect {
            url,
            return_to: options.return_to.to_string(),
        })
    }

    fn finish(
        &mut self,
        options: &ResolvedOptions,
        callback_url: &str,
    ) -> Result<LoginResult, SnaplinkError> {
        let response = parse_callback(callback_url, &options.redirect_uri)?;
        let key = store_key(&options.client_id);
        let raw = self
            .store
            .take(&key)?
            .ok_or_else(|| invalid("hosted-login transaction is missing or expired"))?;
        let transaction: LoginTransaction = serde_json::from_slice(&raw)?;
        if now_seconds()?.saturating_sub(transaction.created_at) > options.ttl.as_secs() {
            return Err(invalid("hosted-login transaction is missing or expired"));
        }
        if transaction.client_id != options.client_id
            || transaction.base_url != canonical_url(&options.base_url)
        {
            return Err(invalid(
                "hosted-login transaction belongs to another client",
            ));
        }
        if response.state != transaction.state {
            return Err(invalid("hosted-login state did not match"));
        }
        if response.issuer.is_empty() || canonical_url_str(&response.issuer) != transaction.base_url
        {
            return Err(invalid("authorization issuer did not match Snaplink"));
        }
        if response.code.is_some() && response.error.is_some() {
            return Err(invalid(
                "authorization response contained both code and error",
            ));
        }
        if let Some(error) = response.error {
            return Err(SnaplinkError::OAuth {
                status: 0,
                code: error,
                description: response.error_description.unwrap_or_default(),
            });
        }
        let code = response
            .code
            .ok_or_else(|| invalid("authorization response did not contain a code"))?;
        let tokens = self.exchange(options, &transaction, &code)?;
        self.tokens = Some(tokens.clone());
        Ok(LoginResult::Complete {
            tokens,
            return_to: transaction.return_to,
        })
    }

    fn exchange(
        &self,
        options: &ResolvedOptions,
        transaction: &LoginTransaction,
        code: &str,
    ) -> Result<TokenResponse, SnaplinkError> {
        let endpoint = token_endpoint(&options.base_url);
        let form = [
            ("grant_type", "authorization_code"),
            ("client_id", transaction.client_id.as_str()),
            ("code", code),
            ("code_verifier", transaction.code_verifier.as_str()),
            ("redirect_uri", transaction.redirect_uri.as_str()),
        ];
        let response = self
            .http_client
            .post(endpoint)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .form(&form)
            .send()?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            return Err(parse_oauth_error(status, &body));
        }
        Ok(response.json()?)
    }
}

#[derive(Clone)]
struct ResolvedOptions {
    base_url: Url,
    client_id: String,
    login_page_url: Url,
    redirect_uri: Url,
    return_to: Url,
    scope: Vec<String>,
    resource: Vec<String>,
    prompt: Option<String>,
    max_age: Option<u64>,
    login_hint: Option<String>,
    acr_values: Option<String>,
    ui_locales: Option<String>,
    ttl: Duration,
}

#[derive(Deserialize, Serialize)]
struct LoginTransaction {
    base_url: String,
    client_id: String,
    code_verifier: String,
    created_at: u64,
    redirect_uri: String,
    return_to: String,
    state: String,
}

struct Callback {
    code: Option<String>,
    state: String,
    issuer: String,
    error: Option<String>,
    error_description: Option<String>,
}

fn resolve_options(options: &LoginOptions) -> Result<ResolvedOptions, SnaplinkError> {
    let base_url = validate_url(
        &options.base_url,
        "base_url",
        false,
        false,
        options.allow_insecure_http_for_development,
    )?;
    if options.client_id.trim().is_empty() {
        return Err(invalid("client_id is required"));
    }
    let redirect_uri = validate_url(
        &options.redirect_uri,
        "redirect_uri",
        true,
        false,
        options.allow_insecure_http_for_development,
    )?;
    let return_to = match &options.return_to {
        Some(value) => validate_url(
            value,
            "return_to",
            true,
            true,
            options.allow_insecure_http_for_development,
        )?,
        None => redirect_uri.clone(),
    };
    if !same_origin(&return_to, &redirect_uri) {
        return Err(invalid("return_to must use the redirect URI origin"));
    }
    let login_page_url = match &options.login_page_url {
        Some(value) => validate_url(
            value,
            "login_page_url",
            true,
            false,
            options.allow_insecure_http_for_development,
        )?,
        None => login_page_from_base(&base_url),
    };
    let scope = if options.scope.is_empty() {
        vec!["openid".into(), "profile".into(), "email".into()]
    } else {
        options.scope.clone()
    };
    validate_values(&scope, "scope")?;
    validate_values(&options.resource, "resource")?;
    let ttl = options.transaction_ttl.unwrap_or(DEFAULT_TRANSACTION_TTL);
    if ttl.is_zero() {
        return Err(invalid("transaction_ttl must be positive"));
    }
    Ok(ResolvedOptions {
        base_url,
        client_id: options.client_id.clone(),
        login_page_url,
        redirect_uri,
        return_to,
        scope,
        resource: options.resource.clone(),
        prompt: options.prompt.clone(),
        max_age: options.max_age,
        login_hint: options.login_hint.clone(),
        acr_values: options.acr_values.clone(),
        ui_locales: options.ui_locales.clone(),
        ttl,
    })
}

fn build_login_url(
    options: &ResolvedOptions,
    state: &str,
    code_challenge: &str,
) -> Result<String, SnaplinkError> {
    let managed = [
        "client_id",
        "redirect_uri",
        "response_type",
        "response_mode",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "resource",
        "prompt",
        "max_age",
        "login_hint",
        "acr_values",
        "ui_locales",
    ];
    let mut pairs = options
        .login_page_url
        .query_pairs()
        .filter(|(key, _)| !managed.contains(&key.as_ref()))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.extend([
        ("client_id".into(), options.client_id.clone()),
        ("redirect_uri".into(), options.redirect_uri.to_string()),
        ("response_type".into(), "code".into()),
        ("response_mode".into(), "query".into()),
        ("scope".into(), options.scope.join(" ")),
        ("state".into(), state.into()),
        ("code_challenge".into(), code_challenge.into()),
        ("code_challenge_method".into(), "S256".into()),
    ]);
    for resource in &options.resource {
        pairs.push(("resource".into(), resource.clone()));
    }
    append_optional(&mut pairs, "prompt", options.prompt.as_deref());
    append_optional(&mut pairs, "login_hint", options.login_hint.as_deref());
    append_optional(&mut pairs, "acr_values", options.acr_values.as_deref());
    append_optional(&mut pairs, "ui_locales", options.ui_locales.as_deref());
    if let Some(max_age) = options.max_age {
        pairs.push(("max_age".into(), max_age.to_string()));
    }
    let mut login_url = options.login_page_url.clone();
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        query.append_pair(&key, &value);
    }
    login_url.set_query(Some(&query.finish()));
    login_url.set_fragment(None);
    Ok(login_url.to_string())
}

fn append_optional(pairs: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        pairs.push((key.into(), value.into()));
    }
}

fn parse_callback(raw: &str, redirect_uri: &Url) -> Result<Callback, SnaplinkError> {
    let callback_url =
        Url::parse(raw).map_err(|_| invalid("callback_url must be an absolute HTTP(S) URL"))?;
    if canonical_url(&callback_url) != canonical_url(redirect_uri) {
        return Err(invalid("callback_url does not match redirect_uri"));
    }
    let mut values = HashMap::new();
    for (key, value) in callback_url.query_pairs() {
        values.entry(key.into_owned()).or_insert(value.into_owned());
    }
    Ok(Callback {
        code: values.get("code").cloned(),
        state: values.get("state").cloned().unwrap_or_default(),
        issuer: values.get("iss").cloned().unwrap_or_default(),
        error: values.get("error").cloned(),
        error_description: values.get("error_description").cloned(),
    })
}

fn parse_oauth_error(status: u16, body: &str) -> SnaplinkError {
    #[derive(Deserialize, Default)]
    struct ErrorBody {
        error: Option<String>,
        error_description: Option<String>,
    }
    let parsed = serde_json::from_str::<ErrorBody>(body).unwrap_or_default();
    SnaplinkError::OAuth {
        status,
        code: parsed.error.unwrap_or_default(),
        description: parsed.error_description.unwrap_or_default(),
    }
}

fn token_endpoint(base_url: &Url) -> Url {
    let mut endpoint = base_url.clone();
    let path = format!("{}/token", base_url.path().trim_end_matches('/'));
    endpoint.set_path(&path);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
}

fn login_page_from_base(base_url: &Url) -> Url {
    let mut page = base_url.clone();
    let path = format!("{}/login/", base_url.path().trim_end_matches('/'));
    page.set_path(&path);
    page
}

fn validate_url(
    raw: &str,
    name: &str,
    allow_query: bool,
    allow_fragment: bool,
    allow_insecure: bool,
) -> Result<Url, SnaplinkError> {
    let url =
        Url::parse(raw).map_err(|_| invalid(&format!("{name} must be an absolute HTTP(S) URL")))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid(&format!("{name} must be an absolute HTTP(S) URL")))?;
    if url.username() != "" || url.password().is_some() {
        return Err(invalid(&format!("{name} must not contain credentials")));
    }
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http" && is_loopback(host);
    if !secure && !(loopback_http || (allow_insecure && url.scheme() == "http")) {
        return Err(invalid(&format!("{name} must use HTTPS or loopback HTTP")));
    }
    if !allow_query && url.query().is_some() {
        return Err(invalid(&format!("{name} must not contain a query")));
    }
    if !allow_fragment && url.fragment().is_some() {
        return Err(invalid(&format!("{name} must not contain a fragment")));
    }
    Ok(url)
}

fn validate_values(values: &[String], name: &str) -> Result<(), SnaplinkError> {
    if values
        .iter()
        .any(|value| value.is_empty() || value.chars().any(|character| character.is_whitespace()))
    {
        return Err(invalid(&format!(
            "{name} values must be non-empty and whitespace-free"
        )));
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn is_loopback(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().trim_matches(['[', ']']),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn canonical_url(url: &Url) -> String {
    let mut value = url.clone();
    value.set_query(None);
    value.set_fragment(None);
    let path = value.path().trim_end_matches('/').to_owned();
    value.set_path(&path);
    value.to_string()
}

fn canonical_url_str(raw: &str) -> String {
    Url::parse(raw)
        .map(|value| canonical_url(&value))
        .unwrap_or_default()
}

fn create_pkce() -> (String, String) {
    let verifier = random_urlsafe(64);
    let digest = Sha256::digest(verifier.as_bytes());
    (verifier, URL_SAFE_NO_PAD.encode(digest))
}

fn random_urlsafe(size: usize) -> String {
    let mut bytes = vec![0; size];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_seconds() -> Result<u64, SnaplinkError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| invalid("system clock is before the Unix epoch"))
}

fn store_key(client_id: &str) -> String {
    let encoded = form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>();
    format!("snaplink.login.v1:{encoded}")
}

fn invalid(message: &str) -> SnaplinkError {
    SnaplinkError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn redirect_then_callback_exchanges_pkce_without_a_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base_url = format!("http://{}", listener.local_addr().expect("address"));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = [0_u8; 8192];
            let size = stream.read(&mut buffer).expect("read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.starts_with("POST /token "));
            let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
            let form = form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect::<HashMap<_, _>>();
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("authorization_code")
            );
            assert!(!form.contains_key("client_secret"));
            assert!(form
                .get("code_verifier")
                .is_some_and(|value| value.len() >= 43));
            let response = br#"{"access_token":"access-1","expires_in":900,"token_type":"Bearer"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                String::from_utf8_lossy(response)
            )
            .expect("write");
        });

        let mut client = SnaplinkClient::new();
        let options = LoginOptions::new(
            &base_url,
            "spa-client",
            "http://app.example.test/auth/callback",
        )
        .return_to("http://app.example.test/dashboard")
        .allow_insecure_http_for_development(true);
        let started = client.login(&options).expect("start");
        let redirect = Url::parse(started.redirect_url().expect("redirect")).expect("URL");
        assert_eq!(redirect.path(), "/login/");
        assert_eq!(
            redirect
                .query_pairs()
                .find(|(key, _)| key == "response_type")
                .map(|(_, value)| value),
            Some("code".into())
        );
        let callback = format!(
            "{}?code=code-1&state={}&iss={}",
            options.redirect_uri,
            urlencoding(&redirect, "state"),
            urlencoding_raw(&base_url)
        );
        let completed = client
            .login(&options.clone().callback_url(callback))
            .expect("complete");
        assert_eq!(completed.tokens().expect("tokens").access_token, "access-1");
        server.join().expect("server");
    }

    #[test]
    fn state_mismatch_is_rejected_before_exchange() {
        let mut client = SnaplinkClient::new();
        let options = LoginOptions::new(
            "https://sso.example.test",
            "spa-client",
            "https://app.example.test/callback",
        );
        client.login(&options).expect("start");
        let callback = options.callback_url(
            "https://app.example.test/callback?code=code-1&state=wrong&iss=https%3A%2F%2Fsso.example.test",
        );
        assert!(matches!(
            client.login(&callback),
            Err(SnaplinkError::InvalidRequest(message))
                if message.contains("state did not match")
        ));
    }

    fn urlencoding(url: &Url, key: &str) -> String {
        url.query_pairs()
            .find(|(name, _)| name == key)
            .map(|(_, value)| urlencoding_raw(&value))
            .expect("query parameter")
    }

    fn urlencoding_raw(value: &str) -> String {
        form_urlencoded::Serializer::new(String::new())
            .append_pair("value", value)
            .finish()
            .trim_start_matches("value=")
            .to_string()
    }
}
