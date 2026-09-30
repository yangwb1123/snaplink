//! Explicit session lifecycle: refresh, logout, and the predicates around them.
//!
//! Refresh is an explicit call rather than something that happens behind the
//! scenes. An implicit renewal makes "which request fired, and when"
//! unobservable, which costs both test determinism and debuggability, so a
//! caller renews when it decides to. Every hosted-login SDK exposes these three
//! operations with the same meaning; native mobile refresh remains implicit.
//!
//! - [`SnaplinkClient::refresh`] renews the access token and rotates the refresh
//!   token.
//! - [`SnaplinkClient::logout`] revokes server-side state, then drops local
//!   state.
//! - [`SnaplinkClient::clear`] drops local state only, without pretending the
//!   server session ended.
//!
//! Logout and clear are deliberately distinct. A caller must be able to forget a
//! token locally without claiming the server session is gone, and must be able
//! to end the server session without pretending it had no local copy.

use crate::{
    parse_oauth_error, token_endpoint, MemoryStateStore, ReqwestTransport, SnaplinkClient,
    SnaplinkError, TokenResponse, Transport, TransportRequest,
};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Why a refresh could not be attempted.
fn login_required() -> SnaplinkError {
    SnaplinkError::InvalidRequest("login is required".to_owned())
}

impl SnaplinkClient {
    /// Restores a session from tokens the caller persisted.
    ///
    /// A native client that stored a token set across a restart comes back
    /// without a fresh login, then [`SnaplinkClient::refresh`] to rotate it. The
    /// caller owns storage; this crate never persists tokens itself.
    pub fn resume(
        base_url: &str,
        client_id: &str,
        tokens: TokenResponse,
    ) -> Result<Self, SnaplinkError> {
        let base_url = crate::login::validate_url(base_url, "base_url", false, false, false)?;
        if client_id.trim().is_empty() {
            return Err(SnaplinkError::InvalidRequest(
                "client_id is required".to_owned(),
            ));
        }
        if tokens.access_token.is_empty() {
            return Err(SnaplinkError::InvalidRequest(
                "an access token is required to resume a session".to_owned(),
            ));
        }
        Ok(Self::with_transport(
            Arc::new(MemoryStateStore::new()),
            Arc::new(ReqwestTransport::new()),
        )
        .with_resumed(base_url, client_id, tokens))
    }

    /// Same as [`SnaplinkClient::resume`] but with a caller-supplied transport,
    /// so a server can reuse one configured client (timeouts, pools) for
    /// login and refresh alike.
    pub fn resume_with_transport(
        base_url: &str,
        client_id: &str,
        tokens: TokenResponse,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, SnaplinkError> {
        let base_url = crate::login::validate_url(base_url, "base_url", false, false, false)?;
        if client_id.trim().is_empty() {
            return Err(SnaplinkError::InvalidRequest(
                "client_id is required".to_owned(),
            ));
        }
        if tokens.access_token.is_empty() {
            return Err(SnaplinkError::InvalidRequest(
                "an access token is required to resume a session".to_owned(),
            ));
        }
        Ok(
            Self::with_transport(Arc::new(MemoryStateStore::new()), transport)
                .with_resumed(base_url, client_id, tokens),
        )
    }

    fn with_resumed(mut self, base_url: Url, client_id: &str, tokens: TokenResponse) -> Self {
        self.base_url = Some(base_url);
        self.client_id = Some(client_id.to_owned());
        self.tokens = Some(tokens);
        self
    }

    /// Whether a refresh token is held, which is the precondition for
    /// [`SnaplinkClient::refresh`]. A session without one must log in again.
    pub fn can_refresh(&self) -> bool {
        self.tokens
            .as_ref()
            .is_some_and(|tokens| tokens.refresh_token.is_some())
    }

    /// The server-reported token lifetime, or zero when unknown.
    ///
    /// This is the original `expires_in` duration, not a decreasing countdown.
    /// Callers that need the remaining lifetime should record when the token
    /// response was received and compare that instant against this duration.
    pub fn expires_in(&self) -> Duration {
        self.tokens
            .as_ref()
            .map(|tokens| Duration::from_secs(tokens.expires_in.unwrap_or(0)))
            .unwrap_or_default()
    }

    /// Renews the access token using the refresh-token grant.
    ///
    /// The server rotates refresh tokens, so the response carries the
    /// replacement and the client adopts it. A refresh never carries a code
    /// verifier.
    ///
    /// An expired, revoked, or reused refresh token fails with the server's
    /// `invalid_grant`. Treat that as terminal for the session and log in again
    /// rather than retrying.
    pub async fn refresh(&mut self) -> Result<crate::TokenResponse, SnaplinkError> {
        let (refresh_token, client_id) = {
            let tokens = self.tokens.as_ref().ok_or_else(login_required)?;
            let refresh_token = tokens.refresh_token.clone().ok_or_else(login_required)?;
            (refresh_token, self.client_id.clone().unwrap_or_default())
        };
        let base_url = self.base_url.clone().ok_or_else(login_required)?;
        // The refresh grant is form-encoded and carries no code verifier, so it
        // goes straight through the transport rather than request_json (which
        // speaks JSON for the activation and account-context endpoints).
        let request =
            TransportRequest::new(crate::transport::Method::Post, token_endpoint(&base_url))
                .header("Accept", "application/json")
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .form([
                    ("grant_type", "refresh_token".to_owned()),
                    ("client_id", client_id),
                    ("refresh_token", refresh_token.clone()),
                ]);
        let response = self.transport.send(request).await?;
        let mut tokens: crate::TokenResponse = crate::decode_token(response)?;
        if tokens.refresh_token.is_none() {
            // A server that does not rotate must not cause the client to lose
            // the ability to refresh again.
            tokens.refresh_token = Some(refresh_token);
        }
        self.tokens = Some(tokens.clone());
        Ok(tokens)
    }

    /// Revokes the server-side session, then clears local state.
    ///
    /// The server call is best-effort: this client's in-memory state is cleared
    /// even when the request fails, because a caller asking to log out must end
    /// up logged out locally regardless. The returned error reports the server
    /// outcome. Callers that persist tokens themselves must delete that copy too.
    pub async fn logout(&mut self) -> Result<(), SnaplinkError> {
        let outcome = self.revoke_session().await;
        self.clear();
        outcome
    }

    /// Drops this client's in-memory session without contacting the server.
    ///
    /// Use this when the local copy must be forgotten but the server session
    /// should survive. Use [`SnaplinkClient::logout`] when it should end. The
    /// caller remains responsible for deleting any tokens it persisted itself.
    pub fn clear(&mut self) {
        self.tokens = None;
        self.account_context = None;
    }

    async fn revoke_session(&self) -> Result<(), SnaplinkError> {
        let (base_url, token) = match (self.base_url.as_ref(), &self.tokens) {
            (Some(base_url), Some(tokens)) if !tokens.access_token.is_empty() => {
                (base_url.clone(), tokens.access_token.clone())
            }
            _ => return Ok(()),
        };
        let endpoint = format!("{}/logout", base_url.as_str().trim_end_matches('/'));
        let request = TransportRequest::new(crate::transport::Method::Post, endpoint)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .header("Content-Type", "application/json")
            .bearer(token)
            .json(serde_json::json!({}));
        let response = self.transport.send(request).await?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(parse_oauth_error(response.status, &response.body))
        }
    }
}
