use thiserror::Error;

use crate::TransportError;

/// Errors returned by the hosted-login SDK.
#[derive(Debug, Error)]
pub enum SnaplinkError {
    #[error("invalid hosted-login request: {0}")]
    InvalidRequest(String),
    #[error("state storage failed: {0}")]
    State(String),
    #[error("transport failed: {0}")]
    Http(#[from] TransportError),
    #[error("JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OAuth token endpoint returned {status}: {code}: {description}")]
    OAuth {
        status: u16,
        code: String,
        description: String,
    },
}
