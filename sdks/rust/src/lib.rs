//! Framework-neutral Snaplink hosted login for public OAuth clients.
//!
//! The first login call returns the existing Console /login/ URL. The
//! callback call validates state and issuer, then exchanges the authorization
//! code with S256 PKCE. A web framework only needs to issue the redirect and
//! pass the callback URL back to this client; no BFF is required.

mod entitlement;
mod error;
mod license_file;
mod login;
mod preferences;
mod session;
mod state;
mod transport;

/// SDK-originated code for a failure response that carried no usable error
/// code.
///
/// A caller that matches on [`SnaplinkError::OAuth`]'s `code` never receives an
/// empty string, and a server code is never invented for such a response: an
/// unreadable 500 must not look like a terminal `invalid_grant`. The `sdk_`
/// prefix keeps it out of the server vocabulary in `docs/error-codes.md`.
pub const UNCLASSIFIED_ERROR: &str = "sdk_response_unclassified";

pub use entitlement::{
    unix_now, Entitlement, Feature, InactiveReason, LicenseState, Limit, LimitGrant, PlanRef,
};
pub use error::SnaplinkError;
pub use license_file::{EntitlementFile, LicenseError, LicenseTrust};
pub use login::{
    AccountContext, ActivationPreparation, LoginOptions, LoginResult, LoginSetupOptions,
    SetupOptions, SnaplinkClient, TokenResponse,
};
pub use preferences::{
    build_login_preference_handoff, from_stored_preferences, to_update_request, PreferenceError,
    PresentationPreferences, PresentationPreferencesPatch, ThemeMode,
};
pub use state::{MemoryStateStore, StateStore};

/// Classify a failure response the way this crate's own transport does.
///
/// A caller that injects a custom [`Transport`] receives the raw response and
/// must turn it into an error; using this function keeps the code and status
/// classification identical to the built-in one, including the
/// [`UNCLASSIFIED_ERROR`] fallback for a response that carried no code.
pub fn error_from_response(status: u16, body: &str) -> SnaplinkError {
    parse_oauth_error(status, body)
}
#[cfg(feature = "blocking")]
pub use transport::BlockingTransport;
pub use transport::{
    Method, ReqwestTransport, Transport, TransportError, TransportRequest, TransportResponse,
};

pub(crate) use login::{decode_token, parse_oauth_error, token_endpoint};
