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
#[cfg(feature = "blocking")]
pub use transport::BlockingTransport;
pub use transport::{
    Method, ReqwestTransport, Transport, TransportError, TransportRequest, TransportResponse,
};

pub(crate) use login::{decode_token, parse_oauth_error, token_endpoint};
