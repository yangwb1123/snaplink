//! Typed commercial entitlement for the Snaplink hosted-login SDK.
//!
//! The server is always the authority on what a tenant may do; this module
//! exists so a caller never has to know the wire shape of an entitlement in
//! order to decide whether a feature is available, and so a lapsed entitlement
//! is never mistaken for a live one.
//!
//! [`Entitlement::state_at`] reproduces `commerce.EntitlementSnapshot.effective`
//! exactly: an entitlement is effective only when `active` is set, `now` is not
//! before `effective_at`, and `expires_at` is unset or strictly after `now`.
//! A presence check cannot make that distinction, which is why
//! [`LicenseState`] has three variants rather than an `Option`.
//!
//! Timestamps are parsed from the RFC 3339 form Go's `time.Time` serialises and
//! are held internally as Unix seconds, so a comparison never depends on a
//! calendar library being correct in two places.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// Stable product capability identifiers, mirroring `commerce.FeatureKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// Core single-tenant SSO.
    CoreSso,
    /// Multi-tenant isolation.
    MultiTenant,
    /// Tenant-facing audit governance, export, and retention.
    AuditGovernance,
    /// Account notifications.
    Notifications,
    /// Instant messaging.
    Im,
    /// Account service.
    Account,
    /// File vault.
    Vault,
    /// SCIM provisioning.
    Scim,
    /// Identity federation.
    Federation,
    /// High-availability topology.
    HighAvailability,
}

impl Feature {
    /// Every feature key the server currently defines, in declaration order.
    pub const ALL: [Feature; 10] = [
        Feature::CoreSso,
        Feature::MultiTenant,
        Feature::AuditGovernance,
        Feature::Notifications,
        Feature::Im,
        Feature::Account,
        Feature::Vault,
        Feature::Scim,
        Feature::Federation,
        Feature::HighAvailability,
    ];

    /// The wire key for this feature.
    pub fn as_str(self) -> &'static str {
        match self {
            Feature::CoreSso => "core_sso",
            Feature::MultiTenant => "multi_tenant",
            Feature::AuditGovernance => "audit_governance",
            Feature::Notifications => "notifications",
            Feature::Im => "im",
            Feature::Account => "account",
            Feature::Vault => "vault",
            Feature::Scim => "scim",
            Feature::Federation => "federation",
            Feature::HighAvailability => "high_availability",
        }
    }

    /// Resolve a wire key, or `None` when the server defines a key this build
    /// predates. An unknown key grants nothing.
    pub fn from_key(key: &str) -> Option<Feature> {
        Feature::ALL.into_iter().find(|feature| feature.as_str() == key)
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable quota dimensions, mirroring `commerce.LimitKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Limit {
    /// Stored tenant users.
    Users,
    /// OAuth clients.
    Clients,
    /// Concurrent sessions.
    Sessions,
    /// Token issue rate, per second.
    TokenRate,
    /// Vault storage bytes.
    StorageBytes,
    /// Vault objects.
    StorageObjects,
}

impl Limit {
    /// Every limit key the server currently defines, in declaration order.
    pub const ALL: [Limit; 6] = [
        Limit::Users,
        Limit::Clients,
        Limit::Sessions,
        Limit::TokenRate,
        Limit::StorageBytes,
        Limit::StorageObjects,
    ];

    /// The wire key for this limit.
    pub fn as_str(self) -> &'static str {
        match self {
            Limit::Users => "users",
            Limit::Clients => "clients",
            Limit::Sessions => "sessions",
            Limit::TokenRate => "token_rate",
            Limit::StorageBytes => "storage_bytes",
            Limit::StorageObjects => "storage_objects",
        }
    }

    /// Resolve a wire key, or `None` when this build predates the key.
    pub fn from_key(key: &str) -> Option<Limit> {
        Limit::ALL.into_iter().find(|limit| limit.as_str() == key)
    }
}

impl std::fmt::Display for Limit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A soft threshold and a hard safety limit, mirroring `commerce.LimitGrant`.
///
/// `unlimited` short-circuits the pair: a grant that is unlimited reports zero
/// for both thresholds, so a caller that reads `soft` alone would see a bogus
/// number. Always read it through [`LimitGrant::is_unlimited`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitGrant {
    /// Included threshold used for warnings and commercial review.
    pub soft: i64,
    /// Safety limit enforced by the service that owns the resource.
    pub hard: i64,
    /// The dimension has no ceiling for this tenant.
    #[serde(default)]
    pub unlimited: bool,
}

impl LimitGrant {
    /// Whether the dimension is unbounded.
    pub fn is_unlimited(self) -> bool {
        self.unlimited
    }
}

/// A plan identifier and version, mirroring `commerce.PlanRef`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRef {
    /// Stable plan identifier.
    #[serde(default)]
    pub id: String,
    /// Immutable published plan version.
    #[serde(default)]
    pub version: u64,
}

/// Why an entitlement is present but not usable.
///
/// Presentation only. It must never drive retry or authorization behaviour:
/// the server collapses distinct internal causes into one wire code, and a
/// client that branches on the reason would leak the distinction the server
/// deliberately hides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InactiveReason {
    /// The entitlement's effective window has not opened yet.
    NotYetEffective,
    /// The entitlement's window has closed.
    Expired,
    /// The server marked the entitlement inactive.
    Suspended,
}

impl InactiveReason {
    /// A stable label for display and telemetry.
    pub fn as_str(self) -> &'static str {
        match self {
            InactiveReason::NotYetEffective => "not_yet_effective",
            InactiveReason::Expired => "expired",
            InactiveReason::Suspended => "suspended",
        }
    }
}

impl std::fmt::Display for InactiveReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The three states a product licence can be in.
///
/// A two-state `Option` cannot tell "never activated" from "activated once but
/// lapsed", and those need different copy and different follow-up actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LicenseState {
    /// No product-to-tenant binding exists.
    NotActivated,
    /// A binding exists but grants nothing right now.
    Inactive {
        /// Why it grants nothing.
        reason: InactiveReason,
        /// Unix seconds at which the window closed, when one applies.
        until: Option<i64>,
    },
    /// Grants are live now.
    Active(Box<Entitlement>),
}

impl LicenseState {
    /// Whether grants are live. The only question a feature gate should ask.
    pub fn is_active(&self) -> bool {
        matches!(self, LicenseState::Active(_))
    }

    /// The entitlement, but only when grants are live.
    pub fn entitlement(&self) -> Option<&Entitlement> {
        match self {
            LicenseState::Active(entitlement) => Some(entitlement),
            _ => None,
        }
    }

    /// Why grants are unavailable, for display.
    pub fn inactive_reason(&self) -> Option<InactiveReason> {
        match self {
            LicenseState::Inactive { reason, .. } => Some(*reason),
            _ => None,
        }
    }
}

/// A server-derived commercial entitlement snapshot.
///
/// Construction is internal; callers obtain one from
/// [`crate::AccountContext`]. Feature and limit maps are stored under their
/// wire keys so a key this build predates is preserved rather than dropped,
/// while lookups stay type-safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entitlement {
    /// Tenant the entitlement binds.
    #[serde(default)]
    pub tenant_id: String,
    /// Subscription that produced the entitlement.
    #[serde(default)]
    pub subscription_id: String,
    /// Plan and version in force.
    #[serde(default)]
    pub plan: PlanRef,
    /// Monotonic revision, usable as a cache-invalidation key.
    #[serde(default)]
    pub revision: u64,
    /// Whether the server considers the subscription live.
    #[serde(default)]
    pub active: bool,
    /// Feature grants keyed by wire key.
    #[serde(default)]
    pub features: BTreeMap<String, bool>,
    /// Limit grants keyed by wire key.
    #[serde(default)]
    pub limits: BTreeMap<String, LimitGrant>,
    /// Unix seconds at which the window opens.
    #[serde(default, deserialize_with = "de_timestamp")]
    pub effective_at: i64,
    /// Unix seconds at which the window closes, when bounded.
    #[serde(default, deserialize_with = "de_optional_timestamp")]
    pub expires_at: Option<i64>,
    /// Unix seconds at which the server generated the snapshot.
    #[serde(default, deserialize_with = "de_timestamp")]
    pub generated_at: i64,
}

impl Entitlement {
    /// Classify the entitlement at `now`, given in Unix seconds.
    ///
    /// Mirrors `commerce.EntitlementSnapshot.effective` exactly: the
    /// `expires_at` boundary is exclusive, so an entitlement whose window
    /// closes at `t` is already inactive at `t`.
    pub fn state_at(&self, now: i64) -> LicenseState {
        if !self.active {
            return LicenseState::Inactive {
                reason: InactiveReason::Suspended,
                until: self.expires_at,
            };
        }
        if now < self.effective_at {
            return LicenseState::Inactive {
                reason: InactiveReason::NotYetEffective,
                until: None,
            };
        }
        if let Some(expires_at) = self.expires_at {
            if now >= expires_at {
                return LicenseState::Inactive {
                    reason: InactiveReason::Expired,
                    until: Some(expires_at),
                };
            }
        }
        LicenseState::Active(Box::new(self.clone()))
    }

    /// Whether `feature` is granted at `now`.
    ///
    /// Returns false for an inactive entitlement regardless of what the map
    /// says, and false for a key this build does not recognise.
    pub fn has(&self, feature: Feature, now: i64) -> bool {
        if !self.state_at(now).is_active() {
            return false;
        }
        self.features.get(feature.as_str()).copied().unwrap_or(false)
    }

    /// The grant for `limit` at `now`, or `None` when inactive or absent.
    pub fn limit(&self, limit: Limit, now: i64) -> Option<LimitGrant> {
        if !self.state_at(now).is_active() {
            return None;
        }
        self.limits.get(limit.as_str()).copied()
    }

    /// Feature keys the server sent that this build does not recognise.
    ///
    /// Surfaced so an operator can see that a plan grants something the SDK
    /// cannot yet gate, instead of silently ignoring it.
    pub fn unknown_features(&self) -> impl Iterator<Item = &str> {
        self.features
            .keys()
            .map(String::as_str)
            .filter(|key| Feature::from_key(key).is_none())
    }

    /// Limit keys the server sent that this build does not recognise.
    pub fn unknown_limits(&self) -> impl Iterator<Item = &str> {
        self.limits
            .keys()
            .map(String::as_str)
            .filter(|key| Limit::from_key(key).is_none())
    }
}

/// Accepts an RFC 3339 timestamp, a Unix-seconds integer, or null.
fn de_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<serde_json::Value>::deserialize(deserializer)?;
    parse_timestamp(raw).ok_or_else(|| D::Error::custom("expected an RFC 3339 timestamp or Unix seconds"))
}

/// Same as [`de_timestamp`] but preserves an absent or zero expiry as `None`.
fn de_optional_timestamp<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(parse_timestamp(raw))
}

/// Go serialises `time.Time` as RFC 3339; an integer is accepted so a fixture or
/// a hand-written entitlement file can use Unix seconds directly.
fn parse_timestamp(raw: Option<serde_json::Value>) -> Option<i64> {
    match raw? {
        serde_json::Value::Null => None,
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(text) => {
            if text.trim().is_empty() {
                return None;
            }
            chrono::DateTime::parse_from_rfc3339(&text)
                .ok()
                .map(|parsed| parsed.timestamp())
        }
        _ => None,
    }
}

/// Current time in Unix seconds, the clock the state helpers expect.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
