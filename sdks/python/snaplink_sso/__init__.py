"""Public package for the Snaplink HTTP SDK."""

from .client import AsyncSSOClient, AsyncTransport, AsyncioTransport, SSOClient, SSOError
from .entitlement import (
    Entitlement,
    Feature,
    InactiveReason,
    Limit,
    LicenseState,
    LicenseStateKind,
    LimitGrant,
    PlanRef,
    entitlement_from_account_context,
    has_feature,
    license_state_from_account_context,
    unix_now,
)
from .hosted_login import LoginResult, MemoryStateStore, Snaplink, StateStore, snaplink
from .hosted_login_async import AsyncSnaplink, async_snaplink
from .license_file import (
    EntitlementFile,
    LicenseError,
    LicenseTrust,
    LicenseVerifier,
    license_trust_from_key,
    vendor_pinned_trust,
    verify_license_file,
)
from .preferences import (
    PresentationPreferences,
    PresentationPreferencesPatch,
    SnaplinkUserPreferencesClient,
    build_login_preference_handoff,
)

__all__ = [
    "AsyncSnaplink",
    "AsyncSSOClient",
    "AsyncTransport",
    "AsyncioTransport",
    "LoginResult",
    "MemoryStateStore",
    "Snaplink",
    "SSOClient",
    "SSOError",
    "StateStore",
    "async_snaplink",
    "Entitlement",
    "EntitlementFile",
    "Feature",
    "InactiveReason",
    "LicenseError",
    "LicenseState",
    "LicenseStateKind",
    "LicenseTrust",
    "LicenseVerifier",
    "Limit",
    "LimitGrant",
    "PlanRef",
    "PresentationPreferences",
    "PresentationPreferencesPatch",
    "SnaplinkUserPreferencesClient",
    "build_login_preference_handoff",
    "entitlement_from_account_context",
    "has_feature",
    "license_state_from_account_context",
    "license_trust_from_key",
    "snaplink",
    "unix_now",
    "vendor_pinned_trust",
    "verify_license_file",
]
