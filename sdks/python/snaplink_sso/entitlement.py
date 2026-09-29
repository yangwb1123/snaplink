"""Application-facing commercial entitlement for the Snaplink Python SDK.

The server is always the authority on what a tenant may do. This module exists
so a caller never has to know the wire shape of an entitlement in order to
decide whether a feature is available, and so a lapsed entitlement is never
mistaken for a live one.

``Entitlement.state_at`` reproduces ``commerce.EntitlementSnapshot.effective``
exactly: an entitlement is effective only when ``active`` is set, ``now`` is not
before ``effective_at``, and ``expires_at`` is unset or strictly after ``now``.
A presence check cannot make that distinction, which is why ``LicenseState`` has
three variants rather than an ``Optional``.

Timestamps arrive as RFC 3339 because that is what Go's ``time.Time``
serialises; ``expires_at`` may also be absent, which is an unbounded grant.
"""

from __future__ import annotations

import calendar
import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, Mapping, Optional

#: Feature keys the server currently defines, mirroring ``commerce.FeatureKey``.
_FEATURE_KEYS = (
    "core_sso",
    "multi_tenant",
    "audit_governance",
    "notifications",
    "im",
    "account",
    "vault",
    "scim",
    "federation",
    "high_availability",
)

#: Quota dimensions the server currently defines, mirroring ``commerce.LimitKey``.
_LIMIT_KEYS = (
    "users",
    "clients",
    "sessions",
    "token_rate",
    "storage_bytes",
    "storage_objects",
)

_EPOCH = datetime.timezone.utc


class Feature(str, Enum):
    """A stable product capability identifier.

    Subclasses ``str`` so a member can be used anywhere the wire key is
    expected, while still being an enum a caller cannot typo.
    """

    CORE_SSO = "core_sso"
    MULTI_TENANT = "multi_tenant"
    AUDIT_GOVERNANCE = "audit_governance"
    NOTIFICATIONS = "notifications"
    IM = "im"
    ACCOUNT = "account"
    VAULT = "vault"
    SCIM = "scim"
    FEDERATION = "federation"
    HIGH_AVAILABILITY = "high_availability"


class Limit(str, Enum):
    """A stable quota dimension."""

    USERS = "users"
    CLIENTS = "clients"
    SESSIONS = "sessions"
    TOKEN_RATE = "token_rate"
    STORAGE_BYTES = "storage_bytes"
    STORAGE_OBJECTS = "storage_objects"


class InactiveReason(str, Enum):
    """Why an entitlement is present but not usable.

    Presentation only. It must never drive retry or authorization behaviour: the
    server collapses distinct internal causes into one wire code, and a client
    that branches on the reason would leak the distinction the server
    deliberately hides.
    """

    NOT_YET_EFFECTIVE = "not_yet_effective"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


def _parse_timestamp(value: Any) -> Optional[int]:
    """Return Unix seconds for an RFC 3339 string or an integer, else ``None``.

    A hand-written entitlement file or a test fixture may use Unix seconds
    directly, so both forms are accepted and land on the same instant.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_EPOCH)
    return calendar.timegm(parsed.utctimetuple())


def unix_now() -> int:
    """Current time in Unix seconds, the clock the state helpers expect."""
    return calendar.timegm(datetime.datetime.now(tz=_EPOCH).utctimetuple())


@dataclass(frozen=True)
class LimitGrant:
    """A soft threshold and a hard safety limit.

    ``unlimited`` short-circuits the pair: an unlimited grant reports zero for
    both thresholds, so a caller reading ``soft`` alone would see a bogus number.
    Always check :attr:`unlimited`.
    """

    soft: int = 0
    hard: int = 0
    unlimited: bool = False

    @classmethod
    def from_wire(cls, value: Any) -> "LimitGrant":
        if not isinstance(value, Mapping):
            return cls()
        soft = value.get("soft", 0)
        hard = value.get("hard", 0)
        unlimited = value.get("unlimited", False)
        return cls(
            soft=int(soft) if isinstance(soft, int) else 0,
            hard=int(hard) if isinstance(hard, int) else 0,
            unlimited=bool(unlimited),
        )


@dataclass(frozen=True)
class PlanRef:
    """A plan identifier and its immutable published version."""

    id: str = ""
    version: int = 0

    @classmethod
    def from_wire(cls, value: Any) -> "PlanRef":
        if not isinstance(value, Mapping):
            return cls()
        version = value.get("version", 0)
        identifier = value.get("id", "")
        return cls(
            id=identifier if isinstance(identifier, str) else "",
            version=int(version) if isinstance(version, int) else 0,
        )


@dataclass(frozen=True)
class Entitlement:
    """A server-derived commercial entitlement snapshot."""

    tenant_id: str = ""
    subscription_id: str = ""
    plan: PlanRef = field(default_factory=PlanRef)
    revision: int = 0
    active: bool = False
    features: Mapping[str, bool] = field(default_factory=dict)
    limits: Mapping[str, LimitGrant] = field(default_factory=dict)
    effective_at: int = 0
    expires_at: Optional[int] = None
    generated_at: int = 0

    @classmethod
    def from_wire(cls, value: Any) -> "Entitlement":
        """Build from the ``entitlement`` object of an account-context response."""
        if not isinstance(value, Mapping):
            raise ValueError("entitlement must be an object")
        raw_features = value.get("features")
        features: Dict[str, bool] = {}
        if isinstance(raw_features, Mapping):
            features = {str(key): bool(flag) for key, flag in raw_features.items()}
        raw_limits = value.get("limits")
        limits: Dict[str, LimitGrant] = {}
        if isinstance(raw_limits, Mapping):
            limits = {str(key): LimitGrant.from_wire(grant) for key, grant in raw_limits.items()}
        revision = value.get("revision", 0)
        return cls(
            tenant_id=str(value.get("tenant_id", "")),
            subscription_id=str(value.get("subscription_id", "")),
            plan=PlanRef.from_wire(value.get("plan")),
            revision=int(revision) if isinstance(revision, int) else 0,
            active=bool(value.get("active", False)),
            features=features,
            limits=limits,
            effective_at=_parse_timestamp(value.get("effective_at")) or 0,
            expires_at=_parse_timestamp(value.get("expires_at")),
            generated_at=_parse_timestamp(value.get("generated_at")) or 0,
        )

    def state_at(self, now: int) -> "LicenseState":
        """Classify the entitlement at ``now``, given in Unix seconds.

        Mirrors ``commerce.EntitlementSnapshot.effective`` exactly: the
        ``expires_at`` boundary is exclusive, so an entitlement whose window
        closes at ``t`` is already inactive at ``t``.
        """
        if not self.active:
            return LicenseState.inactive(InactiveReason.SUSPENDED, self.expires_at)
        if now < self.effective_at:
            return LicenseState.inactive(InactiveReason.NOT_YET_EFFECTIVE)
        if self.expires_at is not None and now >= self.expires_at:
            return LicenseState.inactive(InactiveReason.EXPIRED, self.expires_at)
        return LicenseState.active(self)

    def has(self, feature: Feature, now: int) -> bool:
        """Whether ``feature`` is granted at ``now``.

        Returns ``False`` for an inactive entitlement regardless of what the map
        says, and ``False`` for a key this build does not recognise.
        """
        if not self.state_at(now).is_active:
            return False
        return bool(self.features.get(Feature(feature).value, False))

    def limit(self, limit: Limit, now: int) -> Optional[LimitGrant]:
        """The grant for ``limit`` at ``now``, or ``None`` when inactive or absent."""
        if not self.state_at(now).is_active:
            return None
        return self.limits.get(Limit(limit).value)

    def unknown_features(self) -> Iterator[str]:
        """Feature keys the server sent that this build does not recognise."""
        return (key for key in self.features if key not in _FEATURE_KEYS)

    def unknown_limits(self) -> Iterator[str]:
        """Limit keys the server sent that this build does not recognise."""
        return (key for key in self.limits if key not in _LIMIT_KEYS)


class LicenseStateKind(str, Enum):
    """Which of the three states a product licence is in."""

    NOT_ACTIVATED = "not_activated"
    INACTIVE = "inactive"
    ACTIVE = "active"


@dataclass(frozen=True)
class LicenseState:
    """The classified state of a product licence.

    A two-state ``Optional`` cannot tell "never activated" from "activated once
    but lapsed", and those need different copy and different follow-up actions.
    Frozen so a state cannot be mutated into granting something it did not.
    """

    kind: LicenseStateKind
    reason: Optional[InactiveReason] = None
    until: Optional[int] = None
    entitlement: Optional["Entitlement"] = None

    @classmethod
    def not_activated(cls) -> "LicenseState":
        return cls(LicenseStateKind.NOT_ACTIVATED)

    @classmethod
    def inactive(
        cls, reason: InactiveReason, until: Optional[int] = None
    ) -> "LicenseState":
        return cls(LicenseStateKind.INACTIVE, reason=reason, until=until)

    @classmethod
    def active(cls, entitlement: "Entitlement") -> "LicenseState":
        return cls(LicenseStateKind.ACTIVE, entitlement=entitlement)

    @property
    def is_active(self) -> bool:
        """Whether grants are live. The only question a feature gate should ask."""
        return self.kind is LicenseStateKind.ACTIVE

    @property
    def inactive_reason(self) -> Optional[InactiveReason]:
        """Why grants are unavailable, for display only."""
        return self.reason if self.kind is LicenseStateKind.INACTIVE else None


def entitlement_from_account_context(context: Optional[Mapping[str, Any]]) -> Optional[Entitlement]:
    """Return the entitlement carried by an account-context response.

    Returns ``None`` for a context with no entitlement, which is the
    never-activated case, not a lapsed one.
    """
    if not isinstance(context, Mapping):
        return None
    raw = context.get("entitlement")
    if raw is None:
        return None
    return Entitlement.from_wire(raw)


def license_state_from_account_context(
    context: Optional[Mapping[str, Any]], now: int
) -> LicenseState:
    """Classify an account-context response at ``now``, given in Unix seconds."""
    entitlement = entitlement_from_account_context(context)
    if entitlement is None:
        return LicenseState.not_activated()
    return entitlement.state_at(now)


def has_feature(
    context: Optional[Mapping[str, Any]], feature: Feature, now: int
) -> bool:
    """Whether ``feature`` is granted at ``now`` for this account context."""
    entitlement = entitlement_from_account_context(context)
    return entitlement.has(feature, now) if entitlement is not None else False
