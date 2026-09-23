"""Public package for the Snaplink HTTP SDK."""

from .client import SSOClient, SSOError
from .hosted_login import LoginResult, MemoryStateStore, Snaplink, StateStore, snaplink
from .preferences import (
    PresentationPreferences,
    PresentationPreferencesPatch,
    SnaplinkUserPreferencesClient,
    build_login_preference_handoff,
)

__all__ = [
    "LoginResult",
    "MemoryStateStore",
    "Snaplink",
    "SSOClient",
    "SSOError",
    "StateStore",
    "PresentationPreferences",
    "PresentationPreferencesPatch",
    "SnaplinkUserPreferencesClient",
    "build_login_preference_handoff",
    "snaplink",
]
