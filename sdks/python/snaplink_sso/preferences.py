"""Application-facing shared presentation preferences for Snaplink clients."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, Mapping, Optional

from .client import SSOClient


PresentationThemeMode = str
_LOCALE_PATTERN = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
_THEME_MODES = {"light", "dark", "auto"}


@dataclass(frozen=True)
class PresentationPreferences:
    """Allowlisted presentation values; protocol wire keys stay in this module."""

    locale: Optional[str] = None
    theme_mode: Optional[PresentationThemeMode] = None


@dataclass(frozen=True)
class PresentationPreferencesPatch:
    """Partial update; an empty string removes a stored value."""

    locale: Optional[str] = None
    theme_mode: Optional[PresentationThemeMode] = None


def _validate_locale(value: str, *, allow_empty: bool) -> None:
    if allow_empty and value == "":
        return
    if len(value) > 32 or not _LOCALE_PATTERN.fullmatch(value):
        raise ValueError("locale must be a valid BCP 47 language tag")


def _validate_theme(value: str, *, allow_empty: bool) -> None:
    if allow_empty and value == "":
        return
    if value not in _THEME_MODES:
        raise ValueError("theme_mode must be light, dark, or auto")


def from_my_preferences(value: Mapping[str, Any]) -> PresentationPreferences:
    """Map the generated response's wire shape to application fields."""

    locale = value.get("locale")
    if locale is not None:
        if not isinstance(locale, str):
            raise ValueError("locale must be a string")
        _validate_locale(locale, allow_empty=False)

    generic_theme_mode = value.get("theme_mode")
    legacy_theme_mode = value.get("sverp:theme_mode")
    for theme_value in (generic_theme_mode, legacy_theme_mode):
        if theme_value is not None:
            if not isinstance(theme_value, str):
                raise ValueError("theme_mode must be a string")
            _validate_theme(theme_value, allow_empty=False)
    if (
        generic_theme_mode is not None
        and legacy_theme_mode is not None
        and generic_theme_mode != legacy_theme_mode
    ):
        raise ValueError("conflicting theme preference aliases")
    theme_mode = (
        generic_theme_mode
        if generic_theme_mode is not None
        else legacy_theme_mode
    )

    return PresentationPreferences(locale=locale, theme_mode=theme_mode)


def to_my_preferences_update_request(
    value: PresentationPreferencesPatch,
) -> Dict[str, str]:
    """Map application fields to the generated Snaplink PUT body."""

    result: Dict[str, str] = {}
    if value.locale is not None:
        _validate_locale(value.locale, allow_empty=True)
        result["locale"] = value.locale
    if value.theme_mode is not None:
        _validate_theme(value.theme_mode, allow_empty=True)
        result["theme_mode"] = value.theme_mode
    return result


def build_login_preference_handoff(
    value: PresentationPreferencesPatch,
) -> Dict[str, str]:
    """Return only explicitly changed, non-empty login presentation hints."""

    result: Dict[str, str] = {}
    if value.locale is not None:
        _validate_locale(value.locale, allow_empty=False)
        result["presentation_locale"] = value.locale
    if value.theme_mode not in (None, ""):
        _validate_theme(value.theme_mode, allow_empty=False)
        result["presentation_theme_mode"] = value.theme_mode
    return result


class SnaplinkUserPreferencesClient:
    """Typed preference facade over the generated :class:`SSOClient`."""

    def __init__(self, client: SSOClient) -> None:
        self._client = client

    def get_my_preferences(self) -> PresentationPreferences:
        return from_my_preferences(self._client.get_my_preferences())

    def update_my_preferences(
        self,
        value: PresentationPreferencesPatch,
    ) -> Mapping[str, str]:
        return self._client.put_my_preferences(
            to_my_preferences_update_request(value)
        )
