//! Application-facing presentation preferences for Snaplink clients.
//!
//! Wire keys deliberately do not appear in the application-facing types. This
//! module owns the mapping to the hosted-login query fields and the legacy
//! `sverp:theme_mode` alias, so a protocol rename stays a one-line change here
//! rather than rippling through every call site.
//!
//! A handoff is a presentation hint, not an authorization or tenant parameter:
//! the server persists it as the authenticated user's allowlisted preference
//! only after a successful authentication.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Presentation theme values shared by Snaplink-hosted applications.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    /// Follow the operating system.
    Auto,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl ThemeMode {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            ThemeMode::Auto => "auto",
            ThemeMode::Light => "light",
            ThemeMode::Dark => "dark",
        }
    }

    /// Parse a wire value, rejecting anything outside the allowlist.
    pub fn parse(value: &str) -> Option<ThemeMode> {
        match value {
            "auto" => Some(ThemeMode::Auto),
            "light" => Some(ThemeMode::Light),
            "dark" => Some(ThemeMode::Dark),
            _ => None,
        }
    }
}

impl std::fmt::Display for ThemeMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Application-facing presentation preferences.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresentationPreferences {
    /// BCP 47 language tag, absent when unset.
    pub locale: Option<String>,
    /// Theme selection, absent when unset.
    pub theme_mode: Option<ThemeMode>,
}

/// A partial update. An empty value removes the corresponding preference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresentationPreferencesPatch {
    /// BCP 47 language tag; `Some("")` removes the stored value.
    pub locale: Option<String>,
    /// Theme selection; `Some(ThemeMode)` sets it. Removal is expressed by
    /// omitting the field, because an enum has no empty value.
    pub theme_mode: Option<ThemeMode>,
}

/// Why a preference value was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PreferenceError {
    /// The locale is not a well-formed BCP 47 tag.
    #[error("locale must be a valid BCP 47 language tag")]
    InvalidLocale,
    /// The theme value is outside the allowlist.
    #[error("theme_mode must be light, dark, or auto")]
    InvalidThemeMode,
    /// The response carried both theme aliases with different values.
    #[error("conflicting theme preference aliases")]
    ConflictingThemeAliases,
}

/// Longest locale the server accepts, matching the OpenAPI `maxLength`.
const MAX_LOCALE_LEN: usize = 32;

fn validate_locale(value: &str, allow_empty: bool) -> Result<(), PreferenceError> {
    if allow_empty && value.is_empty() {
        return Ok(());
    }
    if value.is_empty() || value.len() > MAX_LOCALE_LEN {
        return Err(PreferenceError::InvalidLocale);
    }
    // A pragmatic BCP 47 subset: a 2-3 letter primary subtag followed by
    // alphanumeric subtags of 2-8 characters. This mirrors the server's own
    // pattern; it is deliberately not a full RFC 5646 parser.
    let mut parts = value.split('-');
    let primary = parts.next().unwrap_or_default();
    if !(2..=3).contains(&primary.len()) || !primary.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(PreferenceError::InvalidLocale);
    }
    for part in parts {
        if !(2..=8).contains(&part.len()) || !part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(PreferenceError::InvalidLocale);
        }
    }
    Ok(())
}

/// The wire shape of a stored preference, including the legacy theme alias.
#[derive(Clone, Debug, Default, Deserialize)]
struct StoredPreferences {
    #[serde(default)]
    locale: Option<String>,
    #[serde(default, rename = "theme_mode")]
    theme_mode: Option<String>,
    #[serde(default, rename = "sverp:theme_mode")]
    legacy_theme_mode: Option<String>,
}

impl StoredPreferences {
    /// Resolve the theme, refusing a response whose aliases disagree.
    fn resolve_theme(&self) -> Result<Option<ThemeMode>, PreferenceError> {
        if let (Some(current), Some(legacy)) = (&self.theme_mode, &self.legacy_theme_mode) {
            if current != legacy {
                return Err(PreferenceError::ConflictingThemeAliases);
            }
        }
        let raw = self.theme_mode.as_ref().or(self.legacy_theme_mode.as_ref());
        match raw {
            None => Ok(None),
            Some(value) => ThemeMode::parse(value)
                .map(Some)
                .ok_or(PreferenceError::InvalidThemeMode),
        }
    }
}

/// Map a stored preference response to application fields.
pub fn from_stored_preferences(
    raw: &serde_json::Value,
) -> Result<PresentationPreferences, PreferenceError> {
    let stored: StoredPreferences =
        serde_json::from_value(raw.clone()).map_err(|_| PreferenceError::InvalidThemeMode)?;
    if let Some(locale) = &stored.locale {
        validate_locale(locale, false)?;
    }
    let theme_mode = stored.resolve_theme()?;
    Ok(PresentationPreferences {
        locale: stored.locale,
        theme_mode,
    })
}

/// Map a patch to the update request body.
pub fn to_update_request(
    patch: &PresentationPreferencesPatch,
) -> Result<BTreeMap<&'static str, String>, PreferenceError> {
    let mut body = BTreeMap::new();
    if let Some(locale) = &patch.locale {
        validate_locale(locale, true)?;
        body.insert("locale", locale.clone());
    }
    if let Some(theme_mode) = patch.theme_mode {
        body.insert("theme_mode", theme_mode.as_str().to_owned());
    }
    Ok(body)
}

/// Build the hosted-login handoff: only explicitly changed, non-empty values.
///
/// The result is spread into a login request as `presentation_locale` and
/// `presentation_theme_mode`. Absent fields are omitted rather than sent empty,
/// so a handoff never clears a preference the application did not mean to touch.
pub fn build_login_preference_handoff(
    patch: &PresentationPreferencesPatch,
) -> Result<BTreeMap<&'static str, String>, PreferenceError> {
    let mut handoff = BTreeMap::new();
    if let Some(locale) = &patch.locale {
        validate_locale(locale, false)?;
        handoff.insert("presentation_locale", locale.clone());
    }
    if let Some(theme_mode) = patch.theme_mode {
        handoff.insert("presentation_theme_mode", theme_mode.as_str().to_owned());
    }
    Ok(handoff)
}
