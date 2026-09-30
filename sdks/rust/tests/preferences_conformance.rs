//! Presentation-preference handoff conformance.
//!
//! The cases mirror `sdks/python/tests/test_preferences.py` and
//! `sdks/typescript/preferences.test.mjs` so the three implementations
//! agree on validation, the legacy theme alias, and what a handoff contains.

use snaplink_sso_client::{
    build_login_preference_handoff, from_stored_preferences, to_update_request, PreferenceError,
    PresentationPreferences, PresentationPreferencesPatch, ThemeMode,
};

fn patch(locale: Option<&str>, theme: Option<ThemeMode>) -> PresentationPreferencesPatch {
    PresentationPreferencesPatch {
        locale: locale.map(str::to_owned),
        theme_mode: theme,
    }
}

#[test]
fn a_handoff_contains_only_explicitly_set_values() {
    let only_locale = build_login_preference_handoff(&patch(Some("en-US"), None)).expect("valid");
    assert_eq!(
        Some(&"en-US".to_owned()),
        only_locale.get("presentation_locale")
    );
    assert!(!only_locale.contains_key("presentation_theme_mode"));

    let only_theme =
        build_login_preference_handoff(&patch(None, Some(ThemeMode::Dark))).expect("valid");
    assert_eq!(
        Some(&"dark".to_owned()),
        only_theme.get("presentation_theme_mode")
    );
    assert!(!only_theme.contains_key("presentation_locale"));

    let empty = build_login_preference_handoff(&patch(None, None)).expect("valid");
    assert!(empty.is_empty(), "an unset patch hands off nothing");
}

#[test]
fn a_handoff_never_sends_an_empty_value() {
    // An empty locale clears a stored preference through the update body, but
    // must not travel in a login handoff.
    let handoff = build_login_preference_handoff(&patch(Some(""), None));
    assert_eq!(Err(PreferenceError::InvalidLocale), handoff);
}

#[test]
fn valid_bcp47_tags_are_accepted() {
    for locale in ["en", "eng", "en-US", "zh-Hans-CN", "pt-BR", "es-419"] {
        assert!(
            build_login_preference_handoff(&patch(Some(locale), None)).is_ok(),
            "{locale} should be accepted"
        );
    }
}

#[test]
fn malformed_locales_are_rejected() {
    for locale in [
        "",
        "e",
        "english-language-tag",
        "en_US",
        "en-",
        "-US",
        "en-U",
        "1n",
        "en-US-",
    ] {
        assert_eq!(
            Err(PreferenceError::InvalidLocale),
            build_login_preference_handoff(&patch(Some(locale), None)),
            "{locale} should be rejected"
        );
    }
}

#[test]
fn an_overlong_locale_is_rejected() {
    let long = "en-".repeat(12);
    assert!(long.len() > 32);
    assert_eq!(
        Err(PreferenceError::InvalidLocale),
        build_login_preference_handoff(&patch(Some(&long), None))
    );
}

#[test]
fn the_update_body_reaches_a_32_character_locale() {
    let exact = "en-".repeat(10) + "ab";
    assert_eq!(32, exact.len());
    assert!(to_update_request(&patch(Some(&exact), None)).is_ok());
}

#[test]
fn every_theme_mode_round_trips() {
    for (wire, mode) in [
        ("light", ThemeMode::Light),
        ("dark", ThemeMode::Dark),
        ("auto", ThemeMode::Auto),
    ] {
        assert_eq!(Some(mode), ThemeMode::parse(wire));
        assert_eq!(wire, mode.as_str());
    }
    assert_eq!(None, ThemeMode::parse("solarized"));
}

#[test]
fn a_stored_response_maps_to_application_fields() {
    let stored = serde_json::json!({"locale": "zh-Hans-CN", "theme_mode": "dark"});
    let preferences = from_stored_preferences(&stored).expect("valid");
    assert_eq!(
        PresentationPreferences {
            locale: Some("zh-Hans-CN".to_owned()),
            theme_mode: Some(ThemeMode::Dark),
        },
        preferences
    );
}

#[test]
fn the_legacy_theme_alias_is_still_honoured() {
    let legacy = serde_json::json!({"sverp:theme_mode": "light"});
    let preferences = from_stored_preferences(&legacy).expect("valid");
    assert_eq!(Some(ThemeMode::Light), preferences.theme_mode);
}

#[test]
fn conflicting_theme_aliases_are_rejected() {
    let conflicting = serde_json::json!({"theme_mode": "dark", "sverp:theme_mode": "light"});
    assert_eq!(
        Err(PreferenceError::ConflictingThemeAliases),
        from_stored_preferences(&conflicting)
    );
}

#[test]
fn agreeing_theme_aliases_are_accepted() {
    let agreeing = serde_json::json!({"theme_mode": "dark", "sverp:theme_mode": "dark"});
    let preferences = from_stored_preferences(&agreeing).expect("valid");
    assert_eq!(Some(ThemeMode::Dark), preferences.theme_mode);
}

#[test]
fn an_unknown_theme_value_is_rejected() {
    let stored = serde_json::json!({"theme_mode": "neon"});
    assert_eq!(
        Err(PreferenceError::InvalidThemeMode),
        from_stored_preferences(&stored)
    );
}

#[test]
fn an_empty_response_yields_no_preferences() {
    let preferences = from_stored_preferences(&serde_json::json!({})).expect("valid");
    assert_eq!(PresentationPreferences::default(), preferences);
}

#[test]
fn the_update_body_omits_untouched_fields() {
    let body = to_update_request(&patch(Some("en-US"), Some(ThemeMode::Auto))).expect("valid");
    assert_eq!(Some(&"en-US".to_owned()), body.get("locale"));
    assert_eq!(Some(&"auto".to_owned()), body.get("theme_mode"));

    let sparse = to_update_request(&patch(None, Some(ThemeMode::Light))).expect("valid");
    assert_eq!(1, sparse.len(), "an untouched locale must not be sent");

    let empty = to_update_request(&patch(None, None)).expect("valid");
    assert!(empty.is_empty());
}
