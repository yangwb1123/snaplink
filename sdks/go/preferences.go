package snaplink

import (
	"context"
	"net/http"
	"strings"
)

// Wire keys for the allowlisted presentation preferences. They stay here so a
// protocol rename is a one-line change instead of rippling through call sites.
//
// A handoff is a presentation hint, never an authorization or tenant
// parameter: the server persists it as the authenticated user's preference only
// after a successful authentication.

// legacyThemeModeKey is the pre-rename alias still served during migration.
const legacyThemeModeKey = "sverp:theme_mode"

// maxLocaleLength matches the OpenAPI maxLength for presentation_locale.
const maxLocaleLength = 32

// presentationThemeModes is the server's theme allowlist.
var presentationThemeModes = []string{"light", "dark", "auto"}

// PresentationPreferences is a stored preference in application terms. Wire
// keys deliberately do not appear in the field names.
type PresentationPreferences struct {
	Locale    string
	ThemeMode string
}

// PresentationPreferencesPatch is a partial update. A non-nil field is written,
// and an empty string removes the stored value.
type PresentationPreferencesPatch struct {
	Locale    *string
	ThemeMode *string
}

// PreferenceLocale returns a patch field carrying locale, for callers that
// build a patch from optional application state.
func PreferenceLocale(locale string) *string { return &locale }

// PreferenceThemeMode returns a patch field carrying themeMode.
func PreferenceThemeMode(themeMode string) *string { return &themeMode }

// FromMyPreferences maps a /me/preferences response to application fields.
func FromMyPreferences(raw map[string]any) (PresentationPreferences, error) {
	preferences := PresentationPreferences{}
	if locale, ok := raw["locale"]; ok && locale != nil {
		value, ok := locale.(string)
		if !ok {
			return preferences, preferenceError("locale must be a string")
		}
		if err := validateLocale(value, false); err != nil {
			return preferences, err
		}
		preferences.Locale = value
	}
	themeMode, err := resolveThemeMode(raw)
	if err != nil {
		return preferences, err
	}
	preferences.ThemeMode = themeMode
	return preferences, nil
}

// ToMyPreferencesUpdateRequest maps application fields to the PUT body.
func ToMyPreferencesUpdateRequest(patch PresentationPreferencesPatch) (map[string]string, error) {
	body := map[string]string{}
	if patch.Locale != nil {
		if err := validateLocale(*patch.Locale, true); err != nil {
			return nil, err
		}
		body["locale"] = *patch.Locale
	}
	if patch.ThemeMode != nil {
		if err := validateThemeMode(*patch.ThemeMode, true); err != nil {
			return nil, err
		}
		body["theme_mode"] = *patch.ThemeMode
	}
	return body, nil
}

// BuildLoginPreferenceHandoff returns only explicitly changed, non-empty login
// hints. Omitted fields stay omitted so a handoff never clears a stored
// preference the application did not mean to touch.
func BuildLoginPreferenceHandoff(patch PresentationPreferencesPatch) (map[string]string, error) {
	handoff := map[string]string{}
	if patch.Locale != nil {
		if err := validateLocale(*patch.Locale, false); err != nil {
			return nil, err
		}
		handoff["presentation_locale"] = *patch.Locale
	}
	if patch.ThemeMode != nil && *patch.ThemeMode != "" {
		if err := validateThemeMode(*patch.ThemeMode, false); err != nil {
			return nil, err
		}
		handoff["presentation_theme_mode"] = *patch.ThemeMode
	}
	return handoff, nil
}

// GetMyPreferences reads the authenticated user's stored preferences.
func (c *Client) GetMyPreferences(ctx context.Context) (PresentationPreferences, error) {
	if c == nil || c.tokens == nil || strings.TrimSpace(c.tokens.AccessToken) == "" {
		return PresentationPreferences{}, &Error{Status: http.StatusUnauthorized, Code: "login_required", Description: "login is required"}
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return PresentationPreferences{}, &Error{Status: 0, Code: "invalid_request", Description: "base_url is required"}
	}
	var raw map[string]any
	endpoint := strings.TrimRight(c.baseURL, "/") + myPreferencesPath
	if err := c.requestJSON(ctx, http.MethodGet, endpoint, nil, c.tokens.AccessToken, &raw); err != nil {
		return PresentationPreferences{}, err
	}
	return FromMyPreferences(raw)
}

// UpdateMyPreferences writes the supplied fields and returns the server's
// merged view. Fields left nil are untouched.
func (c *Client) UpdateMyPreferences(ctx context.Context, patch PresentationPreferencesPatch) (map[string]any, error) {
	if c == nil || c.tokens == nil || strings.TrimSpace(c.tokens.AccessToken) == "" {
		return nil, &Error{Status: http.StatusUnauthorized, Code: "login_required", Description: "login is required"}
	}
	body, err := ToMyPreferencesUpdateRequest(patch)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, &Error{Status: 0, Code: "invalid_request", Description: "base_url is required"}
	}
	var merged map[string]any
	endpoint := strings.TrimRight(c.baseURL, "/") + myPreferencesPath
	if err := c.requestJSON(ctx, http.MethodPut, endpoint, body, c.tokens.AccessToken, &merged); err != nil {
		return nil, err
	}
	return merged, nil
}

const myPreferencesPath = "/me/preferences"

func resolveThemeMode(raw map[string]any) (string, error) {
	generic, genericSet, err := themeValue(raw, "theme_mode")
	if err != nil {
		return "", err
	}
	legacy, legacySet, err := themeValue(raw, legacyThemeModeKey)
	if err != nil {
		return "", err
	}
	if genericSet && legacySet && generic != legacy {
		return "", preferenceError("conflicting theme preference aliases")
	}
	if genericSet {
		return generic, nil
	}
	if legacySet {
		return legacy, nil
	}
	return "", nil
}

func themeValue(raw map[string]any, key string) (string, bool, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", false, preferenceError("theme_mode must be a string")
	}
	if err := validateThemeMode(text, false); err != nil {
		return "", false, err
	}
	return text, true, nil
}

// validateLocale checks a BCP 47 subset: a 2-3 letter primary subtag followed by
// alphanumeric subtags of 2-8 characters. This is deliberately not a full
// RFC 5646 parser; it mirrors the server's own pattern.
func validateLocale(value string, allowEmpty bool) error {
	if allowEmpty && value == "" {
		return nil
	}
	if value == "" || len(value) > maxLocaleLength {
		return preferenceError("locale must be a valid BCP 47 language tag")
	}
	parts := strings.Split(value, "-")
	if !isAlpha(parts[0]) || len(parts[0]) < 2 || len(parts[0]) > 3 {
		return preferenceError("locale must be a valid BCP 47 language tag")
	}
	for _, part := range parts[1:] {
		if len(part) < 2 || len(part) > 8 || !isAlphaNumeric(part) {
			return preferenceError("locale must be a valid BCP 47 language tag")
		}
	}
	return nil
}

func validateThemeMode(value string, allowEmpty bool) error {
	if allowEmpty && value == "" {
		return nil
	}
	for _, mode := range presentationThemeModes {
		if value == mode {
			return nil
		}
	}
	return preferenceError("theme_mode must be light, dark, or auto")
}

func isAlpha(value string) bool {
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') {
			return false
		}
	}
	return len(value) > 0
}

func isAlphaNumeric(value string) bool {
	for _, char := range value {
		if !isAlpha(string(char)) && (char < '0' || char > '9') {
			return false
		}
	}
	return len(value) > 0
}

func preferenceError(description string) error {
	return &Error{Status: 0, Code: "invalid_request", Description: description}
}
