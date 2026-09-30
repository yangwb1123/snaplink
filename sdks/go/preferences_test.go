package snaplink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPreferencesFromWireMapsApplicationFields(t *testing.T) {
	preferences, err := FromMyPreferences(map[string]any{
		"locale":               "zh-CN",
		"theme_mode":           "dark",
		legacyThemeModeKey:     "dark",
		"notification_prefs":   map[string]any{"ignored": true},
		"marketing_consent_at": "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if preferences.Locale != "zh-CN" || preferences.ThemeMode != "dark" {
		t.Fatalf("unexpected preferences: %#v", preferences)
	}
}

func TestPreferencesReadLegacyThemeAlias(t *testing.T) {
	preferences, err := FromMyPreferences(map[string]any{legacyThemeModeKey: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if preferences.ThemeMode != "auto" {
		t.Fatalf("the legacy alias must stay readable during migration: %#v", preferences)
	}
}

func TestPreferencesRejectConflictingThemeAliases(t *testing.T) {
	_, err := FromMyPreferences(map[string]any{"theme_mode": "dark", legacyThemeModeKey: "light"})
	if err == nil {
		t.Fatal("expected a conflicting-alias error")
	}
}

func TestPreferencesRejectUnknownLocaleAndTheme(t *testing.T) {
	for _, raw := range []map[string]any{
		{"locale": "english-language-tag"},
		{"locale": "en_US"},
		{"locale": "e"},
		{"locale": "a-really-long-subtag-value"},
		{"locale": "en-US-"},
		{"theme_mode": "sepia"},
	} {
		if _, err := FromMyPreferences(raw); err == nil {
			t.Fatalf("expected a validation error for %#v", raw)
		}
	}
}

func TestPreferencesAcceptA32CharacterLocale(t *testing.T) {
	exact := strings.Repeat("en-", 10) + "ab"
	if len(exact) != maxLocaleLength {
		t.Fatalf("the boundary fixture must be exactly 32 characters: %d", len(exact))
	}
	if err := validateLocale(exact, false); err != nil {
		t.Fatalf("a 32-character locale must be accepted: %v", err)
	}
	if err := validateLocale(exact+"cd", false); err == nil {
		t.Fatal("a locale longer than the server maximum must be rejected")
	}
}

func TestPreferencesUpdateRequestOmitsUntouchedFields(t *testing.T) {
	body, err := ToMyPreferencesUpdateRequest(PresentationPreferencesPatch{ThemeMode: PreferenceThemeMode("dark")})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body["theme_mode"] != "dark" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestPreferencesUpdateRequestTreatsEmptyStringAsRemoval(t *testing.T) {
	body, err := ToMyPreferencesUpdateRequest(PresentationPreferencesPatch{Locale: PreferenceLocale("")})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := body["locale"]
	if !ok || value != "" {
		t.Fatalf("an empty value removes the stored preference: %#v", body)
	}
	if _, ok := body["theme_mode"]; ok {
		t.Fatal("an untouched field must not be sent")
	}
}

func TestPreferenceHandoffCarriesOnlyExplicitValues(t *testing.T) {
	locale, themeMode := "en-US", "dark"
	handoff, err := BuildLoginPreferenceHandoff(PresentationPreferencesPatch{Locale: &locale, ThemeMode: &themeMode})
	if err != nil {
		t.Fatal(err)
	}
	if handoff["presentation_locale"] != "en-US" || handoff["presentation_theme_mode"] != "dark" {
		t.Fatalf("unexpected handoff: %#v", handoff)
	}
	localeOnly, err := BuildLoginPreferenceHandoff(PresentationPreferencesPatch{Locale: &locale})
	if err != nil {
		t.Fatal(err)
	}
	if len(localeOnly) != 1 {
		t.Fatalf("an omitted field must stay omitted: %#v", localeOnly)
	}
	empty, err := BuildLoginPreferenceHandoff(PresentationPreferencesPatch{ThemeMode: PreferenceThemeMode("")})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("an empty theme value clears nothing: %#v", empty)
	}
	if _, err := BuildLoginPreferenceHandoff(PresentationPreferencesPatch{ThemeMode: PreferenceThemeMode("sepia")}); err == nil {
		t.Fatal("expected a theme allowlist error")
	}
}

func TestPreferenceHandoffReachesTheLoginURL(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client := NewClient(nil, server.Client())
	locale, themeMode := "en-US", "dark"
	handoff, err := BuildLoginPreferenceHandoff(PresentationPreferencesPatch{Locale: &locale, ThemeMode: &themeMode})
	if err != nil {
		t.Fatal(err)
	}
	options := LoginOptions{
		BaseURL: server.URL, ClientID: "spa-client", RedirectURI: server.URL + "/callback",
		PresentationLocale: handoff["presentation_locale"], PresentationThemeMode: handoff["presentation_theme_mode"],
	}
	started, err := client.Login(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(started.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("presentation_locale") != "en-US" || parsed.Query().Get("presentation_theme_mode") != "dark" {
		t.Fatalf("the handoff did not reach the login URL: %s", started.RedirectURL)
	}
}

func TestPreferencesRequireALogin(t *testing.T) {
	client := NewClient(nil, nil)
	if _, err := client.GetMyPreferences(context.Background()); err == nil {
		t.Fatal("reading preferences without a session must fail")
	}
	if _, err := client.UpdateMyPreferences(context.Background(), PresentationPreferencesPatch{}); err == nil {
		t.Fatal("writing preferences without a session must fail")
	}
}

func TestPreferencesReadAndWriteThroughTheSession(t *testing.T) {
	var putBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access-1", ExpiresIn: 900, TokenType: "Bearer"})
		case myPreferencesPath:
			if r.Header.Get("Authorization") != "Bearer access-1" {
				t.Errorf("preferences must be bearer-authenticated: %q", r.Header.Get("Authorization"))
			}
			if r.Method == http.MethodPut {
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &putBody); err != nil {
					t.Errorf("the PUT body was not JSON: %v", err)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"locale": "en-US", "theme_mode": "light"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"locale": "zh-CN", "theme_mode": "dark"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(nil, server.Client())
	options := LoginOptions{BaseURL: server.URL, ClientID: "spa-client", RedirectURI: server.URL + "/callback"}
	started, err := client.Login(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	loginURL, err := url.Parse(started.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	options.CallbackURL = options.RedirectURI + "?code=code-1&state=" + url.QueryEscape(loginURL.Query().Get("state")) + "&iss=" + url.QueryEscape(server.URL)
	if _, err := client.Login(context.Background(), options); err != nil {
		t.Fatal(err)
	}

	stored, err := client.GetMyPreferences(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stored.Locale != "zh-CN" || stored.ThemeMode != "dark" {
		t.Fatalf("unexpected stored preferences: %#v", stored)
	}
	if _, err := client.UpdateMyPreferences(context.Background(), PresentationPreferencesPatch{Locale: PreferenceLocale("en-US")}); err != nil {
		t.Fatal(err)
	}
	if putBody["locale"] != "en-US" {
		t.Fatalf("unexpected PUT body: %#v", putBody)
	}
	if _, ok := putBody["theme_mode"]; ok {
		t.Fatal("an untouched field must not be sent")
	}
}
