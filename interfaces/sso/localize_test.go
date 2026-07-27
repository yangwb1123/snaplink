package sso_test

// localize_test.go proves the opt-in i18n enrichment (WithLocalizer, shared/i18n)
// end-to-end over a real HTTP /auth/login failure: no mocks — a real
// authenticator returning core.ErrInvalidCredentials, a real i18n.MemoryLocalizer,
// and (for the geo-fallback case) a real platform/geo/static.Provider.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/platform/geo/static"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/i18n"
)

const (
	locUser     = "loc-user-alice"
	locClient   = "loc-client"
	locUsername = "alice"
	locPassword = "correct-horse"
)

// locBundle is a tiny, real (non-mock) translation bundle covering exactly the
// error the failing-login test below triggers.
func locBundle() i18n.Bundle {
	return i18n.Bundle{
		"en": {"invalid_credentials": "The username or password you entered is incorrect."},
		"es": {"invalid_credentials": "El nombre de usuario o la contraseña que ingresaste es incorrecto."},
	}
}

// locNewServer wires a password authenticator that always rejects (so every
// login attempt in these tests exercises the authzErrorBodyWithState /
// invalid_credentials path), plus whatever extra options the test supplies.
func locNewServer(t *testing.T, extra ...sso.Option) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: locUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: locClient, RedirectURIs: []string{"https://app.example.com/cb"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == locUsername && p == locPassword {
				return &sso.AuthResult{UserID: locUser, AuthMethods: []string{"pwd"}}, nil
			}
			return nil, errors.New(core.ErrInvalidCredentials)
		}))

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	opts = append(opts, extra...)
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// locFailLogin POSTs a wrong-password /auth/login attempt (always rejected by
// locNewServer's authenticator) with an optional Accept-Language header, and
// returns the decoded JSON error body.
func locFailLogin(t *testing.T, url, acceptLanguage string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  locClient,
		"credential": map[string]string{"username": locUsername, "password": "WRONG"},
	})
	req, err := http.NewRequest(http.MethodPost, url+"/auth/login", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if acceptLanguage != "" {
		req.Header.Set(core.HeaderAcceptLanguage, acceptLanguage)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// TestLocalize_NoLocalizerIsByteIdentical proves the default (unwired) behavior:
// no error_description_localized field appears, matching every pre-i18n test's
// expectations of the error body shape.
func TestLocalize_NoLocalizerIsByteIdentical(t *testing.T) {
	t.Parallel()
	url := locNewServer(t).URL
	status, body := locFailLogin(t, url, "es")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if body[core.KeyError] != core.ErrInvalidCredentials {
		t.Fatalf("error = %v, want invalid_credentials", body[core.KeyError])
	}
	if _, ok := body[core.KeyErrorDescriptionLocalized]; ok {
		t.Errorf("error_description_localized present with no Localizer configured: %v", body)
	}
}

// TestLocalize_AcceptLanguageSelectsLocale proves the primary path: a wired
// Localizer + an Accept-Language header together add the localized field
// without disturbing the existing error/iss/state fields.
func TestLocalize_AcceptLanguageSelectsLocale(t *testing.T) {
	t.Parallel()
	loc := i18n.NewMemoryLocalizer(locBundle(), "en")
	url := locNewServer(t, sso.WithLocalizer(loc)).URL

	status, body := locFailLogin(t, url, "es-MX,es;q=0.9,en;q=0.5")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	if body[core.KeyError] != core.ErrInvalidCredentials {
		t.Fatalf("error = %v, want invalid_credentials", body[core.KeyError])
	}
	want := "El nombre de usuario o la contraseña que ingresaste es incorrecto."
	if body[core.KeyErrorDescriptionLocalized] != want {
		t.Errorf("error_description_localized = %v, want %q", body[core.KeyErrorDescriptionLocalized], want)
	}
	if _, ok := body[core.KeyIss]; !ok {
		t.Errorf("iss missing from authz error body: %v", body)
	}
}

// TestLocalize_UnsupportedLocaleFallsBackToDefault proves Localize's own
// exact -> base -> default fallback chain surfaces through the wire response:
// a locale the bundle has never heard of still gets the configured default
// locale's translation rather than no localized field at all.
func TestLocalize_UnsupportedLocaleFallsBackToDefault(t *testing.T) {
	t.Parallel()
	loc := i18n.NewMemoryLocalizer(locBundle(), "en")
	url := locNewServer(t, sso.WithLocalizer(loc)).URL

	status, body := locFailLogin(t, url, "de-DE")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	want := "The username or password you entered is incorrect."
	if body[core.KeyErrorDescriptionLocalized] != want {
		t.Errorf("error_description_localized = %v, want default-locale %q", body[core.KeyErrorDescriptionLocalized], want)
	}
}

// TestLocalize_GeoRecommendedLanguageFallback proves the SECOND locale
// signal: with no Accept-Language header at all, the already-resolved geo
// recommended_language (the SAME signal the login response's own
// recommended_language field uses) picks the locale instead.
func TestLocalize_GeoRecommendedLanguageFallback(t *testing.T) {
	t.Parallel()
	loc := i18n.NewMemoryLocalizer(locBundle(), "en")
	geoProvider := static.New()
	if err := geoProvider.Add("0.0.0.0/0", geo.GeoInfo{RecommendedLanguage: "es"}); err != nil {
		t.Fatalf("geo Add: %v", err)
	}
	url := locNewServer(t, sso.WithLocalizer(loc), sso.WithGeoProvider(geoProvider)).URL

	status, body := locFailLogin(t, url, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	want := "El nombre de usuario o la contraseña que ingresaste es incorrecto."
	if body[core.KeyErrorDescriptionLocalized] != want {
		t.Errorf("error_description_localized = %v, want geo-driven %q", body[core.KeyErrorDescriptionLocalized], want)
	}
}
