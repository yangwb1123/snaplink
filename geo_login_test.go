package sso_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/geo/static"
)

// stubAuthenticator returns a fixed AuthResult so the geo
// integration test can isolate the "geo fills RecommendedLanguage"
// path without standing up a real authenticator.
type stubAuthenticator struct {
	name   string
	result *sso.AuthResult
}

func (s *stubAuthenticator) Name() string { return s.name }
func (s *stubAuthenticator) LoginURL(_ string) string { return "" }
func (s *stubAuthenticator) Authenticate(_ context.Context, _ *sso.AuthRequest) (*sso.AuthResult, error) {
	cp := *s.result
	return &cp, nil
}
func (s *stubAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	cp := *s.result
	return &cp, nil
}

// loginFixture wires the smallest set of plumbing the login handler
// needs: stub authenticator, in-memory stores, a session-token issuer.
// Geo provider is wired via WithGeoProvider; tests vary the per-call
// X-Forwarded-For to drive different lookups.
func loginFixture(t *testing.T, auth sso.Authenticator, geoProv geo.Provider) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		AllowedAuthenticators: []string{auth.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(auth),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithGeoProvider(geoProv),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postLogin(t *testing.T, ts *httptest.Server, xff string) map[string]any {
	t.Helper()
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, raw)
	}
	return out
}

func TestLogin_FillsRecommendedLanguageFromGeo(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	ts := loginFixture(t, stub, prov)

	out := postLogin(t, ts, "10.5.6.7")
	if got := out[sso.KeyRecommendedLang]; got != "en-US" {
		t.Errorf("recommended_language = %v, want en-US", got)
	}
}

func TestLogin_AuthenticatorOverridesGeoLanguage(t *testing.T) {
	// Authenticator already knows a stronger signal (e.g. user pref).
	// Geo guess should NOT clobber it.
	stub := &stubAuthenticator{
		name: "stub",
		result: &sso.AuthResult{
			UserID:              "user-alice",
			Provider:            "stub",
			RecommendedLanguage: "ja-JP",
		},
	}
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	ts := loginFixture(t, stub, prov)

	out := postLogin(t, ts, "10.5.6.7")
	if got := out[sso.KeyRecommendedLang]; got != "ja-JP" {
		t.Errorf("recommended_language = %v, want ja-JP (authenticator wins)", got)
	}
}

func TestLogin_NoGeoMatchOmitsLanguageKey(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	prov := static.New() // empty — no entries match
	ts := loginFixture(t, stub, prov)

	out := postLogin(t, ts, "10.5.6.7")
	if _, present := out[sso.KeyRecommendedLang]; present {
		t.Errorf("recommended_language unexpectedly present: %v", out[sso.KeyRecommendedLang])
	}
}

func TestLogin_NilProviderOmitsLanguageKey(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	ts := loginFixture(t, stub, nil) // WithGeoProvider(nil)
	out := postLogin(t, ts, "10.5.6.7")
	if _, present := out[sso.KeyRecommendedLang]; present {
		t.Errorf("recommended_language present despite nil provider")
	}
}
