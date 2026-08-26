package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/platform/geo/static"
)

// stubAuthenticator returns a fixed AuthResult so the geo
// integration test can isolate the "geo fills RecommendedLanguage"
// path without standing up a real authenticator.
type stubAuthenticator struct {
	name   string
	result *sso.AuthResult
}

func (s *stubAuthenticator) Name() string             { return s.name }
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
// needs: stub authenticator, in-memory stores, a session-token issuer, and
// the canonical trusted-proxy context used by forwarded-address tests.
func loginFixture(t *testing.T, auth sso.Authenticator, geoProv geo.Provider) *httptest.Server {
	return loginFixtureWithOptions(t, auth, geoProv, geoLoginTrustedProxyOption(t))
}

// loginFixtureWithoutTrustedProxies keeps the real SDK path intentionally
// unconfigured so the default-deny behavior for forged geo headers is tested.
func loginFixtureWithoutTrustedProxies(t *testing.T, auth sso.Authenticator, geoProv geo.Provider) *httptest.Server {
	return loginFixtureWithOptions(t, auth, geoProv)
}

func loginFixtureWithOptions(t *testing.T, auth sso.Authenticator, geoProv geo.Provider, extra ...sso.Option) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		AllowedAuthenticators: []string{auth.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	opts := []sso.Option{
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(auth),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithGeoProvider(geoProv),
	}
	opts = append(opts, extra...)
	srv := sso.NewServer(opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func geoLoginTrustedProxyOption(t *testing.T) sso.Option {
	t.Helper()
	opt, err := sso.WithTrustedProxies([]string{"127.0.0.0/8"}, 0)
	if err != nil {
		t.Fatalf("WithTrustedProxies: %v", err)
	}
	return opt
}

func postLogin(t *testing.T, ts *httptest.Server, xff string) map[string]any {
	return postLoginWithHeaders(t, ts, xff, "")
}

func postLoginWithHeaders(t *testing.T, ts *httptest.Server, xff, xreal string) map[string]any {
	t.Helper()
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xreal != "" {
		req.Header.Set("X-Real-IP", xreal)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
	if _, present := out[sso.KeyCountryCode]; present {
		t.Errorf("country_code present despite nil provider")
	}
}

func TestLogin_FillsCountryCodeFromGeo(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	ts := loginFixture(t, stub, prov)

	out := postLogin(t, ts, "10.5.6.7")
	if got := out[sso.KeyCountryCode]; got != "US" {
		t.Errorf("country_code = %v, want US", got)
	}
	if got := out[sso.KeyRecommendedLang]; got != "en-US" {
		t.Errorf("recommended_language = %v, want en-US", got)
	}
}

func TestLogin_DefaultGeoExtractorIgnoresForgedForwardedHeaders(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	prov := static.New()
	_ = prov.Add("127.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "CA", RecommendedLanguage: "fr-CA"})
	ts := loginFixtureWithoutTrustedProxies(t, stub, prov)

	out := postLoginWithHeaders(t, ts, "10.5.6.7", "10.5.6.8")
	if got := out[sso.KeyCountryCode]; got != "US" {
		t.Errorf("country_code = %v, want RemoteAddr country US", got)
	}
	if got := out[sso.KeyRecommendedLang]; got != "en-US" {
		t.Errorf("recommended_language = %v, want RemoteAddr language en-US", got)
	}
}

// loginFixtureWithAudit mirrors loginFixture but wires an audit
// MemorySink so tests can assert on what landed in the audit log.
func loginFixtureWithAudit(t *testing.T, auth sso.Authenticator, geoProv geo.Provider) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		AllowedAuthenticators: []string{auth.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(auth),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithAuditRecorder(rec),
		sso.WithGeoProvider(geoProv),
		geoLoginTrustedProxyOption(t),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sink
}

// failingAuthenticator returns a fixed error so tests can drive the
// login_failure audit path.
type failingAuthenticator struct{ name string }

func (f *failingAuthenticator) Name() string             { return f.name }
func (f *failingAuthenticator) LoginURL(_ string) string { return "" }
func (f *failingAuthenticator) Authenticate(_ context.Context, _ *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, errors.New("bad creds")
}
func (f *failingAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("bad")
}

func TestAudit_GeoEnrichment_LoginSuccess(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{
		CountryCode: "US", Region: "US-CA", City: "SF", RecommendedLanguage: "en-US",
	})
	ts, sink := loginFixtureWithAudit(t, stub, prov)
	_ = postLogin(t, ts, "10.5.6.7")

	events, err := sink.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var login *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLogin {
			login = e
			break
		}
	}
	if login == nil {
		t.Fatalf("no login event recorded; got %d events", len(events))
	}
	wantMeta := map[string]string{
		"geo.country_code":         "US",
		"geo.region":               "US-CA",
		"geo.city":                 "SF",
		"geo.recommended_language": "en-US",
	}
	for k, v := range wantMeta {
		if got := login.Metadata[k]; got != v {
			t.Errorf("Metadata[%q] = %q, want %q (full meta=%v)", k, got, v, login.Metadata)
		}
	}
}

func TestAudit_GeoEnrichment_LoginFailureCarriesGeo(t *testing.T) {
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US"})
	ts, sink := loginFixtureWithAudit(t, &failingAuthenticator{name: "stub"}, prov)

	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.5.6.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	events, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	var failure *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLoginFailure {
			failure = e
			break
		}
	}
	if failure == nil {
		t.Fatalf("no login_failure event; got %d events", len(events))
	}
	if got := failure.Metadata["geo.country_code"]; got != "US" {
		t.Errorf("login_failure missing geo.country_code: %v", failure.Metadata)
	}
}

func TestAudit_GeoEnrichment_NoProviderLeavesNoMetadata(t *testing.T) {
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	ts, sink := loginFixtureWithAudit(t, stub, nil) // no geo provider
	_ = postLogin(t, ts, "10.5.6.7")

	events, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	for _, e := range events {
		for k := range e.Metadata {
			if strings.HasPrefix(k, "geo.") {
				t.Errorf("event %q carries geo metadata despite nil provider: %v", e.Type, e.Metadata)
			}
		}
	}
}

func TestAudit_GeoEnrichment_DoesNotClobberExistingMetadata(t *testing.T) {
	// /auth/send-code records a code_sent event with metadata["target"].
	// Verify geo enrichment merges rather than replaces.
	// We need an authenticator whose SendCode the handler will call —
	// stubAuthenticator doesn't implement that interface, so instead we
	// drive the logout path which sets metadata["revoked"].
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US"})
	ts, sink := loginFixtureWithAudit(t, stub, prov)

	// Login to get a session, then logout — logout sets metadata["revoked"].
	loginResp := postLogin(t, ts, "10.5.6.7")
	sid, _ := loginResp[sso.KeySessionID].(string)
	if sid == "" {
		t.Fatal("login did not return session_id")
	}
	logoutBody := `{"session_id":"` + sid + `"}`
	req, _ := http.NewRequest("POST", ts.URL+"/logout", strings.NewReader(logoutBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.5.6.7")
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	events, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	var logout *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLogout {
			logout = e
			break
		}
	}
	if logout == nil {
		t.Fatalf("no logout event; got %d events", len(events))
	}
	// Both the geo enrichment AND the existing 'revoked' should be present.
	if logout.Metadata["geo.country_code"] != "US" {
		t.Errorf("geo metadata missing on logout: %v", logout.Metadata)
	}
	if _, ok := logout.Metadata["revoked"]; !ok {
		t.Errorf("revoked metadata clobbered: %v", logout.Metadata)
	}
}

func TestLogin_AuthenticatorOverridesGeoCountry(t *testing.T) {
	stub := &stubAuthenticator{
		name: "stub",
		result: &sso.AuthResult{
			UserID:      "user-alice",
			Provider:    "stub",
			CountryCode: "JP",
		},
	}
	prov := static.New()
	_ = prov.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	ts := loginFixture(t, stub, prov)

	out := postLogin(t, ts, "10.5.6.7")
	if got := out[sso.KeyCountryCode]; got != "JP" {
		t.Errorf("country_code = %v, want JP (authenticator wins)", got)
	}
	// Language should still get the geo fallback since the
	// authenticator left it empty — fields are independent.
	if got := out[sso.KeyRecommendedLang]; got != "en-US" {
		t.Errorf("recommended_language = %v, want en-US (geo fallback)", got)
	}
}
