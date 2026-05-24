package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	discoIssuer = "https://sso.test"
)

func newDiscoveryServer(t *testing.T, withIDTokenIssuer bool) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "demo", Secret: "s", Active: true,
		AllowedScopes: []string{"read", "write"},
	})
	opts := []sso.Option{
		sso.WithIssuer(discoIssuer),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withIDTokenIssuer {
		opts = append(opts, sso.WithIDTokenIssuer(defaultimpl.NewEd25519JWTIssuer()))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func fetchDiscovery(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v body=%s", err, raw)
	}
	return out
}

func TestDiscovery_AdvertisesRequiredFields(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)

	// Required per OIDC Discovery 1.0 §3 + RFC 8414.
	required := []string{
		"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
		"response_types_supported", "subject_types_supported",
	}
	for _, k := range required {
		if doc[k] == nil {
			t.Errorf("missing required field %q in discovery doc", k)
		}
	}
	if doc["id_token_signing_alg_values_supported"] == nil {
		t.Error("id_token_signing_alg_values_supported missing — required when ID token issuer wired")
	}
}

func TestDiscovery_IssuerComesFromWithIssuer(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	if doc["issuer"] != discoIssuer {
		t.Errorf("issuer = %v want %q", doc["issuer"], discoIssuer)
	}
}

func TestDiscovery_EndpointsAreAbsoluteURLs(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	for _, k := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "introspection_endpoint", "revocation_endpoint", "end_session_endpoint",
	} {
		v, _ := doc[k].(string)
		if v == "" {
			t.Errorf("%s empty", k)
			continue
		}
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			t.Errorf("%s = %q, must be absolute http(s) URL", k, v)
		}
	}
}

func TestDiscovery_GrantTypesIncludesAllSupported(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	grants, _ := doc["grant_types_supported"].([]any)
	if len(grants) == 0 {
		t.Fatal("grant_types_supported missing/empty")
	}
	found := map[string]bool{}
	for _, g := range grants {
		s, _ := g.(string)
		found[s] = true
	}
	for _, expected := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		if !found[expected] {
			t.Errorf("grant %q missing from discovery", expected)
		}
	}
}

func TestDiscovery_PKCEMethodsAdvertised(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) == 0 {
		t.Fatal("code_challenge_methods_supported missing")
	}
	found := map[string]bool{}
	for _, m := range methods {
		s, _ := m.(string)
		found[s] = true
	}
	if !found["S256"] || !found["plain"] {
		t.Errorf("methods = %v want both S256 + plain", methods)
	}
}

func TestDiscovery_PKCEMethodsDropPlainUnderOAuth21Strict(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "demo", Secret: "s", Active: true})
	srv := sso.NewServer(
		sso.WithIssuer(discoIssuer),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithOAuth21StrictMode(true),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	doc := fetchDiscovery(t, httpSrv)
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 {
		t.Fatalf("strict mode methods = %v, want [S256] only", methods)
	}
	if methods[0] != "S256" {
		t.Errorf("methods[0] = %v, want S256", methods[0])
	}
}

func TestDiscovery_ScopesUnionFromClientAndOpenID(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	scopes, _ := doc["scopes_supported"].([]any)
	if len(scopes) == 0 {
		t.Fatal("scopes_supported missing/empty")
	}
	found := map[string]bool{}
	for _, s := range scopes {
		v, _ := s.(string)
		found[v] = true
	}
	if !found["openid"] {
		t.Error("openid scope missing despite ID token issuer wired")
	}
	if !found["read"] || !found["write"] {
		t.Errorf("client AllowedScopes not propagated: %v", scopes)
	}
}

func TestDiscovery_NoIDTokenIssuerOmitsSigningAlgs(t *testing.T) {
	srv := newDiscoveryServer(t, false) // no WithIDTokenIssuer
	doc := fetchDiscovery(t, srv)
	if v := doc["id_token_signing_alg_values_supported"]; v != nil {
		t.Errorf("id_token_signing_alg_values_supported should be omitted when no ID token issuer: %v", v)
	}
	// openid scope should NOT be advertised when there's no ID token
	// issuer (otherwise RPs assume OIDC and break).
	scopes, _ := doc["scopes_supported"].([]any)
	for _, s := range scopes {
		if s == "openid" {
			t.Error("openid scope advertised without ID token issuer")
		}
	}
}

func TestDiscovery_RespectsXForwardedProto(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/openid-configuration", nil)
	r.Host = "public.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "public.example.com")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	tok, _ := out["token_endpoint"].(string)
	if !strings.HasPrefix(tok, "https://public.example.com") {
		t.Errorf("token_endpoint = %q, want absolute https://public.example.com…", tok)
	}
}

func TestDiscovery_ClaimsAdvertised(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	claims, _ := doc["claims_supported"].([]any)
	if len(claims) == 0 {
		t.Fatal("claims_supported missing")
	}
	found := map[string]bool{}
	for _, c := range claims {
		s, _ := c.(string)
		found[s] = true
	}
	// Spot-check OIDC core claims.
	for _, c := range []string{"sub", "iss", "aud", "exp", "iat", "nonce", "auth_time", "amr"} {
		if !found[c] {
			t.Errorf("claim %q not advertised", c)
		}
	}
}

func TestDiscovery_DisplayValuesAdvertised(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	dv, _ := doc["display_values_supported"].([]any)
	if len(dv) == 0 {
		t.Fatal("display_values_supported missing")
	}
	found := false
	for _, v := range dv {
		if v == "page" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("display_values_supported = %v, want to contain \"page\"", dv)
	}
}

func TestDiscovery_DegradesGracefullyOnEmptyClientStore(t *testing.T) {
	// Server with no ClientStore — discovery MUST still respond, just
	// without the client-derived scopes.
	srv := sso.NewServer(
		sso.WithIssuer(discoIssuer),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithIDTokenIssuer(defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded but functional)", resp.StatusCode)
	}
}

// Smoke: every discovery field name should follow OIDC's snake_case
// convention so RPs can parse the doc without normalization.
func TestDiscovery_SnakeCaseFieldNames(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	for k := range doc {
		if strings.ContainsAny(k, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("field %q is not snake_case", k)
		}
	}
	_ = context.Background()
}
