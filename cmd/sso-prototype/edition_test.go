package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/composition"
)

// TestPrototypeExposesOAuthWithoutOIDC is the prototype edition's surface
// contract: OIDC discovery and UserInfo are 404 (not merely disabled), no
// tracing headers, OAuth metadata carries no OIDC fields, and the token
// response has no id_token.
func TestPrototypeExposesOAuthWithoutOIDC(t *testing.T) {
	server, cfg := editionServer(t)
	assertStatus(t, server.URL+sso.PathOIDCDiscovery, http.StatusNotFound)
	assertStatus(t, server.URL+sso.PathUserInfo, http.StatusNotFound)
	assertStatus(t, server.URL+sso.PathEndSession, http.StatusNotFound)
	assertTracingHeaders(t, server.URL+sso.PathHealth, false)
	metadata := getJSON(t, server.URL+sso.PathOAuthAuthorizationServerMetadata, "")
	if metadata["subject_types_supported"] != nil {
		t.Fatalf("OAuth metadata contains OIDC fields: %v", metadata)
	}
	code := loginForCode(t, server.URL, cfg, testVerifier)
	tokens := exchangeCode(t, server.URL, cfg, code, testVerifier)
	if tokens["access_token"] == nil || tokens["id_token"] != nil {
		t.Fatalf("prototype token response = %v", tokens)
	}
}

// TestPrototypeScopesExcludeOpenid pins the seeded prototype scopes: the
// prototype clients must not carry the openid scope.
func TestPrototypeScopesExcludeOpenid(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	for _, scopes := range [][]string{cfg.Client.Scopes, cfg.Second.Scopes} {
		for _, scope := range scopes {
			if scope == "openid" {
				t.Fatalf("prototype seed scopes contain openid: %v", scopes)
			}
		}
	}
}

// TestPrototypeAcceptsScopesWithoutOpenid pins the relaxed prototype
// validation: the openid scope requirement is minimal-only.
func TestPrototypeAcceptsScopesWithoutOpenid(t *testing.T) {
	if _, err := composition.ParseRuntimeConfig(
		[]string{"--scopes", "profile,email"},
		func(string) string { return "" },
		io.Discard,
		edition,
	); err != nil {
		t.Fatalf("prototype without openid should validate: %v", err)
	}
}

func assertTracingHeaders(t *testing.T, endpoint string, want bool) {
	t.Helper()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	hasHeaders := resp.Header.Get(sso.HeaderRequestID) != "" &&
		resp.Header.Get(sso.HeaderTraceparent) != ""
	if hasHeaders != want {
		t.Fatalf("tracing headers present = %v, want %v: %v",
			hasHeaders, want, resp.Header)
	}
}

func editionServer(t *testing.T) (*httptest.Server, composition.RuntimeConfig) {
	t.Helper()
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "https://issuer.example"
	app, err := buildHandler(cfg)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	return server, cfg
}

func assertStatus(t *testing.T, endpoint string, want int) {
	t.Helper()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("GET %s = %d, want %d", endpoint, resp.StatusCode, want)
	}
}
