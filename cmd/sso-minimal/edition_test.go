package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/composition"
)

func TestMinimalAddsOIDCAndTracing(t *testing.T) {
	server, cfg := editionServer(t)
	assertStatus(t, server.URL+sso.PathOIDCDiscovery, http.StatusOK)
	code := loginForCode(t, server.URL, cfg, testVerifier)
	tokens := exchangeCode(t, server.URL, cfg, code, testVerifier)
	if tokens["id_token"] == nil {
		t.Fatalf("minimal token response = %v", tokens)
	}
	assertTracingHeaders(t, server.URL+sso.PathHealth, false)
	assertRequestIDHeader(t, server.URL+sso.PathHealth, true)
}

func TestMinimalRequiresOpenidScope(t *testing.T) {
	_, err := composition.ParseRuntimeConfig(
		[]string{"--scopes", "profile"},
		func(string) string { return "" },
		io.Discard,
		edition,
	)
	if err == nil || !strings.Contains(err.Error(), "openid") {
		t.Fatalf("minimal without openid error = %v, want openid requirement", err)
	}
}

func TestMinimalServesUserInfoAndEndSession(t *testing.T) {
	server, _ := editionServer(t)
	// The routes exist in the minimal edition: without a credential they must
	// fail with an auth error, never a surface 404.
	for _, path := range []string{sso.PathUserInfo, sso.PathEndSession} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("GET %s = 404, want the route served", path)
		}
	}
}

// assertTracingHeaders asserts the FULL legacy header set (X-Request-Id +
// Traceparent). After Decision 7 (docs/design/middleware-observability-unified.md)
// the Traceparent response header is emitted ONLY when a real OTel provider
// is active (no-op provider → invalid span → no Traceparent, no X-Trace-Id).
// The edition tests run without a provider, so `want` is always false here;
// the X-Request-Id surface (which works without a provider) is asserted
// separately via assertRequestIDHeader.
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

// assertRequestIDHeader asserts X-Request-Id presence/absence — the
// correlation surface that works even without an OTel provider (Decision
// 7/12: the request-id contract survives every tracing shape).
func assertRequestIDHeader(t *testing.T, endpoint string, want bool) {
	t.Helper()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	has := resp.Header.Get(sso.HeaderRequestID) != ""
	if has != want {
		t.Fatalf("X-Request-Id present = %v, want %v: %v", has, want, resp.Header)
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
