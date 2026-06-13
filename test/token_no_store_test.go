package ssotest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newNoStoreHarness(t *testing.T) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "ns-c", Secret: "ns-s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestTokenEndpoint_NoStoreCacheHeaders(t *testing.T) {
	srv := newNoStoreHarness(t)
	// Hit /token with a bad request — error response still must
	// carry the no-store headers per RFC 6749 §5.1.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token",
		strings.NewReader("grant_type=invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}
}

func TestRevokeEndpoint_NoStoreCacheHeaders(t *testing.T) {
	srv := newNoStoreHarness(t)
	resp, err := http.Post(srv.URL+"/token/revoke", "application/x-www-form-urlencoded",
		bytes.NewReader([]byte("token=x&client_id=ns-c&client_secret=ns-s")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestIntrospectEndpoint_NoStoreCacheHeaders(t *testing.T) {
	srv := newNoStoreHarness(t)
	resp, err := http.Post(srv.URL+"/token/introspect", "application/x-www-form-urlencoded",
		bytes.NewReader([]byte("token=x&client_id=ns-c&client_secret=ns-s")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestLoginEndpoint_NoStoreCacheHeaders(t *testing.T) {
	// /auth/login bodies carry access_token + refresh_token. Same
	// §5.1 rule the /token endpoint follows. Hit with a malformed
	// request — error responses must stamp the headers too.
	srv := newNoStoreHarness(t)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestUserInfoEndpoint_NoStoreCacheHeaders(t *testing.T) {
	// /userinfo returns subject claims. An intermediary cache could
	// otherwise serve user A's profile to user B's bearer.
	srv := newNoStoreHarness(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	// Intentionally no bearer — endpoint 401s but still must stamp
	// the headers per RFC 6749 §5.1 (error responses included).
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestRegisterEndpoint_NoStoreCacheHeaders(t *testing.T) {
	// DCR /register returns client_secret + registration_access_token.
	srv := newNoStoreHarness(t)
	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestRegistrationGetEndpoint_NoStoreCacheHeaders(t *testing.T) {
	// RFC 7592 GET /register/:id returns the full client record
	// (including secret on some impls). Even on 401-unauthed paths.
	srv := newNoStoreHarness(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/register/ns-c", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}
