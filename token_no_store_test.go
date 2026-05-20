package sso_test

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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}
