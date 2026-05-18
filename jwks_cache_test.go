package sso_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newJWKSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestJWKS_CacheControlHeader(t *testing.T) {
	srv := newJWKSServer(t)
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q want public + max-age", cc)
	}
}

func TestJWKS_ETagPresent(t *testing.T) {
	srv := newJWKSServer(t)
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("ETag missing")
	}
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Errorf("ETag = %q must be quoted (strong validator)", etag)
	}
}

func TestJWKS_ETagStableAcrossRequests(t *testing.T) {
	srv := newJWKSServer(t)
	resp1, _ := http.Get(srv.URL + "/.well-known/jwks.json")
	resp1.Body.Close()
	resp2, _ := http.Get(srv.URL + "/.well-known/jwks.json")
	resp2.Body.Close()
	if resp1.Header.Get("ETag") != resp2.Header.Get("ETag") {
		t.Errorf("ETag drifted between identical requests: %q vs %q",
			resp1.Header.Get("ETag"), resp2.Header.Get("ETag"))
	}
}

func TestJWKS_IfNoneMatchReturns304(t *testing.T) {
	srv := newJWKSServer(t)
	// First request: capture ETag.
	resp1, _ := http.Get(srv.URL + "/.well-known/jwks.json")
	resp1.Body.Close()
	etag := resp1.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag from first request")
	}
	// Second request with If-None-Match: server must return 304.
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/jwks.json", nil)
	r.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("conditional GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("status = %d want 304", resp2.StatusCode)
	}
}

func TestJWKS_IfNoneMatchMismatchReturns200(t *testing.T) {
	srv := newJWKSServer(t)
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/jwks.json", nil)
	r.Header.Set("If-None-Match", `"some-stale-etag"`)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d want 200 (stale ETag should fall through)", resp.StatusCode)
	}
}

func TestJWKS_DifferentIssuerProducesDifferentETag(t *testing.T) {
	// Two servers with different keys must produce different JWKS ETags
	// (the kid + x fields differ).
	srv1 := newJWKSServer(t)
	srv2 := newJWKSServer(t)
	resp1, _ := http.Get(srv1.URL + "/.well-known/jwks.json")
	resp1.Body.Close()
	resp2, _ := http.Get(srv2.URL + "/.well-known/jwks.json")
	resp2.Body.Close()
	if resp1.Header.Get("ETag") == resp2.Header.Get("ETag") {
		t.Error("ETags match across different issuers — ETag computation is broken")
	}
}
