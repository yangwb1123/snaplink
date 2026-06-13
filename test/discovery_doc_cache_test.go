package ssotest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newDiscoveryDocCacheHarness(t *testing.T, ttl time.Duration) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "doc-c", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDiscoveryDocCacheTTL(ttl),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestDiscoveryDocCache_ServesETagAndCacheControl(t *testing.T) {
	srv := newDiscoveryDocCacheHarness(t, time.Minute)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if etag := resp.Header.Get("ETag"); etag == "" || !strings.HasPrefix(etag, `"`) {
		t.Fatalf("ETag = %q want non-empty quoted strong validator", etag)
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.HasPrefix(cc, "public, max-age=") {
		t.Fatalf("Cache-Control = %q want public max-age", cc)
	}
}

func TestDiscoveryDocCache_HonorsIfNoneMatch(t *testing.T) {
	srv := newDiscoveryDocCacheHarness(t, time.Minute)
	first, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	_ = first.Body.Close()
	etag := first.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first response")
	}

	req, _ := http.NewRequest("GET", srv.URL+"/.well-known/openid-configuration", nil)
	req.Header.Set("If-None-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304", resp.StatusCode)
	}
}

func TestDiscoveryDocCache_ETagStableAcrossRefetches(t *testing.T) {
	srv := newDiscoveryDocCacheHarness(t, time.Minute)
	first, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	_ = first.Body.Close()
	second, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	_ = second.Body.Close()
	if a, b := first.Header.Get("ETag"), second.Header.Get("ETag"); a != b {
		t.Fatalf("ETag drift: first=%q second=%q (cache should be stable within TTL)", a, b)
	}
}

func TestDiscoveryDocCache_DisabledByZeroTTL(t *testing.T) {
	// With ttl=0 the body still renders correctly; we just don't
	// cache it across requests.
	srv := newDiscoveryDocCacheHarness(t, 0)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	// No ETag or Cache-Control: caching disabled. The handler falls
	// back to the legacy ctx.JSON path which doesn't set them.
	if etag := resp.Header.Get("ETag"); etag != "" {
		t.Errorf("ETag = %q want empty when caching disabled", etag)
	}
}

func TestDiscoveryDocCache_BodyMatchesCachedAndUncached(t *testing.T) {
	// Sanity: a hot cache hit returns byte-identical body to the
	// initial render, so RP libraries that depend on stable ordering
	// don't trip when the cache flips.
	srv := newDiscoveryDocCacheHarness(t, time.Minute)
	a, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	bodyA := readAllBody(t, a)
	_ = a.Body.Close()
	b, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	bodyB := readAllBody(t, b)
	_ = b.Body.Close()
	if bodyA != bodyB {
		t.Fatalf("body drift between consecutive fetches under cache:\nA=%s\nB=%s", bodyA, bodyB)
	}
}

func readAllBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf)
}
