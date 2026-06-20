package ssotest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

func newBodyLimitHarness(t *testing.T, opts ...sso.Option) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "bl-c", Secret: "s", Active: true})
	base := []sso.Option{
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), time.Minute),
	}
	srv := sso.NewServer(append(base, opts...)...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestBodyLimitPath_OverrideAllowsLargerOnSpecificPath(t *testing.T) {
	// Global cap 200 bytes; /par bumped to 16 KiB. A 1 KiB body to
	// /par succeeds; the same body to /token (or anywhere else)
	// is rejected with 413.
	srv := newBodyLimitHarness(t,
		sso.WithBodyLimit(200),
		sso.WithBodyLimitForPath("/par", 16*1024),
	)
	body := strings.Repeat("a", 1024)

	resp := postRaw(t, srv.URL+"/par", body)
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Errorf("/par rejected at 1KiB despite 16KiB override: status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = postRaw(t, srv.URL+"/token", body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("/token accepted 1KiB body despite 200B global cap: status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestBodyLimitPath_LongestPrefixWins(t *testing.T) {
	// Overrides MUST resolve longest-prefix-first: a 4-byte cap on
	// /token shouldn't override the 16 KiB cap on /token/revoke if
	// both are registered. Crafted so the longer prefix is small
	// and the shorter prefix is large — flipping the order would
	// let the test reject a body that should pass.
	srv := newBodyLimitHarness(t,
		sso.WithBodyLimit(0), // no global
		sso.WithBodyLimitForPath("/token", 4),
		sso.WithBodyLimitForPath("/token/revoke", 16*1024),
	)
	body := strings.Repeat("x", 1024)

	resp := postRaw(t, srv.URL+"/token/revoke", body)
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Errorf("/token/revoke rejected: longest-prefix rule failed (4B cap leaked through)")
	}
	_ = resp.Body.Close()

	resp = postRaw(t, srv.URL+"/token", body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("/token accepted 1KiB despite 4B cap: status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestBodyLimitPath_ZeroOverrideMeansUnlimited(t *testing.T) {
	// Global 100B cap; /par explicitly set to 0 (escape hatch).
	// /par accepts anything; everything else still hits 100B.
	srv := newBodyLimitHarness(t,
		sso.WithBodyLimit(100),
		sso.WithBodyLimitForPath("/par", 0),
	)
	body := strings.Repeat("z", 10*1024)

	resp := postRaw(t, srv.URL+"/par", body)
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Errorf("/par rejected despite unlimited (0) override: status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func postRaw(t *testing.T, url, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	return resp
}
