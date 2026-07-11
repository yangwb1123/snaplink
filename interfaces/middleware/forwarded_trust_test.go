package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// captureBase records what BaseURL resolved inside the middleware chain so
// tests can assert the peer-trust gate on X-Forwarded-Proto/Host.
type captureBase struct {
	got     string
	trusted bool
}

func (c *captureBase) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.got = BaseURL(r)
	c.trusted = ForwardedHeadersTrusted(r)
	w.WriteHeader(http.StatusOK)
}

func forwardedReq(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://local.host/token", nil)
	r.Host = "local.host"
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "public.example.com")
	return r
}

func TestBaseURL_TrustedPeer_HonorsForwardedHeaders(t *testing.T) {
	t.Parallel()
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureBase{}
	tp.Middleware(cap).ServeHTTP(httptest.NewRecorder(), forwardedReq("10.0.0.1:443"))

	if !cap.trusted {
		t.Error("trusted peer: ForwardedHeadersTrusted = false, want true")
	}
	if cap.got != "https://public.example.com" {
		t.Errorf("trusted peer BaseURL = %q, want https://public.example.com", cap.got)
	}
}

func TestBaseURL_UntrustedPeer_FallsBackToDirectValues(t *testing.T) {
	t.Parallel()
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureBase{}
	tp.Middleware(cap).ServeHTTP(httptest.NewRecorder(), forwardedReq("203.0.113.9:443"))

	if cap.trusted {
		t.Error("untrusted peer: ForwardedHeadersTrusted = true, want false")
	}
	// Direct values: no TLS on the request → http; r.Host, not the forged
	// X-Forwarded-Host.
	if cap.got != "http://local.host" {
		t.Errorf("untrusted peer BaseURL = %q, want http://local.host", cap.got)
	}
}

func TestBaseURL_NoMiddleware_LegacyFirstHopTrust(t *testing.T) {
	t.Parallel()
	// Unset knob (no TrustedProxies in the chain) must stay byte-identical
	// to the legacy behavior: forwarded headers honored unconditionally.
	r := forwardedReq("203.0.113.9:443")
	if got := BaseURL(r); got != "https://public.example.com" {
		t.Errorf("no middleware BaseURL = %q, want https://public.example.com", got)
	}
	if !ForwardedHeadersTrusted(r) {
		t.Error("no middleware: ForwardedHeadersTrusted = false, want true (legacy)")
	}
}

func TestTrustedProxies_UntrustedPeer_XFFIgnoredForClientIP(t *testing.T) {
	t.Parallel()
	// The XFF chain walk must not run for a direct peer outside the trusted
	// CIDRs: the whole header is peer-forged, so the rate-limit key
	// (ratelimit.KeyByClientIP → RealClientIP) falls back to RemoteAddr.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	r.RemoteAddr = "203.0.113.9:1234"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "203.0.113.9" {
		t.Errorf("untrusted peer RealClientIP = %q, want 203.0.113.9 (RemoteAddr)", cap.got)
	}
}

func TestForwardedHeadersTrusted_NilRequest(t *testing.T) {
	t.Parallel()
	if !ForwardedHeadersTrusted(nil) {
		t.Error("nil request: ForwardedHeadersTrusted = false, want true (legacy default)")
	}
}
