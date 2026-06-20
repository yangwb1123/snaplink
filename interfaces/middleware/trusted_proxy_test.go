package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeTrustedProxies is a test helper that panics on construction error
// to keep table-driven test bodies concise.
func makeTrustedProxies(t *testing.T, cidrs []string, hops int) *TrustedProxies {
	t.Helper()
	tp, err := NewTrustedProxies(cidrs, hops)
	if err != nil {
		t.Fatalf("NewTrustedProxies(%v, %d): %v", cidrs, hops, err)
	}
	return tp
}

func TestNewTrustedProxies_InvalidCIDR(t *testing.T) {
	_, err := NewTrustedProxies([]string{"not-a-cidr"}, 0)
	if err == nil {
		t.Fatal("expected parse error for invalid CIDR, got nil")
	}
}

// captureIP is a minimal http.Handler that stores the RealClientIP result
// so tests can assert on it.
type captureIP struct {
	got string
}

func (c *captureIP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.got = RealClientIP(r)
	w.WriteHeader(http.StatusOK)
}

func TestTrustedProxies_SingleTier(t *testing.T) {
	// One trusted proxy tier (10.0.0.1/32). The XFF contains two entries:
	// the real client (1.2.3.4) and the trusted proxy (10.0.0.1). The
	// middleware should peel the trusted proxy and return the client IP.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	r.RemoteAddr = "10.0.0.1:54321"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "1.2.3.4" {
		t.Errorf("single tier: got %q, want 1.2.3.4", cap.got)
	}
}

func TestTrustedProxies_TwoTiers(t *testing.T) {
	// Two trusted proxy tiers. XFF = "client, proxy1, proxy2".
	// Both proxies are in the 10.0.0.0/8 range; client is untrusted.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 2)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.2, 10.0.0.3")
	r.RemoteAddr = "10.0.0.3:12345"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "5.6.7.8" {
		t.Errorf("two tiers: got %q, want 5.6.7.8", cap.got)
	}
}

func TestTrustedProxies_ForgedHeader(t *testing.T) {
	// Attacker prepends a spoofed IP to the XFF chain:
	// XFF = "forge, real-client, trusted-proxy".
	// The trusted proxy set the real client IP; the attacker's entry is
	// leftmost. Walking right-to-left with hops=1:
	//   10.0.0.1 (trusted, hops 1→0, continue)
	//   5.6.7.8  (untrusted, return here — this is the real client)
	// The forge entry (9.9.9.9) is never reached.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 1)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 5.6.7.8, 10.0.0.1")
	r.RemoteAddr = "10.0.0.1:8080"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "5.6.7.8" {
		t.Errorf("forged header: got %q, want 5.6.7.8 (should not trust leftmost forge)", cap.got)
	}
}

func TestTrustedProxies_NoXFF_FallsBackToRemoteAddr(t *testing.T) {
	// No X-Forwarded-For header at all — return RemoteAddr with port stripped.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 0)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:43210"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "203.0.113.5" {
		t.Errorf("no XFF: got %q, want 203.0.113.5", cap.got)
	}
}

func TestTrustedProxies_AllTrusted_ReturnsLeftmost(t *testing.T) {
	// Every hop in XFF is trusted. The leftmost entry is the best
	// approximation of the original client (all hops were our own
	// infrastructure).
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 3)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "10.1.1.1, 10.2.2.2, 10.3.3.3")
	r.RemoteAddr = "10.3.3.3:9000"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "10.1.1.1" {
		t.Errorf("all trusted: got %q, want 10.1.1.1 (leftmost)", cap.got)
	}
}

func TestRealClientIP_NoMiddleware_FallsBackToRemoteAddr(t *testing.T) {
	// RealClientIP with no TrustedProxies middleware in the chain must
	// return r.RemoteAddr (port stripped) — byte-identical to today's
	// unconditional XFF read, but without a nil-panic.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.RemoteAddr = "10.0.0.1:55555"

	got := RealClientIP(r)
	if got != "10.0.0.1" {
		t.Errorf("no middleware fallback: got %q, want 10.0.0.1 (RemoteAddr)", got)
	}
}

func TestTrustedProxies_NilMiddleware_Passthrough(t *testing.T) {
	// A nil *TrustedProxies wrapping a handler must not panic — it passes
	// through unchanged (no-op deployment guard).
	var tp *TrustedProxies
	called := false
	h := tp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("nil TrustedProxies.Middleware: inner handler was not called")
	}
}

func TestTrustedProxies_HopsBudget_LimitsStripping(t *testing.T) {
	// The CIDR covers all 10/8 addresses, but hops=1 limits stripping to
	// one trusted proxy tier. XFF = "9.9.9.9, 10.0.0.10, 10.0.0.20".
	//
	// Walk right-to-left:
	//   10.0.0.20 (trusted, hops 1→0, continue)
	//   10.0.0.10 (trusted, hops==0 → budget exhausted → return parts[i-1] = 9.9.9.9)
	//
	// 9.9.9.9 is returned because the hop budget prevents us from peeling
	// more than one proxy tier, so 10.0.0.10 is treated as the boundary
	// and the entry to its left is the client.
	tp := makeTrustedProxies(t, []string{"10.0.0.0/8"}, 1)
	cap := &captureIP{}
	h := tp.Middleware(cap)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 10.0.0.10, 10.0.0.20")
	r.RemoteAddr = "10.0.0.20:80"

	h.ServeHTTP(httptest.NewRecorder(), r)

	if cap.got != "9.9.9.9" {
		t.Errorf("hops budget: got %q, want 9.9.9.9", cap.got)
	}
}

func TestRealClientIP_IPv6RemoteAddr(t *testing.T) {
	// IPv6 RemoteAddr with bracket notation must strip the port correctly.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[::1]:8080"

	got := RealClientIP(r)
	if got != "::1" {
		t.Errorf("IPv6 RemoteAddr: got %q, want ::1", got)
	}
}
