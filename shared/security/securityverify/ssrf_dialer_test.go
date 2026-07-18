package securityverify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// SSRFGuardedDialer is the shared dial-time SSRF gate consumed by both the
// JAR request_uri fetcher (this package) and the federation trust-chain
// fetcher (domains/federation). The load-bearing contract: the IPs actually
// RESOLVED at connect time are re-validated in the same call that dials, so a
// public-looking hostname whose DNS record points at an internal address (DNS
// rebinding) is refused with no TOCTOU window. Rejections carry the
// "(SSRF guard)" marker so a guard rejection is distinguishable from a
// downstream connect failure.

// fakeResolver returns a LookupHost seam that resolves every host to addrs —
// the deterministic stand-in for an attacker-controlled DNS record.
func fakeResolver(addrs ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return addrs, nil }
}

func guardedDialer(lookup func(context.Context, string) ([]string, error)) *SSRFGuardedDialer {
	return &SSRFGuardedDialer{ErrPrefix: "jar_fetch", Timeout: 2 * time.Second, LookupHost: lookup}
}

// mustRejectDial asserts the dial fails WITH the SSRF-guard marker — i.e. the
// resolved/literal IP was inspected and refused before any connect attempt.
func mustRejectDial(t *testing.T, d *SSRFGuardedDialer, addr string) {
	t.Helper()
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("DialContext(%q): expected SSRF rejection, got nil", addr)
	}
	if !strings.Contains(err.Error(), "(SSRF guard)") {
		t.Fatalf("DialContext(%q): err = %v, want SSRF-guard rejection", addr, err)
	}
}

func TestSSRFGuardedDialer_BlocksLiteralInternalIPs(t *testing.T) {
	t.Parallel()
	d := guardedDialer(nil) // literal IPs never hit the resolver
	for _, addr := range []string{
		"127.0.0.1:80",
		"169.254.169.254:80", // cloud metadata / IMDS
		"10.0.0.1:80",
		"172.16.0.1:443",
		"192.168.1.1:80",
		"[::1]:443",
		"0.0.0.0:80",
		"[fe80::1]:80",          // v6 link-local
		"[fd00::1]:443",         // ULA (RFC 4193)
		"[::ffff:10.0.0.1]:80",  // IPv4-mapped v6 wrapping RFC 1918
		"[::ffff:127.0.0.1]:80", // IPv4-mapped v6 wrapping loopback
	} {
		mustRejectDial(t, d, addr)
	}
}

// TestSSRFGuardedDialer_BlocksRebindingResolution is the DNS-rebinding core:
// a NON-literal hostname whose injected resolution is internal must be
// refused at dial time, per resolved address — including a mixed answer where
// only ONE of the records is internal (an attacker can hide the internal IP
// behind a public one in the same RRset).
func TestSSRFGuardedDialer_BlocksRebindingResolution(t *testing.T) {
	t.Parallel()
	for name, addrs := range map[string][]string{
		"loopback":              {"127.0.0.1"},
		"IMDS link-local":       {"169.254.169.254"},
		"RFC1918":               {"10.0.0.5"},
		"mixed public+internal": {"203.0.113.7", "192.168.1.10"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mustRejectDial(t, guardedDialer(fakeResolver(addrs...)), "public.example.com:443")
		})
	}
}

// TestSSRFGuardedDialer_DefaultResolverBlocksLocalhost proves the nil-seam
// default (net.DefaultResolver) path also rejects: "localhost" is a
// non-literal host every resolver maps to loopback. A real listener makes the
// test non-vacuous — absent the guard the dial WOULD succeed.
func TestSSRFGuardedDialer_DefaultResolverBlocksLocalhost(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	mustRejectDial(t, guardedDialer(nil), net.JoinHostPort("localhost", port))
}

func TestSSRFGuardedDialer_ResolverFailuresRefuseDial(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		addrs   []string
		wantErr string
	}{
		"empty answer":       {addrs: nil, wantErr: "no addresses"},
		"unparseable record": {addrs: []string{"not-an-ip"}, wantErr: "unparseable"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := guardedDialer(fakeResolver(tc.addrs...))
			conn, err := d.DialContext(context.Background(), "tcp", "public.example.com:443")
			if err == nil {
				_ = conn.Close()
				t.Fatal("expected refusal, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestSSRFGuardedDialer_PublicResolutionPassesGuard proves the guard does not
// wrongly block a legitimate host: a resolution to TEST-NET-1 (192.0.2.0/24,
// RFC 5737 — not internal per the blocklist, guaranteed unroutable) passes
// validation and reaches the CONNECT stage, so any failure is a connect
// error, never the guard marker.
func TestSSRFGuardedDialer_PublicResolutionPassesGuard(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d := guardedDialer(fakeResolver("192.0.2.1"))
	conn, err := d.DialContext(ctx, "tcp", "public.example.com:443")
	if err == nil {
		_ = conn.Close()
		return
	}
	if strings.Contains(err.Error(), "(SSRF guard)") {
		t.Fatalf("public resolution wrongly blocked by SSRF guard: %v", err)
	}
}

func TestIsInternalIP_Classification(t *testing.T) {
	t.Parallel()
	for ipStr, want := range map[string]bool{
		"127.0.0.1":            true,
		"10.1.2.3":             true,
		"172.16.0.1":           true,
		"192.168.0.1":          true,
		"169.254.169.254":      true,
		"0.0.0.0":              true,
		"::1":                  true,
		"::":                   true,
		"fe80::1":              true,
		"fd12:3456::1":         true, // ULA
		"::ffff:192.168.1.1":   true, // v4-mapped private
		"8.8.8.8":              false,
		"192.0.2.1":            false, // TEST-NET-1: unroutable but not "internal"
		"2001:4860:4860::8888": false,
	} {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("bad test IP %q", ipStr)
		}
		if got := IsInternalIP(ip); got != want {
			t.Errorf("IsInternalIP(%s) = %v, want %v", ipStr, got, want)
		}
	}
}

// rebindTransport rewires the DEFAULT fetcher's transport dialer with an
// injected resolver, keeping everything else about the production client
// (timeout, no-redirect, transport shape) intact. The type assertion doubles
// as the wiring assertion: NewHTTPJARFetcher MUST install an *http.Transport
// carrying the SSRF-guarded DialContext.
func rebindTransport(t *testing.T, f *HTTPJARFetcher, lookup func(context.Context, string) ([]string, error)) {
	t.Helper()
	tr, ok := f.Client.Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		t.Fatalf("NewHTTPJARFetcher transport = %T, want *http.Transport with SSRF-guarded DialContext", f.Client.Transport)
	}
	tr.DialContext = guardedDialer(lookup).DialContext
}

// TestHTTPJARFetcher_RefusesRebindingHost is the JAR-level integration proof:
// an ALLOWLISTED-looking https URL whose hostname rebinds to loopback is
// refused at dial time. A real TLS server listens on that loopback port, so
// absent the guard the connection would be established — the guard marker in
// the error proves the resolved IP was rejected before any connect.
func TestHTTPJARFetcher_RefusesRebindingHost(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("eyJhbGciOiJFUzI1NiJ9.e30.sig"))
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split test server addr: %v", err)
	}

	f := NewHTTPJARFetcher()
	rebindTransport(t, f, fakeResolver("127.0.0.1"))
	_, err = f.Fetch(context.Background(), "https://rp.example.com:"+port+"/request.jwt")
	if err == nil {
		t.Fatal("Fetch succeeded through a rebinding host (SSRF window open)")
	}
	if !strings.Contains(err.Error(), "(SSRF guard)") {
		t.Fatalf("Fetch err = %v, want dial-time SSRF-guard rejection", err)
	}
}

// TestHTTPJARFetcher_PublicResolutionPassesGuard: same fetcher, same URL
// shape, but the injected resolution is public (TEST-NET-1) — the fetch must
// get PAST the SSRF gate to the connect stage (any error is a connect
// timeout, never the guard marker), proving legitimate public hosts are not
// blocked.
func TestHTTPJARFetcher_PublicResolutionPassesGuard(t *testing.T) {
	t.Parallel()
	f := NewHTTPJARFetcher()
	rebindTransport(t, f, fakeResolver("192.0.2.1"))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := f.Fetch(ctx, "https://rp.example.com/request.jwt")
	if err == nil {
		t.Fatal("Fetch to an unroutable TEST-NET address unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "(SSRF guard)") {
		t.Fatalf("public resolution wrongly blocked by SSRF guard: %v", err)
	}
}
