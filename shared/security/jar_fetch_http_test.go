package security_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/security"
)

// HTTPJARFetcher fetches a signed JAR JWT from an HTTPS request_uri.
// The interesting surface is all SSRF/defense hardening: HTTPS-only,
// redirect-free, body-size cap, request timeout, status gating.

// tlsFetcher returns a fetcher whose http.Client trusts srv's self-
// signed cert but RETAINS the production no-redirect policy + timeout
// so the redirect/timeout assertions still exercise the real client.
func tlsFetcher(srv *httptest.Server, timeout time.Duration, maxBytes int64) *security.HTTPJARFetcher {
	client := srv.Client() // trusts the test TLS cert
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &security.HTTPJARFetcher{Client: client, MaxBytes: maxBytes}
}

func TestHTTPJARFetcher_Defaults(t *testing.T) {
	t.Parallel()
	f := security.NewHTTPJARFetcher()
	if f.MaxBytes != security.DefaultJARFetchMaxBytes {
		t.Errorf("MaxBytes = %d, want %d", f.MaxBytes, security.DefaultJARFetchMaxBytes)
	}
	if f.Client == nil {
		t.Fatal("default fetcher has nil client")
	}
	if f.Client.Timeout != security.DefaultJARFetchTimeout {
		t.Errorf("Timeout = %v, want %v", f.Client.Timeout, security.DefaultJARFetchTimeout)
	}
}

func TestHTTPJARFetcher_HappyPath(t *testing.T) {
	t.Parallel()
	const body = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJycCJ9.sig"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	f := tlsFetcher(srv, 5*time.Second, security.DefaultJARFetchMaxBytes)
	got, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestHTTPJARFetcher_RejectsNonHTTPS(t *testing.T) {
	t.Parallel()
	f := security.NewHTTPJARFetcher()
	for _, uri := range []string{
		"http://internal/jar",
		"file:///etc/passwd",
		"ftp://host/jar",
		"HTTPS://upper.example/jar", // case-sensitive prefix gate
	} {
		if _, err := f.Fetch(context.Background(), uri); err == nil {
			t.Errorf("Fetch(%q) accepted a non-https URI", uri)
		}
	}
}

func TestHTTPJARFetcher_NoFollowRedirect(t *testing.T) {
	t.Parallel()
	// A 302 toward an internal target must NOT be followed — the body
	// of the redirect response (not the target) is returned, and since
	// it's a 3xx status the fetch is rejected.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer srv.Close()

	f := tlsFetcher(srv, 5*time.Second, security.DefaultJARFetchMaxBytes)
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("Fetch followed a redirect (SSRF pivot not blocked)")
	}
}

func TestHTTPJARFetcher_RejectsNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := tlsFetcher(srv, 5*time.Second, security.DefaultJARFetchMaxBytes)
	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Fetch accepted a 404")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("err = %v, want status-coded error", err)
	}
}

func TestHTTPJARFetcher_BodySizeCap(t *testing.T) {
	t.Parallel()
	// Body strictly larger than the cap must be rejected, not silently
	// truncated (a truncated JWT would fail signature verify later).
	const cap = 32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", cap+10)))
	}))
	defer srv.Close()

	f := tlsFetcher(srv, 5*time.Second, cap)
	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("Fetch accepted an over-cap body")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v, want size-cap error", err)
	}
}

func TestHTTPJARFetcher_ExactCapAccepted(t *testing.T) {
	t.Parallel()
	const cap = 32
	body := strings.Repeat("A", cap) // exactly at the cap is fine
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	f := tlsFetcher(srv, 5*time.Second, cap)
	got, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch at exact cap: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q", got)
	}
}

func TestHTTPJARFetcher_ZeroMaxBytesUsesDefault(t *testing.T) {
	t.Parallel()
	const body = "small.jwt.body"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// MaxBytes<=0 falls back to DefaultJARFetchMaxBytes inside Fetch.
	f := tlsFetcher(srv, 5*time.Second, 0)
	got, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch with zero MaxBytes: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q", got)
	}
}

func TestHTTPJARFetcher_Timeout(t *testing.T) {
	t.Parallel()
	released := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released // hang until the test releases, well past the client timeout
	}))
	defer srv.Close()
	defer close(released)

	f := tlsFetcher(srv, 50*time.Millisecond, security.DefaultJARFetchMaxBytes)
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("Fetch did not time out on a hanging server")
	}
}

func TestHTTPJARFetcher_ContextCancel(t *testing.T) {
	t.Parallel()
	released := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-released
	}))
	defer srv.Close()
	defer close(released)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled context fails the round-trip immediately
	f := tlsFetcher(srv, 5*time.Second, security.DefaultJARFetchMaxBytes)
	if _, err := f.Fetch(ctx, srv.URL); err == nil {
		t.Fatal("Fetch ignored a cancelled context")
	}
}

func TestHTTPJARFetcher_NilClientUsesDefault(t *testing.T) {
	t.Parallel()
	// With a nil Client the fetcher falls back to http.DefaultClient.
	// A non-https URI still fails the scheme gate before any dial, so
	// this exercises the nil-client branch without a network round-trip.
	f := &security.HTTPJARFetcher{Client: nil, MaxBytes: security.DefaultJARFetchMaxBytes}
	if _, err := f.Fetch(context.Background(), "http://internal/jar"); err == nil {
		t.Fatal("nil-client fetcher accepted non-https URI")
	}
}

func TestHTTPJARFetcher_BadURL(t *testing.T) {
	t.Parallel()
	f := security.NewHTTPJARFetcher()
	// Passes the https:// prefix gate but is not a parseable URL.
	if _, err := f.Fetch(context.Background(), "https://exa mple.com/\x7f"); err == nil {
		t.Fatal("Fetch accepted an unparseable https URL")
	}
}
