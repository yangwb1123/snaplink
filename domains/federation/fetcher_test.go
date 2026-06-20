package federation_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation"
)

// The httpFetcher is unexported, so these tests drive the SSRF gates through
// the PUBLIC resolver surface: the resolver's default fetcher is the hardened
// httpFetcher, and validateFederationURL is applied to every fetched URL
// (leaf entity id, authority hints, fetch endpoint). A leaf id / hint that
// fails the gate makes resolution reject WITHOUT a real outbound request.

// resolverWithDefaultFetcher builds a resolver that uses the REAL httpFetcher
// (no injected fake) so the SSRF gates + redirect/scheme policy run.
func resolverWithDefaultFetcher(t *testing.T, anchorID string) *federation.TrustChainResolver {
	t.Helper()
	cfg := &federation.Config{
		// A configured anchor with a dummy key so the resolver is Enabled; the
		// SSRF gate rejects before any key is used.
		TrustAnchors: []federation.TrustAnchor{{EntityID: anchorID, Keys: nil}},
	}
	return federation.NewTrustChainResolver(cfg)
}

// TestFetcher_RejectsHTTPLeaf: an http:// leaf entity id is rejected by the
// scheme gate (no outbound request).
func TestFetcher_RejectsHTTPLeaf(t *testing.T) {
	r := resolverWithDefaultFetcher(t, "https://anchor.test")
	_, err := r.ResolveTrustChain(context.Background(), "http://rp.internal.test")
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("http:// leaf: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestFetcher_RejectsFileScheme: a file:// leaf is rejected.
func TestFetcher_RejectsFileScheme(t *testing.T) {
	r := resolverWithDefaultFetcher(t, "https://anchor.test")
	_, err := r.ResolveTrustChain(context.Background(), "file:///etc/passwd")
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("file:// leaf: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestFetcher_RejectsInternalIPLeaf: an https leaf whose host is a literal
// internal IP is rejected by the best-effort internal-host block.
func TestFetcher_RejectsInternalIPLeaf(t *testing.T) {
	r := resolverWithDefaultFetcher(t, "https://anchor.test")
	for _, host := range []string{
		"https://127.0.0.1/rp",
		"https://169.254.169.254/latest/meta-data", // cloud metadata
		"https://10.0.0.5/rp",
		"https://192.168.1.10/rp",
		"https://[::1]/rp",
	} {
		_, err := r.ResolveTrustChain(context.Background(), host)
		if !errors.Is(err, federation.ErrTrustChainInvalid) {
			t.Errorf("internal host %q: err = %v, want ErrTrustChainInvalid", host, err)
		}
	}
}

// TestFetcher_NoRedirectFollowed: an https endpoint that 302-redirects is NOT
// followed (a redirect to an internal IP would defeat the scheme/host gate).
// We point the leaf at a TLS test server that redirects; the fetch must fail.
func TestFetcher_NoRedirectFollowed(t *testing.T) {
	// A server that always redirects (to an internal-looking target).
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/secret", http.StatusFound)
	}))
	defer redirector.Close()

	// Use the redirector's own client (trusts its self-signed cert) as the
	// fetcher transport, but keep the no-redirect policy by going through a
	// custom fetcher that mirrors the production CheckRedirect.
	fetcher := &redirectTestFetcher{client: noRedirectClient(redirector.Client())}
	cfg := &federation.Config{TrustAnchors: []federation.TrustAnchor{{EntityID: "https://anchor.test", Keys: nil}}}
	r := federation.NewTrustChainResolver(cfg, federation.WithTrustChainFetcher(fetcher))

	// The leaf id resolves to the redirector; the fetch must error on the
	// redirect (ErrUseLastResponse path returns the 302, which is a non-2xx →
	// fetch failure).
	_, err := r.ResolveTrustChain(context.Background(), redirector.URL)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("redirect: err = %v, want ErrTrustChainInvalid (redirect not followed)", err)
	}
}

// redirectTestFetcher is a minimal EntityStatementFetcher over a real
// *http.Client that mirrors the production no-redirect + https policy, used to
// prove a redirect is not followed. It is NOT the production fetcher (which is
// unexported); it reproduces its redirect/scheme contract for the test.
type redirectTestFetcher struct{ client *http.Client }

func (f *redirectTestFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	if !strings.HasPrefix(entityID, "https://") {
		return nil, errors.New("https only")
	}
	return f.get(ctx, entityID+"/.well-known/openid-federation")
}

func (f *redirectTestFetcher) FetchSubordinateStatement(ctx context.Context, endpoint, iss, sub string) ([]byte, error) {
	return f.get(ctx, endpoint)
}

func (f *redirectTestFetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("non-2xx (redirect not followed)")
	}
	buf := make([]byte, 0)
	tmp := make([]byte, 512)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
	}
	return buf, nil
}

func noRedirectClient(base *http.Client) *http.Client {
	c := *base
	c.Timeout = 5 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("federation: redirect not followed")
	}
	return &c
}

// TestDialWithSSRFCheck_BlocksInternalIPs verifies that dialWithSSRFCheck rejects
// dials to loopback and link-local addresses directly, without needing DNS. These
// are the literal-IP paths that bypass DNS but should still be caught at dial time
// (defense-in-depth over the validateFederationURL literal-IP check).
func TestDialWithSSRFCheck_BlocksInternalIPs(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"loopback v4", "127.0.0.1:80"},
		{"loopback v4 alt", "127.0.0.2:443"},
		{"link-local IMDS", "169.254.169.254:80"},
		{"RFC1918 /8", "10.0.0.1:80"},
		{"RFC1918 /16", "172.16.0.1:80"},
		{"RFC1918 /24", "192.168.1.1:80"},
		{"loopback v6", "[::1]:80"},
		{"unspecified v4", "0.0.0.0:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := federation.DialWithSSRFCheck(context.Background(), "tcp", tc.addr)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("DialWithSSRFCheck(%q): expected SSRF error, got nil", tc.addr)
			}
		})
	}
}

// TestDialWithSSRFCheck_BlocksRebinding is the core DNS-rebinding regression: a
// HOSTNAME (not a literal IP) that DNS-resolves to an internal address must be
// blocked at dial time, AFTER the literal-IP fast path is bypassed and the real
// LookupHost branch runs. "localhost" is the deterministic stand-in for the
// attack ("evil.example.com → 127.0.0.1"): it is a non-literal host that every
// resolver maps to loopback, so it exercises the resolved-IP rejection path
// without depending on attacker-controlled DNS. The dial MUST fail with the
// SSRF-guard marker, NOT a downstream connect error, proving the resolved IP
// was inspected and rejected before any connection was attempted.
func TestDialWithSSRFCheck_BlocksRebinding(t *testing.T) {
	// A real listener on loopback so that, absent the guard, the dial WOULD
	// succeed — the test would be vacuous if nothing were listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}

	addr := net.JoinHostPort("localhost", port)
	conn, err := federation.DialWithSSRFCheck(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("DialWithSSRFCheck(%q): expected SSRF rejection of resolved internal IP, got nil", addr)
	}
	// The error MUST come from the resolved-IP guard, not from a connect
	// failure — otherwise the rebinding host slipped past the resolution check.
	if !strings.Contains(err.Error(), "(SSRF guard)") {
		t.Fatalf("DialWithSSRFCheck(%q): err = %v, want resolved-IP SSRF-guard rejection", addr, err)
	}
}

// TestDialWithSSRFCheck_AllowsPublicAddress proves the guard does NOT break a
// normal, public-looking flow: a non-internal target passes the SSRF check and
// reaches the TCP-connect stage. TEST-NET-1 (192.0.2.0/24, RFC 5737) is a
// documentation range that is NOT internal per the blocklist but is guaranteed
// unroutable, so the dial fails at CONNECT (timeout/refused), never at the SSRF
// gate. A guard-marker error here would mean a legitimate public host was being
// wrongly blocked.
func TestDialWithSSRFCheck_AllowsPublicAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := federation.DialWithSSRFCheck(ctx, "tcp", "192.0.2.1:80")
	if err == nil {
		// A successful dial to a public address is not an SSRF failure — the
		// guard let it through, which is the correct behavior.
		_ = conn.Close()
		return
	}
	if strings.Contains(err.Error(), "(SSRF guard)") {
		t.Fatalf("DialWithSSRFCheck(public addr): wrongly blocked by SSRF guard: %v", err)
	}
}
