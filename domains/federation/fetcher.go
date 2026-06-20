package federation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// OpenID Federation 1.0 §9 — Trust Chain resolution FETCHES documents from
// URLs DERIVED FROM the leaf's authority_hints (and recursively each
// superior's). Those URLs are ATTACKER-INFLUENCEABLE (a malicious leaf names
// its own superiors), so this fetcher is the SSRF perimeter of the resolver.
// It mirrors the JAR request_uri fetcher (security/jar_fetch.go) and the SAML
// SLO fan-out gate (saml/idp/fanout.go isHTTPSURL + the af42850 hardening) and
// the CAEP receiver-endpoint https policy:
//
//   - HTTPS-ONLY: a plain http:// (or file://, etc.) entity ID / fetch
//     endpoint is REJECTED. An http:// target would let a forged federation
//     pivot the server into a server-side request to an internal/IMDS host.
//   - NO REDIRECTS: a 30x from an https host to an internal IP would defeat
//     the scheme gate, so CheckRedirect returns an error (the response is
//     never followed).
//   - INTERNAL-HOST BLOCK (two layers):
//     1. validateFederationURL fast-rejects a URL whose host is a LITERAL
//        private / loopback / link-local IP (e.g. https://10.0.0.1/...).
//     2. dialWithSSRFCheck resolves the hostname at dial time and rejects if
//        ANY resolved IP is internal. This closes the DNS-rebinding gap: a
//        public-looking hostname (evil.example.com) that resolves to
//        169.254.169.254 or another IMDS/internal address at the moment of
//        the dial is blocked here, not at URL-parse time. Because the check
//        and the connection happen in the same call there is no TOCTOU window.
//        FULL SSRF containment STILL REQUIRES the operator's egress network
//        policy (a deny-by-default egress firewall / proxy) as the final
//        layer; these two in-process gates raise the bar substantially.
//   - BOUNDED: a per-fetch timeout + a body-size cap (LimitReader) so a slow
//     or gigantic federation document cannot hang or OOM the resolver.
//
// The seam is an interface so a test can inject a FAKE federation (a set of
// in-memory signed statements) with NO real network — the resolver +
// validator are then exercised offline and deterministically.

// EntityStatementFetcher retrieves the signed federation documents the trust
// chain is assembled from: an entity's self-signed Entity Configuration (from
// its well-known endpoint) and a Subordinate Statement issued BY a superior
// ABOUT a subordinate (from the superior's federation_fetch_endpoint). Both
// return the raw compact JWS bytes; the resolver parses + verifies them. A
// non-nil error is returned for any transport / scheme / size failure (the
// resolver collapses every failure into one coarse rejection).
type EntityStatementFetcher interface {
	// FetchEntityConfiguration GETs entityID + the well-known federation path
	// and returns the raw signed Entity Configuration (a self-signed Entity
	// Statement, iss == sub == entityID).
	FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error)
	// FetchSubordinateStatement GETs the superior's federation_fetch_endpoint
	// with iss=issuer (the superior) and sub=subject (the subordinate) query
	// params (OpenID Federation 1.0 §8.1) and returns the raw signed
	// Subordinate Statement.
	FetchSubordinateStatement(ctx context.Context, fetchEndpoint, issuer, subject string) ([]byte, error)
}

// Default fetch bounds. A federation Entity Statement is a signed JWT with
// inline JWKS + metadata + (optionally) a metadata policy — a few KB in
// practice. 256KiB is generous slack while keeping a hostile document's
// memory footprint bounded; the timeout keeps a resolution from hanging on a
// slow/dead superior (the user is waiting on the registration/login this
// chain gates).
const (
	// DefaultFederationFetchTimeout caps a single HTTP fetch.
	DefaultFederationFetchTimeout = 10 * time.Second
	// DefaultFederationFetchMaxBytes caps a single fetched document.
	DefaultFederationFetchMaxBytes int64 = 256 * 1024
)

// httpFetcher is the production EntityStatementFetcher: an *http.Client with
// redirects disabled, a bounded timeout, and a body cap, plus the https-only +
// best-effort internal-host SSRF gate applied to every target URL.
type httpFetcher struct {
	client   *http.Client
	maxBytes int64
}

// newHTTPFetcher returns the hardened default fetcher.
func newHTTPFetcher() *httpFetcher {
	return &httpFetcher{
		client: &http.Client{
			Timeout: DefaultFederationFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// A redirect from an https host to an internal IP would defeat
				// the scheme + host gate, so refuse to follow any redirect (the
				// federation well-known + fetch endpoints are exact URLs).
				return errors.New("federation: redirect not followed")
			},
			// dialWithSSRFCheck on the transport's DialContext is the
			// defense-in-depth layer against DNS rebinding: it resolves the
			// hostname at dial time and rejects any IP that isInternalIP
			// returns true for — including cases where a public-looking
			// hostname resolves to 169.254.169.254 or another IMDS/internal
			// address AFTER validateFederationURL's literal-IP check passes.
			Transport: &http.Transport{
				DialContext: dialWithSSRFCheck,
			},
		},
		maxBytes: DefaultFederationFetchMaxBytes,
	}
}

// dialWithSSRFCheck is a DialContext function that resolves the target hostname
// before opening a TCP connection and rejects the dial if ANY resolved IP is
// internal (loopback / link-local / private / unspecified). This closes the
// DNS-rebinding gap in validateFederationURL: that function rejects literal
// private-IP hosts but cannot block a public hostname whose DNS record points
// to an internal address at the moment the dial happens.
//
// The check runs at dial time (not URL-parse time) so there is no TOCTOU
// window: the IP we check is the same IP we connect to.
func dialWithSSRFCheck(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid dial address %q: %w", addr, err)
	}
	// If addr is already a numeric IP (e.g. from a literal-IP URL that slipped
	// through) check it directly and skip the DNS round-trip.
	if ip := net.ParseIP(host); ip != nil {
		if isInternalIP(ip) {
			return nil, fmt.Errorf("federation: dial address %q is internal (SSRF guard)", host)
		}
		d := &net.Dialer{Timeout: DefaultFederationFetchTimeout}
		return d.DialContext(ctx, network, addr)
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("federation: DNS resolution failed for %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("federation: DNS returned no addresses for %q", host)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			// Resolver returned something unparseable; treat conservatively.
			return nil, fmt.Errorf("federation: DNS returned unparseable address %q for host %q", a, host)
		}
		if isInternalIP(ip) {
			return nil, fmt.Errorf("federation: resolved address %q for host %q is internal (SSRF guard)", a, host)
		}
	}
	// Connect to the first resolved address. Every address was validated above.
	d := &net.Dialer{Timeout: DefaultFederationFetchTimeout}
	return d.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
}

// FetchEntityConfiguration implements EntityStatementFetcher.
func (f *httpFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	if err := validateFederationURL(entityID); err != nil {
		return nil, err
	}
	return f.get(ctx, entityConfigurationURL(entityID), "application/entity-statement+jwt")
}

// FetchSubordinateStatement implements EntityStatementFetcher.
func (f *httpFetcher) FetchSubordinateStatement(ctx context.Context, fetchEndpoint, issuer, subject string) ([]byte, error) {
	if err := validateFederationURL(fetchEndpoint); err != nil {
		return nil, err
	}
	u, err := url.Parse(fetchEndpoint)
	if err != nil {
		return nil, fmt.Errorf("federation: parse fetch endpoint: %w", err)
	}
	// §8.1: the Subordinate Statement is requested with iss (the issuing
	// superior) + sub (the subject entity). sub is omitted only when the
	// superior is asked for "all" — the resolver always pins both.
	q := u.Query()
	q.Set("iss", issuer)
	q.Set("sub", subject)
	u.RawQuery = q.Encode()
	return f.get(ctx, u.String(), "application/entity-statement+jwt")
}

// get performs the bounded, redirect-free GET and returns the body.
func (f *httpFetcher) get(ctx context.Context, rawURL, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: build request: %w", err)
	}
	req.Header.Set("Accept", accept)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("federation: fetch status %d", resp.StatusCode)
	}
	max := f.maxBytes
	if max <= 0 {
		max = DefaultFederationFetchMaxBytes
	}
	// Read max+1 so an over-cap body is detected + rejected rather than
	// silently truncated into an unverifiable statement.
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("federation: read body: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("federation: body exceeds %d bytes", max)
	}
	return body, nil
}

// entityConfigurationURL appends the well-known federation path to an entity
// identifier (OpenID Federation 1.0 §9). The entity ID may carry a path
// component, so the well-known segment is inserted, not naively concatenated:
// per the spec it is "<entity-id-with-any-path>/.well-known/openid-federation".
func entityConfigurationURL(entityID string) string {
	trimmed := strings.TrimRight(entityID, "/")
	return trimmed + core.PathFederationEntityConfig
}

// validateFederationURL is the first-pass SSRF gate applied to EVERY fetched
// URL (entity ID or federation_fetch_endpoint). It enforces https + a non-empty
// host, and fast-rejects a LITERAL internal-IP host. It does NOT block
// hostnames that resolve to internal IPs at dial time — that is the job of
// dialWithSSRFCheck (DNS-rebinding defense). See the file header for the full
// two-layer model and the operator-egress requirement.
func validateFederationURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("federation: malformed URL: %w", err)
	}
	// https ONLY — an http:// / file:// / scheme-relative target would turn a
	// forged authority_hint into a server-side request to an internal endpoint.
	if u.Scheme != "https" {
		return fmt.Errorf("federation: URL must be https (got scheme %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("federation: URL has no host")
	}
	// Fast-reject a literal internal IP. A hostname that resolves to an internal
	// IP at dial time is caught by dialWithSSRFCheck instead.
	if ip := net.ParseIP(host); ip != nil && isInternalIP(ip) {
		return fmt.Errorf("federation: URL host %q is an internal address", host)
	}
	return nil
}

// isInternalIP reports whether ip is one an SSRF probe would target: loopback,
// link-local (incl. the cloud metadata 169.254.169.254 range), private
// (RFC 1918 / ULA), or unspecified. The CIDR set mirrors the conventional
// SSRF blocklist; net.IP.IsPrivate covers RFC 1918 + RFC 4193.
func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:a.b.c.d) — re-check the embedded v4 so a mapped
	// private address is not waved through.
	if v4 := ip.To4(); v4 != nil && !v4.Equal(ip) {
		return isInternalIP(v4)
	}
	return false
}
