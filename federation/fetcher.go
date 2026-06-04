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

	"github.com/snaplink/sso/core"
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
//   - BEST-EFFORT internal-host block: a literal private / loopback /
//     link-local IP host is rejected up front. This is a DEFENSE-IN-DEPTH
//     heuristic, NOT a complete SSRF control — a hostname that DNS-resolves
//     to an internal IP still passes (the resolution happens inside the
//     transport). FULL SSRF containment REQUIRES the operator's egress
//     network policy (a deny-by-default egress firewall / proxy), exactly as
//     documented for the JAR fetcher. This gate raises the bar; it is not the
//     wall.
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
		},
		maxBytes: DefaultFederationFetchMaxBytes,
	}
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
	defer resp.Body.Close()
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

// validateFederationURL is the SSRF gate applied to EVERY fetched URL (an
// entity ID or a federation_fetch_endpoint). It enforces https + a host, and
// best-effort rejects a literal internal-IP host. See the file header for the
// (deliberate) limits of the host check and the operator-egress requirement.
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
	// Best-effort literal-internal-IP block (defense in depth, NOT a complete
	// control — a hostname resolving to an internal IP still passes; the
	// operator's egress policy is the real boundary).
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
