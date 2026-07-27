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

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/securityverify"
)

// OpenID Federation 1.0 §9 — Trust Chain resolution FETCHES documents from
// URLs DERIVED FROM the leaf's authority_hints (and recursively each
// superior's). Those URLs are ATTACKER-INFLUENCEABLE (a malicious leaf names
// its own superiors), so this fetcher is the SSRF perimeter of the resolver.
// It shares the dial-time SSRF guard with the JAR request_uri fetcher
// (securityverify.SSRFGuardedDialer) and mirrors the SAML
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
			// The guarded dialer on the transport's DialContext is the
			// defense-in-depth layer against DNS rebinding: it resolves the
			// hostname at dial time and rejects any IP that IsInternalIP
			// returns true for — including cases where a public-looking
			// hostname resolves to 169.254.169.254 or another IMDS/internal
			// address AFTER validateFederationURL's literal-IP check passes.
			// Transport() carries DefaultTransport's HTTP/2 + idle-conn hygiene
			// while deliberately omitting Proxy (a proxy would bypass the
			// resolved-IP guard); dialWithSSRFCheck stays the test seam over the
			// same federationSSRFDialer.DialContext.
			Transport: federationSSRFDialer.Transport(),
		},
		maxBytes: DefaultFederationFetchMaxBytes,
	}
}

// federationSSRFDialer is the shared dial-time SSRF gate
// (securityverify.SSRFGuardedDialer — one copy for this fetcher and the JAR
// request_uri fetcher), namespaced with this package's error prefix so the
// error surface is byte-identical to the pre-extraction implementation.
var federationSSRFDialer = &securityverify.SSRFGuardedDialer{
	ErrPrefix: "federation",
	Timeout:   DefaultFederationFetchTimeout,
}

// dialWithSSRFCheck is a DialContext function that resolves the target hostname
// before opening a TCP connection and rejects the dial if ANY resolved IP is
// internal (loopback / link-local / private / unspecified). This closes the
// DNS-rebinding gap in validateFederationURL: that function rejects literal
// private-IP hosts but cannot block a public hostname whose DNS record points
// to an internal address at the moment the dial happens.
//
// The check runs at dial time (not URL-parse time) so there is no TOCTOU
// window: the IP we check is the same IP we connect to. The mechanics live in
// securityverify.SSRFGuardedDialer.
func dialWithSSRFCheck(ctx context.Context, network, addr string) (net.Conn, error) {
	return federationSSRFDialer.DialContext(ctx, network, addr)
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

// NewDefaultFetcher returns the hardened production EntityStatementFetcher
// (https-only, SSRF-guarded dial, no redirects, bounded timeout + body size —
// see the file header for the full model). NewTrustChainResolver already uses
// this fetcher by default when no WithTrustChainFetcher option overrides it;
// it is exported so an OPTIONAL decorator (e.g. a connection-health observer
// that records fetch outcomes for observability) can WRAP the SAME hardened
// fetcher instead of reimplementing its SSRF/timeout/size hardening.
func NewDefaultFetcher() EntityStatementFetcher {
	return newHTTPFetcher()
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
	// IP at dial time is caught by dialWithSSRFCheck instead. The IP
	// classification is shared with the dial-time guard (single policy copy).
	if ip := net.ParseIP(host); ip != nil && securityverify.IsInternalIP(ip) {
		return fmt.Errorf("federation: URL host %q is an internal address", host)
	}
	return nil
}
