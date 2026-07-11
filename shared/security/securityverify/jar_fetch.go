package securityverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// RFC 9101 §5.2.2 — JAR `request_uri` (URL-fetched variant).
//
// Lets the RP host its signed authorization-request JWT at a URL
// and pass that URL on `/auth/login?request_uri=<URL>`. The AS
// fetches the URL, then verifies the JWT body exactly as if it had
// been supplied inline via the `request` parameter.
//
// Why expose this when PAR already covers "push the request":
//   - Some OIDC libraries default to JAR-by-URL (Apple's Sign-in
//     With Apple, certain SAML→OIDC bridges).
//   - Static OIDC RPs can host the request JWT on a CDN-friendly
//     path and never touch the AS server-to-server.
//
// SSRF defense is the only interesting design question here:
//   - HTTPS scheme MUST be enforced (no `file://`, no plain HTTP).
//   - Per-client allowlist (`Client.AllowedRequestURIs`) is the
//     canonical defense — an attacker who steals client_id but not
//     control over the registered allowlist cannot pivot to internal
//     endpoints.
//   - Redirect following is disabled (a 302 from an allowlisted host
//     to an internal IP would otherwise defeat the allowlist).
//   - Dial-time resolved-IP re-validation ([SSRFGuardedDialer]) —
//     the allowlist pins WHICH URLs may be fetched, but the
//     allowlisted host's DNS stays attacker-influenceable: whoever
//     controls the registered domain's zone can repoint the
//     public-looking hostname at 169.254.169.254 or an RFC 1918
//     address AFTER registration (DNS rebinding). The guard checks
//     the IPs actually resolved at connect time, in the same call
//     that dials, so there is no TOCTOU window.
//   - Body size cap + request timeout — small JWTs are fine; an
//     adversary feeding gigabytes through the AS isn't.
//
// `urn:ietf:params:oauth:request_uri:` prefixed values STILL go
// through the PAR path. Distinction is by scheme.

// JARFetcher retrieves the signed JWT body at the given URI.
// Pluggable so deployments can inject proxy-aware HTTP clients,
// custom TLS configs, or test doubles. Default impl
// (`NewHTTPJARFetcher`) is HTTPS-only, redirect-free, with a 5s
// timeout and a 16KB body cap — values tuned for "small signed JWT"
// not "arbitrary HTTP fetch".
type JARFetcher interface {
	Fetch(ctx context.Context, uri string) ([]byte, error)
}

// DefaultJARFetchTimeout caps a single Fetch call. Short on
// purpose: the user is waiting on the /auth/login response while
// this round-trips. A misbehaving fetch must not delay the
// redirect-time path.
const DefaultJARFetchTimeout = 5 * time.Second

// DefaultJARFetchMaxBytes is the body-size cap. Real signed
// request objects are well under 4KB; doubling that as the cap
// gives slack while keeping memory pressure bounded.
const DefaultJARFetchMaxBytes int64 = 16 * 1024

// HTTPJARFetcher is the production [JARFetcher] backed by an
// *http.Client. Disables redirect following so a fetched
// allowlisted URL can't be flipped to an internal IP via a 302
// response.
type HTTPJARFetcher struct {
	Client   *http.Client
	MaxBytes int64
}

// NewHTTPJARFetcher returns a hardened fetcher: HTTPS-only, no
// redirects, 5s timeout, 16KB body cap, dial-time SSRF guard.
// Override by setting the fields on the returned struct.
func NewHTTPJARFetcher() *HTTPJARFetcher {
	// The per-client AllowedRequestURIs allowlist pins WHICH URLs may be
	// fetched, but the allowlisted host's DNS is still attacker-influenceable:
	// the RP (or whoever controls the registered domain's zone) can point the
	// public-looking hostname at 169.254.169.254 or another internal address
	// AFTER the allowlist entry was vetted. The SSRF-guarded dialer
	// re-validates the RESOLVED IPs at connect time, closing that
	// DNS-rebinding window — same guard the federation trust-chain fetcher
	// uses.
	dialer := &SSRFGuardedDialer{ErrPrefix: "jar_fetch", Timeout: DefaultJARFetchTimeout}
	return &HTTPJARFetcher{
		Client: &http.Client{
			Timeout: DefaultJARFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: dialer.Transport(),
		},
		MaxBytes: DefaultJARFetchMaxBytes,
	}
}

// SSRFGuardedDialer produces a DialContext that re-resolves the target
// hostname and refuses the dial if ANY resolved IP is internal (see
// [IsInternalIP]). It is the shared dial-time SSRF gate for every outbound
// fetcher whose target URL — or the DNS record behind it — is
// attacker-influenceable: the JAR request_uri fetcher in this file and the
// OpenID Federation trust-chain fetcher (domains/federation) both consume it,
// so the IP-classification policy has exactly one copy.
//
// URL-parse-time host checks cannot stop DNS rebinding: a public-looking
// hostname can resolve to an internal address at the moment of the dial.
// Because this check and the connection happen in the same call, the IP that
// is checked is the IP that is dialed — no TOCTOU window. FULL SSRF
// containment STILL REQUIRES the operator's egress network policy as the
// final layer; this in-process gate raises the bar substantially.
type SSRFGuardedDialer struct {
	// ErrPrefix namespaces the returned errors per consumer (e.g.
	// "federation", "jar_fetch") so each fetcher's error surface is
	// indistinguishable from its pre-extraction form.
	ErrPrefix string
	// Timeout bounds the underlying TCP connect.
	Timeout time.Duration
	// LookupHost is the resolver seam; nil uses net.DefaultResolver. Tests
	// inject a fake here to simulate a rebinding record deterministically,
	// and split-horizon deployments can pin a specific resolver.
	LookupHost func(ctx context.Context, host string) ([]string, error)
}

// Transport returns an *http.Transport wired to this guarded dialer, carrying
// http.DefaultTransport's connection-hygiene fields — HTTP/2 negotiation
// (ForceAttemptHTTP2 is REQUIRED because a custom DialContext otherwise
// conservatively disables h2), idle-connection pooling, and handshake timeouts
// — that a bare http.Transport{DialContext: ...} silently drops. It
// DELIBERATELY omits Proxy: routing through an egress proxy would move DNS
// resolution and the TCP connect into the proxy, defeating the resolved-IP
// guard this dialer exists to enforce. A deployment that requires proxied
// egress must inject its own client (WithJARFetcher / the federation fetcher's
// option) and rely on the proxy's own egress policy for SSRF containment.
func (d *SSRFGuardedDialer) Transport() *http.Transport {
	return &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// DialContext resolves addr's host, rejects the dial if any resolved IP is
// internal, and connects only to an address validated in this same call.
func (d *SSRFGuardedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid dial address %q: %w", d.ErrPrefix, addr, err)
	}
	// If addr is already a numeric IP (e.g. from a literal-IP URL that slipped
	// through) check it directly and skip the DNS round-trip.
	if ip := net.ParseIP(host); ip != nil {
		if IsInternalIP(ip) {
			return nil, fmt.Errorf("%s: dial address %q is internal (SSRF guard)", d.ErrPrefix, host)
		}
		dialer := &net.Dialer{Timeout: d.Timeout}
		return dialer.DialContext(ctx, network, addr)
	}
	addrs, err := d.lookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%s: DNS resolution failed for %q: %w", d.ErrPrefix, host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: DNS returned no addresses for %q", d.ErrPrefix, host)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			// Resolver returned something unparseable; treat conservatively.
			return nil, fmt.Errorf("%s: DNS returned unparseable address %q for host %q", d.ErrPrefix, a, host)
		}
		if IsInternalIP(ip) {
			return nil, fmt.Errorf("%s: resolved address %q for host %q is internal (SSRF guard)", d.ErrPrefix, a, host)
		}
	}
	// Connect to the first resolved address. Every address was validated above.
	dialer := &net.Dialer{Timeout: d.Timeout}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
}

// lookupHost applies the resolver seam's default.
func (d *SSRFGuardedDialer) lookupHost(ctx context.Context, host string) ([]string, error) {
	if d.LookupHost != nil {
		return d.LookupHost(ctx, host)
	}
	return net.DefaultResolver.LookupHost(ctx, host)
}

// IsInternalIP reports whether ip is one an SSRF probe would target: loopback,
// link-local (incl. the cloud metadata 169.254.169.254 range), private
// (RFC 1918 / ULA), or unspecified. The CIDR set mirrors the conventional
// SSRF blocklist; net.IP.IsPrivate covers RFC 1918 + RFC 4193.
func IsInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:a.b.c.d) — re-check the embedded v4 so a mapped
	// private address is not waved through.
	if v4 := ip.To4(); v4 != nil && !v4.Equal(ip) {
		return IsInternalIP(v4)
	}
	return false
}

// Fetch implements JARFetcher.
func (f *HTTPJARFetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	if !strings.HasPrefix(uri, "https://") {
		return nil, errors.New("jar_fetch: request_uri MUST be HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("jar_fetch: build request: %w", err)
	}
	// RFC 9101 §5.2.2: AS MAY send Accept hinting the expected MIME.
	// Conventional value mirrors the JAR JWT typ header.
	req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt")
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jar_fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jar_fetch: status %d", resp.StatusCode)
	}
	max := f.MaxBytes
	if max <= 0 {
		max = DefaultJARFetchMaxBytes
	}
	// LimitReader caps total bytes; reading +1 lets us detect
	// overflow and reject cleanly rather than silently truncating
	// a body that the signature would later fail to verify on.
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("jar_fetch: read body: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("jar_fetch: body exceeds %d bytes", max)
	}
	return body, nil
}

// IsJARFetchableURI reports whether a `request_uri` value should be
// routed to the JAR URL-fetch path vs. the PAR `urn:` path. JAR
// URIs MUST be HTTPS; PAR URIs use the dedicated urn: prefix. Any
// other scheme (http://, file://, ftp://, etc.) is rejected.
func IsJARFetchableURI(uri string) bool {
	return strings.HasPrefix(uri, "https://")
}

// IsRequestURIAllowed checks the URI against the client's exact-
// match allowlist. Empty allowlist = denied (no SSRF surface
// exposed). Wildcards are intentionally NOT supported — the whole
// point of the allowlist is making "where can I fetch from" the
// AS-side configuration, not RP-controlled.
func IsRequestURIAllowed(uri string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	return slices.Contains(allowed, uri)
}
