package security

import (
	"context"
	"errors"
	"fmt"
	"io"
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
// redirects, 5s timeout, 16KB body cap. Override by setting the
// fields on the returned struct.
func NewHTTPJARFetcher() *HTTPJARFetcher {
	return &HTTPJARFetcher{
		Client: &http.Client{
			Timeout: DefaultJARFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxBytes: DefaultJARFetchMaxBytes,
	}
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
