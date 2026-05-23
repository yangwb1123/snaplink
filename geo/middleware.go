package geo

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/core"
)

// HandlerContextKey is the value-bag key the geo middleware uses to
// stash *GeoInfo on HandlerContext. Handlers should prefer
// FromHandlerContext to a raw ctx.Get — the helper does the type
// assertion + nil guard in one place.
const HandlerContextKey = "geo:info"

// DefaultLookupTimeout caps how long a single geo lookup may
// block in the request hot path. Geo is a UX hint, not a
// request-blocking concern — keep this short.
const DefaultLookupTimeout = 200 * time.Millisecond

// IPExtractor pulls a client IP from a request. Implementations
// may trust forwarded headers (when there's a known edge proxy)
// or stick to RemoteAddr (when the SSO server faces the internet
// directly). Returning nil tells the middleware to skip the
// lookup for this request.
type IPExtractor func(r *http.Request) net.IP

// MiddlewareOptions tune the geo middleware. Zero value is fine —
// the middleware uses sane defaults (DefaultIPExtractor +
// DefaultLookupTimeout, no error reporter).
type MiddlewareOptions struct {
	// IPExtractor extracts the client IP. Defaults to
	// DefaultIPExtractor (honors X-Forwarded-For, X-Real-IP,
	// then RemoteAddr).
	IPExtractor IPExtractor

	// Timeout caps a single Provider.Lookup call. Defaults to
	// DefaultLookupTimeout. The lookup runs in the request hot
	// path; values larger than a couple hundred milliseconds will
	// hurt p99.
	Timeout time.Duration

	// OnError is called when Provider.Lookup fails with anything
	// other than ErrNotFound. Use for alerting on backend outages.
	// Optional — geo failures stay non-fatal so the request
	// proceeds.
	OnError func(err error)
}

// Middleware constructs a core.MiddlewareFunc that resolves the
// request's client IP through Provider and stashes the *GeoInfo on
// the HandlerContext value bag under HandlerContextKey. Lookup
// failures (including ErrNotFound) are intentionally silent —
// downstream handlers + audit enrichment treat absence as "no geo
// for this request" and continue normally.
//
// A nil Provider returns a no-op middleware so callers wire this
// unconditionally.
func Middleware(p Provider, opts MiddlewareOptions) core.MiddlewareFunc {
	if p == nil {
		return func(core.HandlerContext) {}
	}
	extract := opts.IPExtractor
	if extract == nil {
		extract = DefaultIPExtractor
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultLookupTimeout
	}
	return func(hctx core.HandlerContext) {
		ip := extract(hctx.Request())
		if ip == nil {
			return
		}
		ctx, cancel := context.WithTimeout(hctx.Request().Context(), timeout)
		defer cancel()
		info, err := p.Lookup(ctx, ip)
		if err != nil {
			if opts.OnError != nil && !errors.Is(err, ErrNotFound) {
				opts.OnError(err)
			}
			return
		}
		if info == nil {
			return
		}
		hctx.Set(HandlerContextKey, info)
	}
}

// FromHandlerContext returns the *GeoInfo the middleware stashed
// for this request, or (nil, false) when no middleware ran / the
// lookup failed / the IP was unknown.
func FromHandlerContext(hctx core.HandlerContext) (*GeoInfo, bool) {
	if hctx == nil {
		return nil, false
	}
	v := hctx.Get(HandlerContextKey)
	if v == nil {
		return nil, false
	}
	g, ok := v.(*GeoInfo)
	return g, ok
}

// DefaultIPExtractor pulls the apparent client IP using the same
// precedence the audit middleware uses: X-Forwarded-For (first
// hop) → X-Real-IP → RemoteAddr. Only trust forwarded headers
// when the SSO server sits behind a known edge proxy.
func DefaultIPExtractor(r *http.Request) net.IP {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip
		}
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip
		}
	}
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip
			}
		}
		// RemoteAddr without a port (rare: certain test harnesses).
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return ip
		}
	}
	return nil
}
