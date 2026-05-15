package sso

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/geo"
)

// GeoHandlerContextKey is the value-bag key the geo middleware uses
// to stash *geo.GeoInfo on HandlerContext. Handlers should prefer
// GeoFromHandlerContext to a raw ctx.Get — the helper does the
// type assertion + nil guard in one place.
const GeoHandlerContextKey = "geo:info"

// DefaultGeoLookupTimeout caps how long a single geo lookup may
// block in the request hot path. Geo is a UX hint, not a
// request-blocking concern — keep this short.
const DefaultGeoLookupTimeout = 200 * time.Millisecond

// GeoIPExtractor pulls a client IP from a request. Implementations
// may trust forwarded headers (when there's a known edge proxy)
// or stick to RemoteAddr (when the SSO server faces the internet
// directly). Returning nil tells the middleware to skip the
// lookup for this request.
type GeoIPExtractor func(r *http.Request) net.IP

// GeoMiddlewareOptions tune the geo middleware. Zero value is fine
// — the middleware uses sane defaults (DefaultGeoIPExtractor +
// DefaultGeoLookupTimeout, no error reporter).
type GeoMiddlewareOptions struct {
	// Extractor pulls the client IP. Defaults to DefaultGeoIPExtractor
	// (XFF first hop → X-Real-IP → RemoteAddr host).
	Extractor GeoIPExtractor
	// Timeout caps a single Lookup. Defaults to DefaultGeoLookupTimeout.
	Timeout time.Duration
	// OnError is called when Lookup fails with anything other than
	// geo.ErrNotFound / geo.ErrInvalidIP. Optional — geo failures are
	// intentionally non-fatal so the request continues either way,
	// but operators may want to log + alert on backend outages.
	OnError func(err error)
}

// GeoMiddleware constructs a MiddlewareFunc that looks up the
// request's client IP via p and stashes the resulting *GeoInfo on
// the HandlerContext value bag (key GeoHandlerContextKey). Lookup
// failure (including ErrNotFound) is intentionally non-fatal: the
// request continues with no GeoInfo set.
//
// A nil Provider returns a no-op middleware so callers can wire
// this unconditionally and let configuration decide whether to
// enable geo at all.
func GeoMiddleware(p geo.Provider, opts GeoMiddlewareOptions) MiddlewareFunc {
	if p == nil {
		return func(HandlerContext) {}
	}
	extract := opts.Extractor
	if extract == nil {
		extract = DefaultGeoIPExtractor
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultGeoLookupTimeout
	}
	return func(hctx HandlerContext) {
		ip := extract(hctx.Request())
		if ip == nil {
			return
		}
		ctx, cancel := context.WithTimeout(hctx.Request().Context(), timeout)
		defer cancel()
		info, err := p.Lookup(ctx, ip)
		if err != nil {
			if opts.OnError != nil && err != geo.ErrNotFound && err != geo.ErrInvalidIP {
				opts.OnError(err)
			}
			return
		}
		hctx.Set(GeoHandlerContextKey, info)
	}
}

// GeoFromHandlerContext returns the *GeoInfo the geo middleware
// stashed for this request, or (nil, false) when the lookup didn't
// run / failed / wasn't wired. Callers should treat the false case
// as "no hint, fall through to defaults".
func GeoFromHandlerContext(hctx HandlerContext) (*geo.GeoInfo, bool) {
	if hctx == nil {
		return nil, false
	}
	v := hctx.Get(GeoHandlerContextKey)
	if v == nil {
		return nil, false
	}
	info, ok := v.(*geo.GeoInfo)
	return info, ok && info != nil
}

// DefaultGeoIPExtractor pulls the client IP in priority order:
//  1. X-Forwarded-For first hop (the originating client per RFC
//     7239 conventions; later hops are intermediate proxies).
//  2. X-Real-IP (single value; some edge proxies use this instead).
//  3. RemoteAddr host part (the direct TCP peer; correct only when
//     the server faces the internet directly).
//
// Returns nil when no usable address is found. SECURITY: trusting
// XFF/X-Real-IP is correct ONLY when a known edge proxy strips
// and re-sets the header. Internet-facing deployments without an
// edge proxy should write a custom GeoIPExtractor that ignores
// forwarded headers and uses RemoteAddr only.
func DefaultGeoIPExtractor(r *http.Request) net.IP {
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
