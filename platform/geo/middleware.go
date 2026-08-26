package geo

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
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

// IPExtractor pulls a client IP from a request. The default extractor uses
// the canonical peer-trust result when one is present and otherwise sticks to
// RemoteAddr. Custom extractors may trust forwarded headers when their caller
// has established that boundary; returning nil skips this request's lookup.
type IPExtractor func(r *http.Request) net.IP

// MiddlewareOptions tune the geo middleware. Zero value is fine —
// the middleware uses sane defaults (DefaultIPExtractor +
// DefaultLookupTimeout, no error reporter).
type MiddlewareOptions struct {
	// IPExtractor extracts the client IP. Defaults to DefaultIPExtractor,
	// which parses canonical peertrust.RequestInfo when present and otherwise
	// uses RemoteAddr. It never reads raw X-Forwarded-For or X-Real-IP.
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

// CountryCodeFromContext returns the coarse ISO-3166-1 alpha-2 country
// code GeoMiddleware stashed for this request, or "" when no provider is
// wired, the lookup failed, or the IP was unknown. It is the single
// canonical geo→Event read: both interfaces/sso and protocols/oauth route
// their token-usage Offer seams through it so a missing geo source degrades
// to the zero value everywhere — the per-token observation table must never
// see a token's sightings split by which seam reported them.
func CountryCodeFromContext(hctx core.HandlerContext) string {
	info, ok := FromHandlerContext(hctx)
	if !ok {
		return ""
	}
	return info.CountryCode
}

// DefaultIPExtractor pulls the apparent client IP from the canonical
// peertrust.RequestInfo stamped by TrustedProxies. A present but empty or
// malformed ClientIP, and a request without RequestInfo, fall back only to
// RemoteAddr. Raw X-Forwarded-For and X-Real-IP are deliberately ignored;
// callers that need another source must provide an explicit IPExtractor.
func DefaultIPExtractor(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if info, ok := peertrust.RequestInfoFrom(r); ok {
		if ip := net.ParseIP(strings.TrimSpace(info.ClientIP)); ip != nil {
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
