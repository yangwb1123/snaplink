package tenant

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// HandlerContextKey is the value-bag key the Middleware stashes
// a *Resolved under. Handlers should prefer FromHandlerContext to a
// raw ctx.Get — the typed helper guards against absent / mistyped
// values.
const HandlerContextKey = "tenant:resolved"

// DefaultLookupTimeout caps how long a single tenant resolution
// may block in the request hot path. The lookup is purely a
// Domain → Tenant DB read; even SQL backends should be well under
// this.
const DefaultLookupTimeout = 100 * time.Millisecond

// HostExtractor pulls the request hostname for tenant resolution.
// Implementations may trust the Host header (default), the X-Forwarded-Host
// from a known proxy, or another signal entirely. Returning ""
// tells the middleware to skip the lookup.
type HostExtractor func(r *http.Request) string

// Resolved bundles the Tenant + Domain the middleware found for
// this request. Stashed on HandlerContext for handlers to read;
// handlers SHOULD treat absence as "no tenant context for this
// request" and decide based on their own contract (some public
// endpoints don't need one).
type Resolved struct {
	Tenant *Tenant
	Domain *Domain
}

// MiddlewareOptions tune the middleware. Zero value is fine — the
// defaults extract Host from the request, time the lookup at
// DefaultLookupTimeout, and silently no-op on unknown hostnames
// (handlers + a separate gate decide whether to hard-reject).
type MiddlewareOptions struct {
	// HostExtractor pulls the hostname. Defaults to DefaultHostExtractor.
	HostExtractor HostExtractor
	// Timeout caps a single lookup. Defaults to DefaultLookupTimeout.
	Timeout time.Duration
	// OnError is called when GetDomain fails with anything other
	// than ErrDomainNotFound. Optional — backend outages stay
	// non-fatal so the request continues, but operators should
	// alert on them.
	OnError func(err error)
	// IncludeSuspended, when true, populates the context even for
	// tenants whose Status is Suspended. Default is false: a
	// suspended tenant resolves but the middleware leaves the
	// context empty so handlers naturally fall through to the
	// "no tenant" code path. Set true if you want handlers to
	// surface a maintenance page instead.
	IncludeSuspended bool
}

// Middleware constructs a MiddlewareFunc that resolves the request
// hostname through store and stashes the *Resolved on
// HandlerContext under HandlerContextKey. Lookup failure
// (including ErrDomainNotFound) is intentionally non-fatal — the
// request continues with no tenant set; handlers + audit
// enrichment naturally degrade.
//
// A nil store returns a no-op middleware so callers wire this
// unconditionally.
func Middleware(store Store, opts MiddlewareOptions) core.MiddlewareFunc {
	if store == nil {
		return func(core.HandlerContext) {}
	}
	extract := opts.HostExtractor
	if extract == nil {
		extract = DefaultHostExtractor
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultLookupTimeout
	}
	return func(hctx core.HandlerContext) {
		host := extract(hctx.Request())
		if host == "" {
			return
		}
		ctx, cancel := context.WithTimeout(hctx.Request().Context(), timeout)
		defer cancel()
		dom, err := store.GetDomain(ctx, host)
		if err != nil {
			if opts.OnError != nil && err != ErrDomainNotFound {
				opts.OnError(err)
			}
			return
		}
		t, err := store.GetTenant(ctx, dom.TenantID)
		if err != nil {
			// Dangling domain row pointing at a deleted tenant —
			// surface to OnError so operators notice, but don't
			// fail the request.
			if opts.OnError != nil && err != ErrTenantNotFound {
				opts.OnError(err)
			}
			return
		}
		if t == nil {
			// Misbehaved Store returned (nil, nil); treat as "no
			// tenant" rather than panicking.
			return
		}
		if t.Status != StatusActive && !opts.IncludeSuspended {
			return
		}
		hctx.Set(HandlerContextKey, &Resolved{Tenant: t, Domain: dom})
	}
}

// FromHandlerContext returns the *Resolved the middleware stashed
// for this request, or (nil, false) when the lookup didn't run /
// the host wasn't known / the tenant is suspended (with default
// options).
func FromHandlerContext(hctx core.HandlerContext) (*Resolved, bool) {
	if hctx == nil {
		return nil, false
	}
	v := hctx.Get(HandlerContextKey)
	if v == nil {
		return nil, false
	}
	r, ok := v.(*Resolved)
	return r, ok
}

// ResolveTenantID performs the same Host -> Domain -> Tenant lookup as
// Middleware, returning just the resolved tenant ID (or "" on any failure or
// absence). Exposed for callers OUTSIDE the router's per-request middleware
// chain — e.g. the rate-limit rejection metric, which runs BEFORE Middleware
// in the HTTP stack and so cannot read FromHandlerContext. Honors the same
// Timeout/HostExtractor/IncludeSuspended knobs as Middleware so the result is
// identical whichever path resolved it.
//
// Callers on a hot path should NOT invoke this per-request — it costs a
// store round-trip. It's intended for already-slow-path callers (a rejected
// request) where the extra lookup is negligible relative to the reject
// itself.
func ResolveTenantID(ctx context.Context, store Store, opts MiddlewareOptions, r *http.Request) string {
	if store == nil || r == nil {
		return ""
	}
	extract := opts.HostExtractor
	if extract == nil {
		extract = DefaultHostExtractor
	}
	host := extract(r)
	if host == "" {
		return ""
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultLookupTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dom, err := store.GetDomain(lookupCtx, host)
	if err != nil {
		return ""
	}
	t, err := store.GetTenant(lookupCtx, dom.TenantID)
	if err != nil || t == nil {
		return ""
	}
	if t.Status != StatusActive && !opts.IncludeSuspended {
		return ""
	}
	return t.ID
}

// DefaultHostExtractor pulls the hostname from the standard places:
// the Host header (mandatory in HTTP/1.1), or the first hop of an
// X-Forwarded-Host when present (only trust when the AS sits behind
// a known proxy). Strips port + lowercases for canonical matching.
func DefaultHostExtractor(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		// First entry in the comma-sep list = original client-supplied
		// Host; trailing entries are the proxy chain.
		if comma := strings.IndexByte(xfh, ','); comma > 0 {
			return stripHostPort(strings.TrimSpace(xfh[:comma]))
		}
		return stripHostPort(strings.TrimSpace(xfh))
	}
	return stripHostPort(r.Host)
}

// stripHostPort removes the trailing :port (if any) and unwraps
// bracketed IPv6 literals. Per RFC 1035 §2.3.3 hostnames are
// case-insensitive; canonicalize at the boundary so downstream
// lookups don't need to.
func stripHostPort(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	// IPv6 literal in brackets: [2001:db8::1]:443 → 2001:db8::1
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}
