package sso

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/tenant"
)

// TenantHandlerContextKey is the value-bag key the tenant
// middleware uses to stash *Resolved on HandlerContext. Handlers
// should prefer TenantFromHandlerContext to a raw ctx.Get — the
// helper does the type assertion + nil guard in one place.
const TenantHandlerContextKey = "tenant:resolved"

// DefaultTenantLookupTimeout caps how long a single tenant
// resolution may block in the request hot path. The lookup is
// purely a Domain → Tenant DB read; even SQL backends should be
// well under this.
const DefaultTenantLookupTimeout = 100 * time.Millisecond

// HostExtractor pulls the request hostname for tenant resolution.
// Implementations may trust the Host header (default), the X-Forwarded-Host
// from a known proxy, or another signal entirely. Returning ""
// tells the middleware to skip the lookup.
type HostExtractor func(r *http.Request) string

// ResolvedTenant bundles the Tenant + Domain the middleware found
// for this request. Stashed on HandlerContext for handlers to
// read; handlers SHOULD treat absence as "no tenant context for
// this request" and decide based on their own contract (some
// public endpoints don't need one).
type ResolvedTenant struct {
	Tenant *tenant.Tenant
	Domain *tenant.Domain
}

// TenantMiddlewareOptions tune the middleware. Zero value is fine
// — the defaults extract Host from the request, time the lookup
// at DefaultTenantLookupTimeout, and silently no-op on unknown
// hostnames (handlers + a separate gate decide whether to hard-
// reject).
type TenantMiddlewareOptions struct {
	// HostExtractor pulls the hostname. Defaults to DefaultHostExtractor.
	HostExtractor HostExtractor
	// Timeout caps a single lookup. Defaults to
	// DefaultTenantLookupTimeout.
	Timeout time.Duration
	// OnError is called when GetDomain fails with anything other
	// than tenant.ErrDomainNotFound. Optional — backend outages
	// stay non-fatal so the request continues, but operators
	// should alert on them.
	OnError func(err error)
	// IncludeSuspended, when true, populates the context even for
	// tenants whose Status is Suspended. Default is false: a
	// suspended tenant resolves but the middleware leaves the
	// context empty so handlers naturally fall through to the
	// "no tenant" code path. Set true if you want handlers to
	// surface a maintenance page instead.
	IncludeSuspended bool
}

// TenantMiddleware constructs a MiddlewareFunc that resolves the
// request hostname through store and stashes the *ResolvedTenant
// on HandlerContext under TenantHandlerContextKey. Lookup failure
// (including ErrDomainNotFound) is intentionally non-fatal — the
// request continues with no tenant set; handlers + audit
// enrichment naturally degrade.
//
// A nil store returns a no-op middleware so callers wire this
// unconditionally.
func TenantMiddleware(store tenant.Store, opts TenantMiddlewareOptions) MiddlewareFunc {
	if store == nil {
		return func(HandlerContext) {}
	}
	extract := opts.HostExtractor
	if extract == nil {
		extract = DefaultHostExtractor
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTenantLookupTimeout
	}
	return func(hctx HandlerContext) {
		host := extract(hctx.Request())
		if host == "" {
			return
		}
		ctx, cancel := context.WithTimeout(hctx.Request().Context(), timeout)
		defer cancel()
		dom, err := store.GetDomain(ctx, host)
		if err != nil {
			if opts.OnError != nil && err != tenant.ErrDomainNotFound {
				opts.OnError(err)
			}
			return
		}
		t, err := store.GetTenant(ctx, dom.TenantID)
		if err != nil {
			// Dangling domain row pointing at a deleted tenant —
			// surface to OnError so operators notice, but don't
			// fail the request.
			if opts.OnError != nil && err != tenant.ErrTenantNotFound {
				opts.OnError(err)
			}
			return
		}
		if t == nil {
			// Misbehaved Store returned (nil, nil); treat as "no
			// tenant" rather than panicking.
			return
		}
		if t.Status != tenant.StatusActive && !opts.IncludeSuspended {
			return
		}
		hctx.Set(TenantHandlerContextKey, &ResolvedTenant{Tenant: t, Domain: dom})
	}
}

// TenantFromHandlerContext returns the *ResolvedTenant the
// middleware stashed for this request, or (nil, false) when the
// lookup didn't run / the host wasn't known / the tenant is
// suspended (with default options).
func TenantFromHandlerContext(hctx HandlerContext) (*ResolvedTenant, bool) {
	if hctx == nil {
		return nil, false
	}
	v := hctx.Get(TenantHandlerContextKey)
	if v == nil {
		return nil, false
	}
	r, ok := v.(*ResolvedTenant)
	return r, ok && r != nil
}

// DefaultHostExtractor reads the request hostname in priority
// order:
//  1. X-Forwarded-Host first hop (when the deployment runs behind
//     an edge proxy that sets it).
//  2. r.Host (the Host header, or req.Host when set explicitly).
//
// Strips any port suffix so "acme.com:8443" resolves to "acme.com".
//
// SECURITY: trusting X-Forwarded-Host is correct ONLY when a
// known edge proxy strips and re-sets it. Internet-facing
// deployments without one should write a custom HostExtractor
// that returns r.Host unconditionally.
func DefaultHostExtractor(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		v = strings.TrimSpace(v)
		if v != "" {
			return stripHostPort(v)
		}
	}
	return stripHostPort(r.Host)
}

func stripHostPort(h string) string {
	if h == "" {
		return ""
	}
	// IPv6 literal in brackets.
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndex(h, ":"); i > 0 {
		return h[:i]
	}
	return h
}
