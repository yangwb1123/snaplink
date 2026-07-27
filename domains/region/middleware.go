package region

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

// MiddlewareOptions tune the region middleware. Zero value is fine — no
// error reporter, no allowlist (the resolver itself decides what's valid).
type MiddlewareOptions struct {
	// OnError is called when Resolver.Resolve returns a non-nil error. Use
	// for alerting on a malformed region source. Optional — resolution
	// failures stay non-fatal so the request proceeds with an empty region.
	OnError func(r *http.Request, err error)

	// AllowedRegions, when non-empty, restricts the stashed serving region
	// to this set: a resolved value outside it is dropped (the empty region
	// is stashed instead). This is a middleware-level backstop on top of
	// whatever the resolver enforces — it does NOT reject the request
	// (enforcement is a later layer). Empty means "accept whatever the
	// resolver returns".
	AllowedRegions []ID
}

// Middleware constructs a core.MiddlewareFunc that resolves the request's
// serving region through resolver and stashes the resulting ID on the
// HandlerContext value bag under HandlerContextKey. Mirrors geo.Middleware:
// resolution failures are non-fatal — the request proceeds with an empty
// region stashed, and downstream layers treat absence as "unconstrained".
//
// A nil resolver returns a no-op middleware so callers can wire this
// unconditionally (nil-default byte-identical, matching geo's discipline).
func Middleware(resolver Resolver, opts MiddlewareOptions) core.MiddlewareFunc {
	if resolver == nil {
		return func(core.HandlerContext) {}
	}
	return func(hctx core.HandlerContext) {
		id, err := resolver.Resolve(hctx.Request())
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(hctx.Request(), err)
			}
			// Non-fatal: proceed with no region rather than failing the
			// request. Stash the empty ID so a stale value from an earlier
			// middleware can't leak through.
			hctx.Set(HandlerContextKey, ID(""))
			return
		}
		if len(opts.AllowedRegions) > 0 && id != "" && !containsRegion(opts.AllowedRegions, id) {
			// Resolved a region the operator hasn't allow-listed at the
			// middleware boundary: drop it rather than stash an untrusted
			// value. Rejection of the request itself is a later layer.
			id = ""
		}
		hctx.Set(HandlerContextKey, id)
	}
}

// FromHandlerContext returns the serving-region ID the middleware stashed
// for this request, or ("", false) when no middleware ran. An empty ID with
// ok==true means the middleware ran but resolved no region (unconstrained).
func FromHandlerContext(hctx core.HandlerContext) (ID, bool) {
	if hctx == nil {
		return "", false
	}
	v := hctx.Get(HandlerContextKey)
	if v == nil {
		return "", false
	}
	id, ok := v.(ID)
	return id, ok
}

// WithHandlerContext stashes a serving-region ID on the HandlerContext value
// bag — the explicit counterpart to FromHandlerContext, for callers that
// resolve the region outside the middleware (tests, or a handler that
// derives it from already-validated state). No-op on a nil context.
func WithHandlerContext(hctx core.HandlerContext, id ID) {
	if hctx == nil {
		return
	}
	hctx.Set(HandlerContextKey, id)
}
