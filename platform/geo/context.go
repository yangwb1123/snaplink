package geo

import "context"

// ctxKey is the unique unexported type used for context.WithValue
// keys; the unexported type prevents key collisions across
// packages that might also stash values on the same Context.
type ctxKey struct{}

// WithContext returns a derived context carrying info. Useful when
// callers need to thread the geo lookup result into a downstream
// gRPC call, audit metadata enrichment, or any other code path
// that only sees a context.Context (not the SSO HandlerContext
// value bag — for that, use the FromHandlerContext helper exposed
// by the sso package).
//
// Passing nil info returns ctx unchanged so callers can chain
// unconditionally.
func WithContext(ctx context.Context, info *GeoInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, info)
}

// FromContext returns the *GeoInfo stashed via WithContext, or
// (nil, false) when not set. Treat the false case as "no hint,
// fall through to defaults" — geo is a UX hint, not a security
// signal.
func FromContext(ctx context.Context) (*GeoInfo, bool) {
	if ctx == nil {
		return nil, false
	}
	info, ok := ctx.Value(ctxKey{}).(*GeoInfo)
	return info, ok && info != nil
}
