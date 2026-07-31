package peertrust

import (
	"context"
	"net/http"
)

// RequestInfo is the canonical proxy-boundary result for one HTTP request.
// Only the trusted-proxy middleware should create it; lower layers consume it
// instead of independently deciding whether X-Forwarded-* can be trusted.
type RequestInfo struct {
	ClientIP                string
	ForwardedHeadersTrusted bool
}

type requestInfoKey struct{}

// WithRequestInfo returns a context carrying the canonical proxy-boundary
// result. It is exported so delivery adapters can stamp requests while the
// security decision remains owned by this shared kernel package.
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFrom returns the canonical proxy-boundary result when a trusted
// proxy middleware evaluated the request.
func RequestInfoFrom(r *http.Request) (RequestInfo, bool) {
	if r == nil {
		return RequestInfo{}, false
	}
	info, ok := r.Context().Value(requestInfoKey{}).(RequestInfo)
	return info, ok
}

// ForwardedHeadersTrusted reports the direct-peer verdict. Absence preserves
// the documented legacy first-hop trust contract; installing the trusted
// proxy middleware turns this into an explicit allow/deny decision.
func ForwardedHeadersTrusted(r *http.Request) bool {
	info, ok := RequestInfoFrom(r)
	return !ok || info.ForwardedHeadersTrusted
}
