package ratelimit

// HTTP header names emitted or inspected by the middleware. Local
// constants rather than reuse from sso/consts.go because the
// ratelimit package cannot import sso (would cycle: sso → ratelimit
// via WithRateLimit).
const (
	HeaderRetryAfter    = "Retry-After"
	HeaderContentType   = "Content-Type"
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"

	ContentTypeJSON = "application/json"
)

// ErrRateLimited is the stable error code in the 429 response body.
// SPAs branch on this string; never on the human-readable message.
const ErrRateLimited = "rate_limited"

// rateLimitedBody is the canonical 429 JSON body, precomputed so the
// hot path doesn't allocate per rejection.
var rateLimitedBody = []byte(`{"error":"` + ErrRateLimited + `"}`)
