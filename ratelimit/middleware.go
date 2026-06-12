package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/middleware"
)

// Policy maps an incoming request to the limiter that gates it. Prefix
// rules are evaluated in registration order; first match wins. When no
// prefix matches, Default applies. A nil Default means "no rate limit
// for unmatched paths" — useful when only specific endpoints (login,
// send-code) need throttling.
type Policy struct {
	// Default limiter for paths not matched by any Prefix rule. nil =
	// allow without limit.
	Default Limiter

	// Prefixes are checked in order. First match wins; the matching
	// rule's Limiter is used.
	Prefixes []PrefixRule

	// Key extracts the bucket key from a request. Default
	// (KeyByClientIP) keys per source IP. Plug in custom for
	// per-(IP,client_id) buckets, per-API-key, etc.
	Key KeyFunc
}

// PrefixRule pairs a URL path prefix with the limiter that applies
// when the request path starts with the prefix.
type PrefixRule struct {
	Prefix  string
	Limiter Limiter
}

// KeyFunc extracts a bucket key from a request.
type KeyFunc func(*http.Request) string

// KeyByClientIDOrIP keys the limiter by `client_id` when an
// authenticated /token-style request supplies one via HTTP Basic
// (RFC 6749 §2.3.1's mandated method); otherwise falls back to
// [KeyByClientIP]. Useful on /token, /par, /token/introspect and
// /token/revoke where the appropriate noisy-neighbor blast radius
// is the client, not the source IP (which may be shared by
// thousands of users behind a NAT or corporate proxy).
//
// Body-supplied credentials (client_secret_post) are NOT inspected
// because doing so would consume r.Body and break downstream
// handlers that depend on parsing it themselves. The IP fallback
// kicks in for those requests — operators who need per-client
// rate-limiting MUST require client_secret_basic for those endpoints.
func KeyByClientIDOrIP(r *http.Request) string {
	if cid, _, ok := r.BasicAuth(); ok && cid != "" {
		return "client:" + cid
	}
	return KeyByClientIP(r)
}

// KeyByClientIP keys the limiter per validated client IP.
//
// When [middleware.TrustedProxies] middleware is present in the chain
// (installed via [sso.WithTrustedProxies]), it has already derived the
// validated real client IP by walking the X-Forwarded-For chain from
// right to left and stopping at the first untrusted hop; [middleware.RealClientIP]
// returns that validated value and the raw header is not re-read.
//
// Without TrustedProxies middleware, [middleware.RealClientIP] falls back
// to r.RemoteAddr — the direct TCP peer — which is the safe behavior behind
// a layer-4 load balancer that does NOT inject XFF. Operators who run
// behind an L7 proxy that injects XFF MUST wire WithTrustedProxies so the
// IP key is forge-resistant.
func KeyByClientIP(r *http.Request) string {
	return middleware.RealClientIP(r)
}

// Middleware returns an http.Handler middleware that enforces p. Empty
// Policy (no Default, no Prefixes) is identity — useful for tests
// disabling rate limiting via an option flag without removing the
// middleware from the chain.
func Middleware(p Policy) func(http.Handler) http.Handler {
	keyFn := p.Key
	if keyFn == nil {
		keyFn = KeyByClientIP
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lim := p.limiterFor(r.URL.Path)
			if lim == nil {
				next.ServeHTTP(w, r)
				return
			}
			ok, retry := lim.Allow(keyFn(r))
			if !ok {
				writeTooManyRequests(w, retry)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limiterFor returns the Limiter that applies to a given request path,
// or nil when no rule matches and Default is nil.
func (p Policy) limiterFor(path string) Limiter {
	for _, rule := range p.Prefixes {
		if rule.Prefix != "" && strings.HasPrefix(path, rule.Prefix) {
			return rule.Limiter
		}
	}
	return p.Default
}

// writeTooManyRequests writes a standard 429 response with Retry-After
// (seconds, ceiling-rounded so a client never retries early) and a
// minimal JSON body so SPAs can branch on the error code.
func writeTooManyRequests(w http.ResponseWriter, retry time.Duration) {
	if retry > 0 {
		seconds := int(math.Ceil(retry.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set(HeaderRetryAfter, strconv.Itoa(seconds))
	}
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write(rateLimitedBody)
}
