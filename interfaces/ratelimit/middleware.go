package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/middleware"
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

// KeyByClientIDOrIP is UNSAFE as a sole rate-limit key and is retained only for
// SDK back-compat — the binary now keys by [KeyByClientIP] (see
// serverbuildplatform). The rate-limit middleware runs BEFORE client
// authentication, so the HTTP Basic username here is unverified, attacker-chosen
// input. Keying a bucket on it lets a single source rotate the username per
// request (`Basic r1:x`, `Basic r2:x`, ...) to spawn a fresh empty bucket every
// time and escape ALL throttling — both the per-bucket and the per-IP bound —
// turning the limiter off for credential-stuffing / flood / bcrypt-CPU DoS.
//
// A per-client bucket can only be keyed SAFELY on an AUTHENTICATED client, which
// is a post-auth concern this pre-auth middleware cannot satisfy. Prefer
// [KeyByClientIP]: the edge-validated source IP cannot be forged per request, so
// it is the un-escapable abuse bound.
func KeyByClientIDOrIP(r *http.Request) string {
	if cid, _, ok := r.BasicAuth(); ok && cid != "" {
		return "client:" + cid
	}
	return KeyByClientIP(r)
}

// KeyByClientIP keys the limiter per real client IP.
//
// When [middleware.TrustedProxies] middleware is present in the chain
// (installed via [sso.WithTrustedProxies]), it has already derived the
// validated real client IP by walking the X-Forwarded-For chain from
// right to left; [middleware.RealClientIP] returns that validated value.
//
// Without TrustedProxies, KeyByClientIP returns the TCP remote address
// (r.RemoteAddr host). X-Forwarded-For is intentionally NOT read here —
// a client can set any XFF value, so reading it without chain validation
// would let an attacker forge their own key and bypass rate limiting.
// Operators behind a trusted L7 proxy MUST wire WithTrustedProxies so the
// edge-stripped, CIDR-validated IP is used instead.
func KeyByClientIP(r *http.Request) string {
	return middleware.RealClientIP(r)
}

// KeyBySubject keys the limiter per authenticated subject (user ID).
// When the request carries a validated bearer token and the auth
// middleware has stored the subject in the context via
// [middleware.WithSubject], this function returns "sub:<subject>".
// This makes the rate limit per-user rather than per-IP — useful on
// /userinfo and other per-user resource endpoints where many users
// can share a single NAT or corporate IP.
//
// Falls back to [KeyByClientIP] when no authenticated subject is
// available (unauthenticated requests, or middleware ran before auth).
func KeyBySubject(r *http.Request) string {
	if sub := middleware.SubjectFromContext(r); sub != "" {
		return "sub:" + sub
	}
	return KeyByClientIP(r)
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
