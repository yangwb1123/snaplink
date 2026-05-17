// Package cors provides a minimal CORS middleware that composes with
// the `http.Handler` middleware stack the sso package uses for
// metrics + ratelimit + tracing.
//
// The legacy `sso.CORS` (in middleware.go) is a `MiddlewareFunc`
// bound to the SSO router — it can't be wrapped around the entire
// handler tree. Use this package for new SPA integrations that need
// full CORS semantics (credentials, exposed headers, preflight
// caching).
//
// Sensible defaults: AllowedMethods covers GET / POST / PUT / DELETE
// / OPTIONS; AllowedHeaders covers Authorization + Content-Type. An
// empty AllowedOrigins skips CORS entirely (the middleware is a
// no-op).
package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Policy configures the CORS middleware. Empty fields fall back to
// the sensible defaults documented in the package doc.
type Policy struct {
	// AllowedOrigins is the exact list of origins that may reach the
	// server. "*" wildcards every origin (the browser then refuses to
	// send credentials per the CORS spec — combine with
	// AllowCredentials only when you've enumerated specific origins).
	// Empty = CORS disabled (the middleware is a no-op).
	AllowedOrigins []string

	// AllowedMethods is the list returned in the preflight response.
	// Default: GET, POST, PUT, DELETE, OPTIONS.
	AllowedMethods []string

	// AllowedHeaders is the list returned in the preflight response.
	// Default: Authorization, Content-Type.
	AllowedHeaders []string

	// ExposedHeaders is the list the browser may read from the
	// actual response (beyond the CORS-safelisted defaults). Useful
	// when SPAs need to read X-Request-ID, X-RateLimit-Remaining, etc.
	ExposedHeaders []string

	// AllowCredentials sets Access-Control-Allow-Credentials: true.
	// The spec forbids combining this with AllowedOrigins=["*"] —
	// the middleware echoes the request Origin instead when both
	// are set, which the spec allows.
	AllowCredentials bool

	// MaxAge sets Access-Control-Max-Age (preflight cache TTL on
	// the browser). 0 = header omitted (browser default, typically
	// 5 seconds). Common production value: 1 * time.Hour.
	MaxAge time.Duration
}

// Middleware returns an http.Handler middleware enforcing p. When
// AllowedOrigins is empty the middleware is identity (zero overhead
// for deployments not using CORS).
func Middleware(p Policy) func(http.Handler) http.Handler {
	if len(p.AllowedOrigins) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	// Cache joined strings + lookups so per-request work is just a
	// few map / slice probes.
	if len(p.AllowedMethods) == 0 {
		p.AllowedMethods = []string{
			http.MethodGet, http.MethodPost, http.MethodPut,
			http.MethodDelete, http.MethodOptions,
		}
	}
	if len(p.AllowedHeaders) == 0 {
		p.AllowedHeaders = []string{"Authorization", "Content-Type"}
	}
	methodsHdr := strings.Join(p.AllowedMethods, ", ")
	headersHdr := strings.Join(p.AllowedHeaders, ", ")
	exposeHdr := strings.Join(p.ExposedHeaders, ", ")
	var maxAgeHdr string
	if p.MaxAge > 0 {
		maxAgeHdr = strconv.Itoa(int(p.MaxAge.Seconds()))
	}

	allowsWildcard := false
	exactOrigins := make(map[string]struct{}, len(p.AllowedOrigins))
	for _, o := range p.AllowedOrigins {
		if o == "*" {
			allowsWildcard = true
			continue
		}
		exactOrigins[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			if _, exact := exactOrigins[origin]; !exact && !allowsWildcard {
				// Not allowed — drop CORS headers entirely. The
				// browser blocks the response on its end.
				next.ServeHTTP(w, r)
				return
			}

			// Allowed origin echo strategy:
			//   * Wildcard + credentials: echo the request Origin
			//     (spec forbids "*" + credentials).
			//   * Wildcard alone: emit "*".
			//   * Exact match: echo the request Origin (no need to
			//     emit "*").
			allowOrigin := origin
			if allowsWildcard && !p.AllowCredentials {
				if _, exact := exactOrigins[origin]; !exact {
					allowOrigin = "*"
				}
			}
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			// Vary on Origin so caches don't serve a per-origin
			// response to the wrong origin.
			w.Header().Add("Vary", "Origin")
			if p.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			if exposeHdr != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposeHdr)
			}

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				// CORS preflight. Echo methods + headers + max-age,
				// short-circuit with 204 — the actual request comes
				// in a follow-up.
				w.Header().Set("Access-Control-Allow-Methods", methodsHdr)
				w.Header().Set("Access-Control-Allow-Headers", headersHdr)
				if maxAgeHdr != "" {
					w.Header().Set("Access-Control-Max-Age", maxAgeHdr)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
