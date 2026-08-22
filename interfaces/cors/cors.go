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
// / OPTIONS; AllowedHeaders covers Authorization + Content-Type. Empty
// AllowedOrigins and PathOverrides skips CORS entirely (the middleware is a
// no-op); a non-empty PathOverrides map can enable only selected paths.
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
	// Empty with no PathOverrides = CORS disabled (the middleware is a no-op).
	AllowedOrigins []string

	// AllowedMethods is the list returned in the preflight response.
	// Default: GET, POST, PUT, DELETE, OPTIONS.
	AllowedMethods []string

	// AllowedHeaders is the list returned in the preflight response.
	// Default: Authorization, Content-Type.
	AllowedHeaders []string

	// ExposedHeaders is the list the browser may read from the
	// actual response (beyond the CORS-safelisted defaults). Useful
	// when SPAs need to read X-Request-ID, Retry-After, etc.
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

	// PathOverrides route-matches specific URL path prefixes against
	// distinct CORS policies. The key is a URL path prefix (e.g.
	// "/.well-known/jwks.json") and the value is the policy to apply
	// when the request path starts with that prefix. Longer prefixes
	// are checked first; the first match wins. Use this for endpoints
	// that need a different CORS posture than the router-level default
	// (e.g. a permissive /.well-known/jwks.json vs a strict /token).
	PathOverrides map[string]Policy
}

// corsConfig holds the precomputed CORS values shared across all
// requests. Joined header strings + origin lookups are built once at
// Middleware construction so per-request work is just a few probes.
type corsConfig struct {
	methodsHdr       string
	headersHdr       string
	exposeHdr        string
	maxAgeHdr        string
	allowsWildcard   bool
	allowCredentials bool
	exactOrigins     map[string]struct{}
}

// buildConfig precomputes the per-request constants from p. Defaults
// for methods/headers are applied here (p is taken by value, so the
// caller's Policy is untouched).
func buildConfig(p Policy) corsConfig {
	if len(p.AllowedMethods) == 0 {
		p.AllowedMethods = DefaultAllowedMethods
	}
	if len(p.AllowedHeaders) == 0 {
		p.AllowedHeaders = DefaultAllowedHeaders
	}
	cfg := corsConfig{
		methodsHdr:       strings.Join(p.AllowedMethods, ", "),
		headersHdr:       strings.Join(p.AllowedHeaders, ", "),
		exposeHdr:        strings.Join(p.ExposedHeaders, ", "),
		allowCredentials: p.AllowCredentials,
		exactOrigins:     make(map[string]struct{}, len(p.AllowedOrigins)),
	}
	if p.MaxAge > 0 {
		cfg.maxAgeHdr = strconv.Itoa(int(p.MaxAge.Seconds()))
	}
	for _, o := range p.AllowedOrigins {
		if o == OriginWildcard {
			cfg.allowsWildcard = true
			continue
		}
		cfg.exactOrigins[o] = struct{}{}
	}
	return cfg
}

// originAllowed reports whether origin may receive CORS headers.
func (c *corsConfig) originAllowed(origin string) bool {
	if _, exact := c.exactOrigins[origin]; exact {
		return true
	}
	return c.allowsWildcard
}

// resolveAllowOrigin picks the Access-Control-Allow-Origin value:
//   - Wildcard + credentials: echo the request Origin (spec forbids
//     "*" + credentials).
//   - Wildcard alone (non-exact origin): emit "*".
//   - Exact match: echo the request Origin (no need to emit "*").
func (c *corsConfig) resolveAllowOrigin(origin string) string {
	if c.allowsWildcard && !c.allowCredentials {
		if _, exact := c.exactOrigins[origin]; !exact {
			return OriginWildcard
		}
	}
	return origin
}

// writeCommonHeaders emits the Allow-Origin / Vary / credentials /
// exposed-headers values shared by both preflight and actual requests.
func (c *corsConfig) writeCommonHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set(HeaderAccessControlAllowOrigin, c.resolveAllowOrigin(origin))
	// Vary on Origin so caches don't serve a per-origin response to
	// the wrong origin.
	w.Header().Add(HeaderVary, HeaderOrigin)
	if c.allowCredentials {
		w.Header().Set(HeaderAccessControlAllowCreds, TrueLiteral)
	}
	if c.exposeHdr != "" {
		w.Header().Set(HeaderAccessControlExposeHeaders, c.exposeHdr)
	}
}

// isPreflight reports whether r is a CORS preflight request.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get(HeaderAccessControlRequestMethod) != ""
}

// writePreflight emits the preflight-only headers (methods, headers,
// max-age) and short-circuits with 204 — the actual request arrives
// in a follow-up.
func (c *corsConfig) writePreflight(w http.ResponseWriter) {
	w.Header().Set(HeaderAccessControlAllowMethods, c.methodsHdr)
	w.Header().Set(HeaderAccessControlAllowHeaders, c.headersHdr)
	if c.maxAgeHdr != "" {
		w.Header().Set(HeaderAccessControlMaxAge, c.maxAgeHdr)
	}
	w.WriteHeader(http.StatusNoContent)
}

// Middleware returns an http.Handler middleware enforcing p. When
// AllowedOrigins is empty the middleware is identity (zero overhead
// for deployments not using CORS). When p.PathOverrides is non-empty,
// the request path is checked against overrides BEFORE the default
// policy — so /.well-known/jwks.json can have a permissive policy
// while /token stays locked down.
func Middleware(p Policy) func(http.Handler) http.Handler {
	if len(p.AllowedOrigins) == 0 && len(p.PathOverrides) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	defaultCfg := buildConfig(p)
	overrideCfgs := buildOverrideConfigs(p.PathOverrides)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := resolveCORSConfig(r.URL.Path, defaultCfg, overrideCfgs)

			origin := r.Header.Get(HeaderOrigin)
			if origin == "" || !cfg.originAllowed(origin) {
				// No origin, or not allowed — drop CORS headers
				// entirely. The browser blocks the response on its end.
				next.ServeHTTP(w, r)
				return
			}

			cfg.writeCommonHeaders(w, origin)

			if isPreflight(r) {
				cfg.writePreflight(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// buildOverrideConfigs constructs a sorted-by-length (longest first)
// list of (prefix, config) pairs for path-override matching.
func buildOverrideConfigs(overrides map[string]Policy) []prefixCORSConfig {
	if len(overrides) == 0 {
		return nil
	}
	cfgs := make([]prefixCORSConfig, 0, len(overrides))
	for prefix, p := range overrides {
		cfgs = append(cfgs, prefixCORSConfig{
			prefix: prefix,
			cfg:    buildConfig(p),
		})
	}
	// Sort by prefix length descending so the most specific match wins.
	for i := 0; i < len(cfgs); i++ {
		for j := i + 1; j < len(cfgs); j++ {
			if len(cfgs[j].prefix) > len(cfgs[i].prefix) ||
				(len(cfgs[j].prefix) == len(cfgs[i].prefix) && cfgs[j].prefix < cfgs[i].prefix) {
				cfgs[i], cfgs[j] = cfgs[j], cfgs[i]
			}
		}
	}
	return cfgs
}

// resolveCORSConfig returns the most specific path override for path,
// or the default config when no override matches.
func resolveCORSConfig(path string, defaultCfg corsConfig, overrides []prefixCORSConfig) corsConfig {
	for _, oc := range overrides {
		if len(path) >= len(oc.prefix) && path[:len(oc.prefix)] == oc.prefix {
			return oc.cfg
		}
	}
	return defaultCfg
}

// prefixCORSConfig pairs a URL prefix with its precomputed CORS config.
type prefixCORSConfig struct {
	prefix string
	cfg    corsConfig
}
