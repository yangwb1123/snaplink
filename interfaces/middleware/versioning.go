package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// DeprecationPolicy configures the opt-in Sunset (RFC 8594) + Deprecation
// (draft-ietf-httpapi-deprecation-header convention) response headers for one
// endpoint, a group of endpoints, or the whole API. The zero value is never
// applied on its own — [Deprecation] only stamps headers for a policy a
// caller explicitly wired via [DeprecationConfig], so an unconfigured server
// adds neither header to any response (ADR-0008).
type DeprecationPolicy struct {
	// Since is when the resource became deprecated, formatted per the
	// draft-ietf-httpapi-deprecation-header convention. The zero value emits
	// "Deprecation: true" (deprecated, timing unspecified) instead of a date.
	Since time.Time
	// Sunset is the RFC 8594 date the resource stops being available. The
	// zero value omits the Sunset header — a resource MAY be marked
	// deprecated without yet committing to a removal date.
	Sunset time.Time
	// Link is an optional absolute URL to a migration guide, emitted as
	// `Link: <url>; rel="sunset"` alongside Sunset. Empty omits the header.
	Link string
}

// DeprecationConfig selects which responses [Deprecation] stamps. Global (if
// set) applies to every request; Routes additionally (or instead) marks
// individual endpoints, keyed by exact path or by a "/"-suffixed prefix (e.g.
// "/api/v1/admin/" matches every path under that prefix). A path matching
// both Global and an entry in Routes gets the Routes policy — the more
// specific opt-in wins. Both fields empty/nil ⇒ Deprecation is a pure
// pass-through, adding no header to any response.
type DeprecationConfig struct {
	Global *DeprecationPolicy
	Routes map[string]DeprecationPolicy
}

// Deprecation returns http.Handler middleware that stamps the Sunset +
// Deprecation (+ optional Link) response headers configured by cfg, then
// always calls through to next — it never rejects a request, only annotates
// the response. Wire it in the server's middleware chain (whole-API opt-in
// via a non-nil cfg.Global) or reuse it per-route via cfg.Routes; either way,
// a server that never configures either field never adds these headers,
// which keeps every existing route byte-identical by default.
func Deprecation(cfg DeprecationConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if policy, ok := matchDeprecationRoute(cfg.Routes, r.URL.Path); ok {
				stampDeprecationHeaders(w, policy)
			} else if cfg.Global != nil {
				stampDeprecationHeaders(w, *cfg.Global)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// matchDeprecationRoute finds the most specific Routes entry for path: an
// exact match wins; otherwise the longest "/"-suffixed prefix that path
// starts with. Returns ok=false when routes is empty or nothing matches.
func matchDeprecationRoute(routes map[string]DeprecationPolicy, path string) (DeprecationPolicy, bool) {
	if policy, ok := routes[path]; ok {
		return policy, true
	}
	var best DeprecationPolicy
	bestLen := -1
	for key, policy := range routes {
		if !strings.HasSuffix(key, "/") || !strings.HasPrefix(path, key) {
			continue
		}
		if len(key) > bestLen {
			best, bestLen = policy, len(key)
		}
	}
	return best, bestLen >= 0
}

// stampDeprecationHeaders sets the Deprecation/Sunset/Link headers per
// policy. Called BEFORE next.ServeHTTP so the downstream handler's own
// WriteHeader call (if any) still ships these values — Go's ResponseWriter
// allows setting headers any time before the status line is written.
func stampDeprecationHeaders(w http.ResponseWriter, policy DeprecationPolicy) {
	h := w.Header()
	deprecationValue := "true"
	if !policy.Since.IsZero() {
		deprecationValue = policy.Since.UTC().Format(http.TimeFormat)
	}
	h.Set(core.HeaderDeprecation, deprecationValue)
	if !policy.Sunset.IsZero() {
		h.Set(core.HeaderSunset, policy.Sunset.UTC().Format(http.TimeFormat))
	}
	if policy.Link != "" {
		h.Set(core.HeaderLink, "<"+policy.Link+`>; rel="sunset"`)
	}
}

// AcceptVersionConfig configures Accept-Version request-header negotiation
// (ADR-0008).
type AcceptVersionConfig struct {
	// Supported lists the version tokens this deployment accepts (e.g. "v1",
	// "v2alpha"). Empty/nil disables negotiation entirely: [AcceptVersion]
	// passes every request through unmodified regardless of what
	// Accept-Version value (if any) it carries. This is what keeps the
	// mechanism additive — a server that never calls WithAPIVersioning
	// behaves byte-identically to one built before this package existed.
	Supported []string
}

// AcceptVersion returns http.Handler middleware enforcing Accept-Version
// negotiation. A request with NO Accept-Version header is NEVER touched —
// today's behavior for every existing client is unchanged. A request that
// DOES send the header must name one of cfg.Supported or the middleware
// short-circuits with 400 + {"error":"unsupported_version"} before the
// route (and any handler-level work) ever runs. When cfg.Supported is
// empty, negotiation is off and every request — header or not — passes
// through untouched.
func AcceptVersion(cfg AcceptVersionConfig) func(http.Handler) http.Handler {
	supported := make(map[string]bool, len(cfg.Supported))
	for _, v := range cfg.Supported {
		supported[v] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(supported) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			v := r.Header.Get(core.HeaderAcceptVersion)
			if v == "" || supported[v] {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
			w.WriteHeader(http.StatusBadRequest)
			// Both the code and the description are fixed strings (the
			// caller-supplied version value v is never echoed into the body),
			// so hand-building the JSON is safe — same pattern as
			// writeServiceDegraded's fixed-vocabulary body in degradation.go.
			_, _ = w.Write([]byte(`{"` + core.KeyError + `":"` + core.ErrUnsupportedVersion +
				`","` + core.KeyErrorDescription + `":"requested API version is not supported by this deployment"}`))
		})
	}
}
