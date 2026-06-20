package handler

import (
	"net/http"
	"sort"
	"strings"

	"github.com/snaplink/sso/shared/core"
)

// HandleLivez serves GET /livez — always 200 with {"status":"alive"}.
func HandleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"alive"}`))
}

// BodyLimitMiddleware caps request body size. It pre-checks
// Content-Length when set so over-sized requests are rejected with 413
// before any handler reads the body — without the pre-check a bare
// MaxBytesReader only surfaces the overflow when the downstream handler
// reads, which collapses into the handler's generic 400 and hides the
// real cause from operators. Chunked requests (no Content-Length) fall
// back to MaxBytesReader's streaming guard.
//
// `byPath` overrides the global default per URL prefix (longest match
// wins). An override of 0 means "unlimited for this path" — the escape
// hatch for endpoints that legitimately accept large bodies even while
// the global cap is in effect.
func BodyLimitMiddleware(defaultMax int64, byPath map[string]int64) func(http.Handler) http.Handler {
	// Pre-sort override prefixes by descending length so the hot path
	// picks the longest match without re-sorting per request.
	type prefixCap struct {
		prefix string
		max    int64
	}
	prefixes := make([]prefixCap, 0, len(byPath))
	for p, m := range byPath {
		prefixes = append(prefixes, prefixCap{prefix: p, max: m})
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return len(prefixes[i].prefix) > len(prefixes[j].prefix)
	})

	resolveMax := func(path string) int64 {
		for _, pc := range prefixes {
			if strings.HasPrefix(path, pc.prefix) {
				return pc.max
			}
		}
		return defaultMax
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			max := resolveMax(r.URL.Path)
			if max <= 0 {
				// Unlimited — no global cap and no override, or an
				// explicit "0" override (escape hatch).
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength > max {
				w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(`{"error":"` + core.ErrPayloadTooLarge + `"}`))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}
