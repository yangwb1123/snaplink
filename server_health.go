package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

)
func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"alive"}`))
}

// handleReadyz runs every registered [ReadyCheck] in parallel,
// aggregates results into `{name: "ok" | err.Error()}`, returns 200
// when all pass / 503 when any fail. Bounded by a 3-second context
// deadline so a hung check can't wedge the probe.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	aggregateCtx, cancelAgg := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancelAgg()

	results := make(map[string]string, len(s.readyChecks))
	allOK := true
	for _, c := range s.readyChecks {
		// Skip orphan timeout entries (WithReadyCheckTimeout
		// registered before any WithReadyCheck for that name) so
		// they don't surface as "ok" results — they're metadata, not
		// checks.
		if c.Check == nil {
			continue
		}
		ctx := aggregateCtx
		// Per-check timeout overrides the aggregate when set + smaller
		// (operators wiring 1s for a fast check). If the per-check
		// timeout is LARGER than what the aggregate has left, the
		// parent ctx still wins — no check can outlive /readyz's hard
		// upper bound (operators wanting longer probes raise the
		// kubelet-side timeoutSeconds).
		if c.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(aggregateCtx, c.Timeout)
			//nolint:gocritic // cancel called below in tight loop; declaring outside the loop wouldn't compose cleanly
			defer cancel()
		}
		if err := c.Check(ctx); err != nil {
			results[c.Name] = err.Error()
			allOK = false
		} else {
			results[c.Name] = "ok"
		}
	}

	status := "ready"
	code := http.StatusOK
	if !allOK {
		status = "unready"
		code = http.StatusServiceUnavailable
	}

	body, _ := json.Marshal(map[string]any{
		"status": status,
		"checks": results,
	})
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// bodyLimitMiddleware wraps r.Body with MaxBytesReader and pre-checks
// Content-Length when set so over-sized requests fail before allocating
// any buffers. Chunked requests fall back to MaxBytesReader's
// streaming guard.
//
// `byPath` overrides the global default per URL prefix (longest match
// wins). An override of 0 means "unlimited for this path" — escape
// hatch for endpoints that legitimately accept large bodies even
// while the global cap is in effect.
func bodyLimitMiddleware(defaultMax int64, byPath map[string]int64) func(http.Handler) http.Handler {
	// Pre-sort the override prefixes by descending length so the
	// hot path picks the longest match without re-sorting per
	// request.
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
				// Unlimited — either no global cap and no override,
				// or an explicit "0" override (escape hatch).
				next.ServeHTTP(w, r)
				return
			}
			if r.ContentLength > max {
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(`{"error":"` + ErrPayloadTooLarge + `"}`))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

