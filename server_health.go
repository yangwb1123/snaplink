package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/snaplink/sso/internal/handler"
)

func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	handler.HandleLivez(w, r)
}

// handleReadyz runs every registered [ReadyCheck], aggregates results
// into a `checks` map of {name: "ok" | err.Error()}, returns 200 when
// all pass / 503 when any fail. The per-check name MUST surface in the
// body so operators (and the kubelet) can tell which dependency broke.
// Bounded by a 3-second context deadline so a hung check can't wedge
// the probe.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	aggregateCtx, cancelAgg := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancelAgg()

	results := make(map[string]string, len(s.readyChecks))
	allOK := true
	for _, rc := range s.readyChecks {
		// Skip orphan timeout entries (WithReadyCheckTimeout
		// registered before any WithReadyCheck for that name) so they
		// don't surface as "ok" results — they're metadata, not checks.
		if rc.Check == nil {
			continue
		}
		ctx := aggregateCtx
		// Per-check timeout overrides the aggregate when set; the
		// parent ctx still bounds it so no check outlives /readyz's
		// hard upper bound.
		if rc.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(aggregateCtx, rc.Timeout)
			//nolint:gocritic // cancel called below in tight loop; declaring outside wouldn't compose cleanly
			defer cancel()
		}
		if err := rc.Check(ctx); err != nil {
			results[rc.Name] = err.Error()
			allOK = false
		} else {
			results[rc.Name] = "ok"
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

func bodyLimitMiddleware(defaultMax int64, byPath map[string]int64) func(http.Handler) http.Handler {
	return handler.BodyLimitMiddleware(defaultMax, byPath)
}
