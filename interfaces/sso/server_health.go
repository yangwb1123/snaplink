package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/shared/core"
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
			// Log the raw error server-side; the HTTP body must not
			// expose internal strings to unauthenticated callers.
			s.logger.Error("readyz check failed", "check", rc.Name, "error", err)
			results[rc.Name] = "check failed"
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

func WithStorageHealth(sources ...StorageHealthSource) Option {
	return func(s *Server) {
		for _, src := range sources {
			if src.Name == "" {
				continue
			}
			s.storageHealthSources = append(s.storageHealthSources, src)
		}
	}
}

func (s *Server) handleStorageHealth(ctx HandlerContext) {
	handler.HandleStorageHealth(s.BuildHandlerDeps(), ctx)
}

func (s *Server) logErrorCtx(ctx core.HandlerContext, msg string, kv ...any) {
	handler.LogErrorCtx(s.BuildHandlerDeps(), ctx, msg, kv...)
}

// handleStatus serves GET /api/v1/status — runtime server health + info.
// Unauthenticated, read-only, no business logic.
//
// The response includes:
//   - version / commit / build_time / uptime_seconds (runtime identity)
//   - modules — per-store connectivity health (probed via the wired
//     StorageHealthSource list, which the cmd layer populates from every
//     store that has a Ping() method)
//   - stats — lightweight counts where a cheap backend fingerprint is
//     available (ClientStoreStats), omitted when the backend does not
//     implement the optional interface (no List() call is ever made)
func (s *Server) handleStatus(ctx HandlerContext) {
	bi := core.ReadBuildInfo()
	uptime := time.Since(s.startedAt).Truncate(time.Second)

	// Module health: probe every wired StorageHealthSource. Each source
	// has a Ping() that the cmd layer installed — this is the same probe
	// the admin /storage-health endpoint uses, but aggregated here for a
	// single-request overview.
	modules := s.probeModules(ctx.Request().Context())

	// Stats: cheap fingerprint where the optional interface is implemented.
	stats := s.collectStatusStats(ctx.Request().Context())

	body := map[string]any{
		"version":        bi.Version,
		"commit":         bi.VCSRevision,
		"build_time":     bi.VCSTime,
		"uptime_seconds": int(uptime.Seconds()),
		"modules":        modules,
	}
	if len(stats) > 0 {
		body["stats"] = stats
	}

	ctx.JSON(http.StatusOK, body)
}

// probeModules runs Ping on every wired StorageHealthSource and returns
// a map of module name → "ok" / "error: <msg>". Sources without a Ping
// function are reported as "ok" (they are stateless wrappers). The total
// probe time is bounded by storageHealthProbeTimeout per source.
func (s *Server) probeModules(parent context.Context) map[string]string {
	modules := map[string]string{}

	// Pre-populate with the basic wiring status so even backends without
	// a Ping() are visible.
	if s.sessionMgr != nil {
		modules["sessions"] = "ok"
	}
	if s.userProvider != nil {
		modules["users"] = "ok"
	}
	if s.clientStore != nil {
		modules["clients"] = "ok"
	}

	// Run Ping probes on every wired StorageHealthSource. Multiple sources
	// may map to the same module key (e.g. "sqlite-oauth-auth-codes" and
	// "sqlite-oauth-refresh-tokens"), so the last probe wins — they all
	// share the same backend connectivity anyway.
	for _, src := range s.storageHealthSources {
		if src.Ping == nil {
			continue
		}
		probeCtx, cancel := context.WithTimeout(parent, storageHealthProbeTimeout)
		if err := src.Ping(probeCtx); err != nil {
			modules[src.Name] = "error: " + err.Error()
		} else {
			modules[src.Name] = "ok"
		}
		cancel()
	}

	// Sort module keys for deterministic output.
	if len(modules) > 1 {
		keys := make([]string, 0, len(modules))
		for k := range modules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sorted := make(map[string]string, len(keys))
		for _, k := range keys {
			sorted[k] = modules[k]
		}
		modules = sorted
	}
	return modules
}

// collectStatusStats returns lightweight counts where a cheap fingerprint
// interface is available. This never calls List() — only optional interfaces
// that the backend MAY implement for cheap cardinality queries.
func (s *Server) collectStatusStats(_ context.Context) map[string]int {
	stats := map[string]int{}

	if s.clientStore != nil {
		if cs, ok := s.clientStore.(ClientStoreStats); ok {
			// Use a background context — this is best-effort
			// informational output, not a request-path operation.
			if count, _, err := cs.Stats(context.Background()); err == nil {
				stats["registered_clients"] = count
			}
		}
	}

	return stats
}

// storageHealthProbeTimeout is the per-source Ping deadline used by
// handleStatus. Mirrors the internal/handler constant so status and
// the admin storage-health endpoint use the same timeout.
const storageHealthProbeTimeout = 3 * time.Second
