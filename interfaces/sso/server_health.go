package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/degradation"
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

// mountAPIVersionPreview registers GET /api/v2alpha/version when opted in
// (WithAPIVersionPreview). This is ADR-0008's ONE example route proving the
// "/api/v2alpha" path-prefix routing mechanism actually works — it is
// deliberately NOT a commitment to a full v2 API surface (see the ADR's
// tiered version-progression lifecycle: v2alpha is a no-guarantees preview).
// False (the default) ⇒ Mount() never registers it, byte-identical to a
// build without this feature.
func (s *Server) mountAPIVersionPreview() {
	if !s.apiV2AlphaPreview {
		return
	}
	s.router.GET(core.PathAPIVersionPreview, s.handleAPIVersionPreview)
}

// handleAPIVersionPreview serves GET /api/v2alpha/version — a read-only,
// unauthenticated capability probe advertising the API versioning tiers this
// deployment understands (ADR-0008's Decision table): "v1" is always stable;
// "v2alpha" (this very endpoint) is preview/no-guarantees. supported_versions
// echoes WithAPIVersioning's configured list, if any, so a client can confirm
// what Accept-Version tokens the negotiation middleware will accept.
func (s *Server) handleAPIVersionPreview(ctx HandlerContext) {
	ctx.JSON(http.StatusOK, map[string]any{
		"api_version":        "v2alpha",
		"stability":          "preview",
		"supported_versions": s.apiVersionSupported,
	})
}

// --- Disaster-recovery degraded-service (DR) control plane ---

// PathDRMode is the admin degraded-service mode endpoint. Mounted under the
// /api/v1 group (full path /api/v1/admin/dr/mode), so the admin middleware
// gates GET as admin:read and POST as admin:write via the /api/v1/admin/ prefix.
const PathDRMode = "/admin/dr/mode"

// DR enforcement-policy path prefixes. Held as named consts (not inline
// literals) so the auth-plane / discovery reads the auth_only mode keeps open
// cannot silently drift from the routes actually mounted.
const (
	drAuthPlanePrefix = "/auth/"        // /auth/login, /auth/mfa, /auth/send-code, ...
	drWellKnownPrefix = "/.well-known/" // JWKS + discovery — needed to CONSUME issued tokens
)

// degradationPolicy declares which requests each degraded mode permits, wired
// from the server's real endpoint paths. See degradation.Policy for the
// per-mode semantics; the sets here are the concrete instantiation:
//   - probes always pass;
//   - read_only keeps the token issuance/introspection plane writable;
//   - auth_only keeps only the auth + token + key/discovery plane;
//   - local_only sheds the remote-dependent endpoints (home-realm upstream
//     discovery, federation fetch, inbound shared-signals push).
func (s *Server) degradationPolicy() degradation.Policy {
	return degradation.Policy{
		// Probes + the DR toggle itself stay reachable in every mode so an
		// operator can always lift the posture over HTTP (full path = the
		// /api/v1 group prefix + the admin-relative PathDRMode).
		ProbePaths:     []string{PathLivez, PathReadyz, PathMetrics, PathAPIPrefix + PathDRMode},
		ReadOnlyExempt: []string{PathToken, PathIntrospect},
		AuthOnlyAllow:  []string{drAuthPlanePrefix, PathToken, drWellKnownPrefix},
		LocalOnlyBlock: []string{PathSSFReceive, PathFederationFetch, PathHomeRealm},
	}
}

// degradationGate builds the enforcement middleware. Called only when
// s.degradation is wired (see buildMiddlewareChain), so a build without the
// feature never constructs it. It seeds the state gauge with the boot posture
// and increments the degraded-rejection counter on every refusal.
func (s *Server) degradationGate() func(http.Handler) http.Handler {
	if s.metrics != nil && s.metrics.DegradationMode != nil {
		s.metrics.DegradationMode.WithLabelValues(string(s.degradation.Mode())).Set(1)
	}
	return middleware.Degradation(middleware.DegradationConfig{
		Controller: s.degradation,
		Policy:     s.degradationPolicy(),
		OnReject: func(mode degradation.Mode, r *http.Request) {
			if s.metrics != nil && s.metrics.DegradedRejectionsTotal != nil {
				s.metrics.DegradedRejectionsTotal.WithLabelValues(string(mode), r.Method).Inc()
			}
		},
	})
}

// onDegradationChange is the manager change hook: it moves the state gauge and
// records the transition to the audit trail (with the acting admin, when the
// change came through the admin endpoint). Registered by WithDegradationManager.
func (s *Server) onDegradationChange(ctx context.Context, from, to degradation.Mode, reason string) {
	s.logger.Info("degradation mode changed", "from", string(from), "to", string(to), "reason", reason)
	if s.metrics != nil && s.metrics.DegradationMode != nil {
		s.metrics.DegradationMode.WithLabelValues(string(from)).Set(0)
		s.metrics.DegradationMode.WithLabelValues(string(to)).Set(1)
	}
	if s.auditor == nil {
		return
	}
	e := &audit.Event{Type: audit.EventDegradationModeChanged, Outcome: audit.OutcomeSuccess, Timestamp: time.Now()}
	if actor, _, ok := admin.ActorFromContext(ctx); ok {
		e.ActorID = actor
	}
	e.Reason = reason
	audit.SetMeta(e, "from", string(from))
	audit.SetMeta(e, "to", string(to))
	s.auditor.Record(ctx, e)
}

// handleGetDRMode serves GET /api/v1/admin/dr/mode — the current posture.
func (s *Server) handleGetDRMode(ctx HandlerContext) {
	ctx.JSON(http.StatusOK, map[string]string{"mode": string(s.degradation.Mode())})
}

// handleSetDRMode serves POST /api/v1/admin/dr/mode — sets the posture. Body:
// {"mode": "<mode>", "reason": "<why>"}. An unknown mode returns 400
// invalid_mode; a malformed body returns 400 invalid_request.
func (s *Server) handleSetDRMode(ctx HandlerContext) {
	var req struct {
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	changed, err := s.degradation.SetMode(ctx.Request().Context(), degradation.Mode(req.Mode), req.Reason)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidMode})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"mode": req.Mode, "changed": changed})
}
