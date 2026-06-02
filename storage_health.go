package sso

import (
	"context"
	"net/http"
	"sort"
	"time"
)

// StorageHealthSource describes one wired store for the storage-health
// report. The SDK does NOT own the store handles or their *sql.DB — those
// live in cmd, which constructs them per the operator's backend config — so
// this is a small struct of funcs the cmd supplies rather than an interface
// the SDK forces every store to implement. cmd reuses the same collection
// point as appendReadyCheck (every store exposing Ping) and, for the SQLite
// stores, closes over the store's *sql.DB to drive migrate.Status.
//
//   - Name is the operator-facing label (e.g. "identity-users",
//     "oauth-refresh-tokens"); it MUST NOT contain a DSN or any secret.
//   - Ping probes reachability. Required. A nil Ping means the store has no
//     reachability signal (a process-local memory backend) and is reported
//     reachable with no schema versions.
//   - SchemaVersions is optional. When set it returns the store's
//     migrate-namespace -> applied-version map (typically a closure over
//     migrate.Status on the store's *sql.DB). nil ⇒ the report omits
//     schema_versions for this store (e.g. a memory backend, or a SQLite
//     store whose *sql.DB cmd cannot reach).
type StorageHealthSource struct {
	Name           string
	Ping           func(ctx context.Context) error
	SchemaVersions func(ctx context.Context) (map[string]int, error)
}

// WithStorageHealth mounts GET /api/v1/admin/storage-health, a read-only
// admin endpoint that reports per-store reachability (Ping + latency) and
// schema version (migrate namespace -> version) for every supplied source.
// It is the detailed counterpart to /readyz's pass/fail aggregate — the
// view operators need for DR drills and rolling-upgrade safety (which store
// is on which schema, which is slow, which is down).
//
// Admin-gated (admin:read) by the path prefix /api/v1/admin/ — see
// admin.IsProtectedPath. No new go.mod dependency.
//
// nil / no sources ⇒ the route is NOT mounted — behavior is byte-identical
// to a build without it. Sources can be passed across multiple calls; they
// accumulate.
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

// storageHealthStore is one store's entry in the storage-health JSON
// report. A store that fails Ping reports Reachable=false + Error (an
// operator-facing reachability string, never the DSN/credentials) and the
// endpoint still returns 200 — one store being down must not 500 the whole
// report (the operator needs the status of the survivors during a DR
// drill).
type storageHealthStore struct {
	Name           string         `json:"name"`
	Reachable      bool           `json:"reachable"`
	PingLatencyMS  *float64       `json:"ping_latency_ms,omitempty"`
	SchemaVersions map[string]int `json:"schema_versions,omitempty"`
	Error          string         `json:"error,omitempty"`
}

// storageHealthProbeTimeout bounds each store's Ping + schema-version probe
// so a single wedged store can't stall the whole report past a DR drill's
// patience. Generous relative to /readyz's per-check budget because this is
// an operator-initiated diagnostic, not a kubelet probe on the hot path.
const storageHealthProbeTimeout = 3 * time.Second

// handleStorageHealth serves GET /api/v1/admin/storage-health. For each
// wired source it times a Ping (→ reachable + ping_latency_ms) and, when a
// SchemaVersions getter is present, collects the migrate-namespace ->
// version map. The endpoint returns 200 with a per-store status array even
// when individual stores are unreachable — a partial outage during a DR
// drill must still surface the healthy stores, so we never fail the whole
// report on one store. Error strings are reachability messages only; cmd is
// responsible for never putting a DSN/secret in Source.Name or letting one
// surface through Ping (the SQLite Ping returns driver errors, not the DSN).
func (s *Server) handleStorageHealth(ctx HandlerContext) {
	reqCtx := ctx.Request().Context()
	stores := make([]storageHealthStore, 0, len(s.storageHealthSources))
	for _, src := range s.storageHealthSources {
		stores = append(stores, probeStorageHealth(reqCtx, src))
	}
	// Stable ordering so the report is deterministic regardless of wiring
	// order — operators diffing two drills compare like-for-like.
	sort.Slice(stores, func(i, j int) bool { return stores[i].Name < stores[j].Name })
	ctx.JSON(http.StatusOK, map[string]any{
		"stores":       stores,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// probeStorageHealth runs one source's reachability + schema probe under a
// bounded timeout and maps the outcome onto the wire shape. A nil Ping is a
// memory backend with no reachability signal: reported reachable with no
// latency and no schema versions. A Ping error ⇒ reachable=false + the
// error string (and schema versions are skipped — an unreachable store
// can't answer them).
func probeStorageHealth(parent context.Context, src StorageHealthSource) storageHealthStore {
	out := storageHealthStore{Name: src.Name}
	probeCtx, cancel := context.WithTimeout(parent, storageHealthProbeTimeout)
	defer cancel()

	if src.Ping == nil {
		// No reachability signal (process-local memory backend): treat as
		// reachable so the store still surfaces in the report; schema
		// versions are inapplicable.
		out.Reachable = true
		return out
	}

	start := time.Now()
	err := src.Ping(probeCtx)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	out.PingLatencyMS = &latency
	if err != nil {
		out.Reachable = false
		out.Error = err.Error()
		return out
	}
	out.Reachable = true

	if src.SchemaVersions != nil {
		versions, verr := src.SchemaVersions(probeCtx)
		if verr != nil {
			// The store pinged but its schema couldn't be read — surface
			// that as a non-fatal note; the store is still reachable. Don't
			// flip reachable to false (Ping succeeded), but record why
			// schema_versions is absent so an operator isn't left guessing.
			out.Error = verr.Error()
			return out
		}
		if len(versions) > 0 {
			out.SchemaVersions = versions
		}
	}
	return out
}
