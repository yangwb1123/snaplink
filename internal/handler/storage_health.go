package handler

import (
	"context"
	"net/http"
	"sort"
	"time"

)

const storageHealthProbeTimeout = 3 * time.Second

type storageHealthStore struct {
	Name           string         `json:"name"`
	Reachable      bool           `json:"reachable"`
	PingLatencyMS  *float64       `json:"ping_latency_ms,omitempty"`
	SchemaVersions map[string]int `json:"schema_versions,omitempty"`
	Error          string         `json:"error,omitempty"`
}

// HandleStorageHealth serves GET /api/v1/admin/storage-health.
func HandleStorageHealth(d StorageHealthDeps, ctx HandlerContext) {
	reqCtx := ctx.Request().Context()
	sources := d.StorageHealthSources()
	stores := make([]storageHealthStore, 0, len(sources))
	for _, src := range sources {
		stores = append(stores, probeStorageHealth(reqCtx, src))
	}
	sort.Slice(stores, func(i, j int) bool { return stores[i].Name < stores[j].Name })
	ctx.JSON(http.StatusOK, map[string]any{
		"stores":       stores,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func probeStorageHealth(parent context.Context, src StorageHealthSource) storageHealthStore {
	out := storageHealthStore{Name: src.Name}
	probeCtx, cancel := context.WithTimeout(parent, storageHealthProbeTimeout)
	defer cancel()

	if src.Ping == nil {
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
			out.Error = verr.Error()
			return out
		}
		if len(versions) > 0 {
			out.SchemaVersions = versions
		}
	}
	return out
}
