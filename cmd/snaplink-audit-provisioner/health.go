package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
)

const (
	pathLivez   = "/livez"
	pathReadyz  = "/readyz"
	pathMetrics = "/metrics"
)

type runtimeStatus struct {
	ready           atomic.Bool
	appliedRevision atomic.Uint64
	attempts        atomic.Uint64
	successes       atomic.Uint64
	failures        atomic.Uint64
	stale           atomic.Uint64
	conflicts       atomic.Uint64
	tenantCreates   atomic.Uint64
	sourceCreates   atomic.Uint64
	schemaCreates   atomic.Uint64
}

func (status *runtimeStatus) record(result auditgovernance.ReconcileResult, err error) string {
	status.attempts.Add(1)
	class := reconcileErrorClass(err)
	if err == nil {
		status.ready.Store(true)
		status.appliedRevision.Store(result.Revision)
		status.successes.Add(1)
		status.tenantCreates.Add(uint64(result.TenantsCreated))
		status.sourceCreates.Add(uint64(result.SourcesCreated))
		status.schemaCreates.Add(uint64(result.SchemasCreated))
		return class
	}
	status.ready.Store(false)
	status.failures.Add(1)
	if class == "stale_revision" {
		status.stale.Add(1)
	}
	if class == "revision_conflict" || class == "remote_drift" {
		status.conflicts.Add(1)
	}
	return class
}

func reconcileErrorClass(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, auditgovernance.ErrDesiredManifest):
		return "manifest_invalid"
	case errors.Is(err, auditgovernance.ErrDesiredStale):
		return "stale_revision"
	case errors.Is(err, auditgovernance.ErrDesiredConflict):
		return "revision_conflict"
	case errors.Is(err, auditgovernance.ErrRemoteDrift):
		return "remote_drift"
	case errors.Is(err, auditgovernance.ErrTokenUnavailable):
		return "authorization_unavailable"
	default:
		return "control_unavailable"
	}
}

func newStatusHandler(status *runtimeStatus) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(pathLivez, func(writer http.ResponseWriter, request *http.Request) {
		if requireGet(writer, request) {
			writeStatusJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
		}
	})
	mux.HandleFunc(pathReadyz, status.readyz)
	mux.HandleFunc(pathMetrics, status.metrics)
	return mux
}

func (status *runtimeStatus) readyz(writer http.ResponseWriter, request *http.Request) {
	if !requireGet(writer, request) {
		return
	}
	code, state := http.StatusOK, "ready"
	if !status.ready.Load() {
		code, state = http.StatusServiceUnavailable, "degraded"
	}
	writeStatusJSON(writer, code, map[string]any{
		"status": state, "applied_revision": status.appliedRevision.Load(),
	})
}

func (status *runtimeStatus) metrics(writer http.ResponseWriter, request *http.Request) {
	if !requireGet(writer, request) {
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	ready := 0
	if status.ready.Load() {
		ready = 1
	}
	_, _ = fmt.Fprintf(writer, `snaplink_audit_provisioner_ready %d
snaplink_audit_provisioner_applied_revision %d
snaplink_audit_provisioner_reconcile_total{result="success"} %d
snaplink_audit_provisioner_reconcile_total{result="failure"} %d
snaplink_audit_provisioner_revision_rejected_total{reason="stale"} %d
snaplink_audit_provisioner_revision_rejected_total{reason="conflict"} %d
snaplink_audit_provisioner_created_total{kind="tenant"} %d
snaplink_audit_provisioner_created_total{kind="source"} %d
snaplink_audit_provisioner_created_total{kind="schema"} %d
`, ready, status.appliedRevision.Load(), status.successes.Load(), status.failures.Load(),
		status.stale.Load(), status.conflicts.Load(), status.tenantCreates.Load(),
		status.sourceCreates.Load(), status.schemaCreates.Load())
}

func requireGet(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet {
		return true
	}
	writer.Header().Set("Allow", http.MethodGet)
	writer.WriteHeader(http.StatusMethodNotAllowed)
	return false
}

func writeStatusJSON(writer http.ResponseWriter, code int, value any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(code)
	_ = json.NewEncoder(writer).Encode(value)
}
