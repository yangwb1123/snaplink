package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
)

func TestStatusHandlerSeparatesLivenessReadinessAndMetrics(t *testing.T) {
	status := &runtimeStatus{}
	handler := newStatusHandler(status)
	degraded := httptest.NewRecorder()
	handler.ServeHTTP(degraded, httptest.NewRequest(http.MethodGet, pathReadyz, nil))
	if degraded.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded readiness status=%d", degraded.Code)
	}
	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, pathLivez, nil))
	if live.Code != http.StatusOK {
		t.Fatalf("liveness status=%d", live.Code)
	}
	status.record(auditgovernance.ReconcileResult{
		Revision: 4, TenantsCreated: 1, SourcesCreated: 2, SchemasCreated: 3,
	}, nil)
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, pathReadyz, nil))
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"applied_revision":4`) {
		t.Fatalf("readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, pathMetrics, nil))
	if !strings.Contains(metrics.Body.String(), `snaplink_audit_provisioner_created_total{kind="schema"} 3`) {
		t.Fatalf("metrics=%s", metrics.Body.String())
	}
}

func TestStatusReturnsToDegradedOnStaleManifest(t *testing.T) {
	status := &runtimeStatus{}
	status.record(auditgovernance.ReconcileResult{Revision: 5}, nil)
	status.record(auditgovernance.ReconcileResult{Revision: 4}, auditgovernance.ErrDesiredStale)
	response := httptest.NewRecorder()
	newStatusHandler(status).ServeHTTP(response, httptest.NewRequest(http.MethodGet, pathReadyz, nil))
	if response.Code != http.StatusServiceUnavailable || status.appliedRevision.Load() != 5 {
		t.Fatalf("status=%d applied=%d", response.Code, status.appliedRevision.Load())
	}
}
