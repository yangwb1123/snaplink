package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestBuildApp_MetricsEndpointServedWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Metrics.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// promhttp serves the standard Go runtime + process collectors out
	// of the box; presence of either proves the registry is live.
	if !strings.Contains(string(body), "go_goroutines") {
		t.Errorf("response missing go_goroutines: %.200q", body)
	}
}

func TestBuildApp_MetricsEndpointAbsentWhenDisabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	// Metrics.Enabled defaults to false.

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// /metrics isn't registered in the outer mux, so it falls through
	// to the SSO router, which has no handler for it → 404.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d want 404 when metrics disabled", resp.StatusCode)
	}
}

func TestBuildApp_MetricsRegistersAsyncSinkCollectorWhenAuditAsyncOn(t *testing.T) {
	t.Parallel()
	// Async audit + metrics together — verify that the AsyncSinkCollector
	// hooks into the registry so its series surface on /metrics.
	cfg := &config.Config{}
	cfg.Metrics.Enabled = true
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 32
	cfg.Audit.Async.Enabled = true

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.auditAsyncSink != nil {
		defer func() { _ = a.auditAsyncSink.Close(context.Background()) }()
	}

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "sso_audit_async_queue_capacity") {
		t.Errorf("response missing async sink series: %.500q", body)
	}
}
