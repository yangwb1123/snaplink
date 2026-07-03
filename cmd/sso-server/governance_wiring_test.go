package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

// governance_wiring_test.go proves the wave-2 cmd wiring: the credential
// rotation scheduler, config-audit snapshots/history/drift, and break-glass
// sweeper are wired iff their config section enables them, and leave the build
// byte-identical (no lifecycle handle, no mounted route) when disabled.

func governanceEnabledConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Rotation.Enabled = true
	cfg.Rotation.Interval = time.Hour
	cfg.Rotation.Overlap = time.Minute
	// Seeds the webhook-HMAC rotator; also exercised by the snapshot redaction.
	cfg.Audit.Webhook.SigningSecret = "seed-hmac-secret"
	cfg.ConfigAudit.Enabled = true
	cfg.ConfigAudit.Backend = "memory"
	cfg.ConfigAudit.Drift.Interval = time.Hour
	cfg.BreakGlass.Enabled = true
	cfg.BreakGlass.SweeperInterval = time.Hour
	return cfg
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

var governanceAdminPaths = []string{
	"/api/v1/admin/credentials",
	"/api/v1/admin/config/applied",
	"/api/v1/admin/break-glass",
}

func TestGovernance_WiredWhenEnabled(t *testing.T) {
	t.Parallel()
	a, err := buildApp(governanceEnabledConfig(), quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	// Lifecycle handles present — the actual cmd wiring, independent of routing.
	if a.credentialSchedCancel == nil || a.credentialSchedDone == nil {
		t.Error("credential rotation scheduler not started with rotation.enabled")
	}
	if a.configAuditStore == nil {
		t.Error("config audit store not built with config_audit.enabled")
	}
	if a.configDriftCancel == nil || a.configDriftDone == nil {
		t.Error("config drift loop not started with drift.interval > 0")
	}
	if a.breakGlassCancel == nil || a.breakGlassDone == nil {
		t.Error("break-glass sweeper not started with break_glass.enabled")
	}

	// Routes reachable (the Options reached the Server): a mounted admin route
	// serves a non-404; the raw Server handler applies no bearer gate here.
	ts := httptest.NewServer(a.server.Handler())
	defer ts.Close()
	for _, p := range governanceAdminPaths {
		if code := getStatus(t, ts.URL+p); code == http.StatusNotFound {
			t.Errorf("GET %s = 404; route not mounted despite feature enabled", p)
		}
	}
}

func TestGovernance_NotWiredWhenDisabled(t *testing.T) {
	t.Parallel()
	a, err := buildApp(&config.Config{}, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	if a.credentialSchedCancel != nil || a.credentialSchedDone != nil {
		t.Error("credential scheduler started with rotation disabled")
	}
	if a.configAuditStore != nil {
		t.Error("config audit store built with config_audit disabled")
	}
	if a.configDriftCancel != nil || a.configDriftDone != nil {
		t.Error("config drift loop started with config_audit disabled")
	}
	if a.breakGlassCancel != nil || a.breakGlassDone != nil {
		t.Error("break-glass sweeper started with break_glass disabled")
	}

	ts := httptest.NewServer(a.server.Handler())
	defer ts.Close()
	for _, p := range governanceAdminPaths {
		if code := getStatus(t, ts.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d; want 404 (unmounted) when feature disabled", p, code)
		}
	}
}

// TestGovernance_ConfigAuditWithoutDriftLeavesLoopOff proves the snapshot/history
// endpoints wire even without the opt-in drift loop, and that the drift loop
// stays off (no background goroutine) when drift.interval is 0.
func TestGovernance_ConfigAuditWithoutDriftLeavesLoopOff(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.ConfigAudit.Enabled = true
	cfg.ConfigAudit.Backend = "memory"
	// Drift.Interval left 0.
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	if a.configAuditStore == nil {
		t.Error("config audit store must build even without drift")
	}
	if a.configDriftCancel != nil {
		t.Error("drift loop must stay off when drift.interval == 0")
	}
	ts := httptest.NewServer(a.server.Handler())
	defer ts.Close()
	if code := getStatus(t, ts.URL+"/api/v1/admin/config/applied"); code == http.StatusNotFound {
		t.Error("config/applied must be mounted with config_audit enabled")
	}
}
