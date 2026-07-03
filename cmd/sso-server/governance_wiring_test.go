package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/interfaces/sso"
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
	// Wave-3 cmd wiring: the four already-merged SDK features, enabled via their
	// own config sections. Rotation.enabled (above) also mounts the compromise
	// route (WithCredentialCompromise reuses the rotation Scheduler).
	cfg.TokenPolicies.Policies = []tokenpolicy.Policy{{Name: "cap-access-ttl", MaxTTL: time.Hour}}
	cfg.AccessPolicies.Policies = []conditionalaccess.Policy{
		{Name: "deny-unmanaged", Enabled: true, Actions: conditionalaccess.Actions{Deny: true}},
	}
	cfg.Degradation.Enabled = true
	cfg.Degradation.InitialMode = "read_only"
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

// postStatus is the POST sibling of getStatus, needed for the credential
// compromise route (POST-only). The StdRouter returns 404 for BOTH an unknown
// path AND a method mismatch, so a mounted POST route MUST be probed with POST
// to distinguish "wired" (non-404) from "absent" (404).
func postStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Post(url, "application/json", http.NoBody)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

var governanceAdminPaths = []string{
	"/api/v1/admin/credentials",
	"/api/v1/admin/config/applied",
	"/api/v1/admin/break-glass",
	// Wave-3 GET admin governance views (token policy, conditional access, DR mode).
	"/api/v1/admin/token-policies",
	"/api/v1/admin/access-policies",
	"/api/v1/admin/dr/mode",
}

// governanceCompromisePath is the POST-only emergency compromise route; the
// :type segment is filled with the webhook-HMAC rotator that rotation seeds.
const governanceCompromisePath = "/api/v1/admin/credentials/webhook_hmac/compromise"

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
	// Degradation manager wired with the configured initial mode. It has no
	// lifecycle handle (no goroutine), so its wiring is proven by the retained
	// manager + its mode, then by the mounted route below.
	if a.degradationMgr == nil {
		t.Error("degradation manager not built with degradation.enabled")
	} else if got := a.degradationMgr.Mode(); got != sso.DegradationModeReadOnly {
		t.Errorf("degradation initial mode = %q; want %q", got, sso.DegradationModeReadOnly)
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
	// Credential compromise is POST-only; rotation.enabled mounts it via the
	// shared Scheduler (WithCredentialCompromise).
	if code := postStatus(t, ts.URL+governanceCompromisePath); code == http.StatusNotFound {
		t.Errorf("POST %s = 404; compromise route not mounted despite rotation enabled", governanceCompromisePath)
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
	if a.degradationMgr != nil {
		t.Error("degradation manager built with degradation disabled")
	}

	ts := httptest.NewServer(a.server.Handler())
	defer ts.Close()
	for _, p := range governanceAdminPaths {
		if code := getStatus(t, ts.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d; want 404 (unmounted) when feature disabled", p, code)
		}
	}
	// The compromise route stays unmounted (byte-identical) with rotation off.
	if code := postStatus(t, ts.URL+governanceCompromisePath); code != http.StatusNotFound {
		t.Errorf("POST %s = %d; want 404 (unmounted) when rotation disabled", governanceCompromisePath, code)
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
