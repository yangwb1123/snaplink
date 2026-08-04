package main

// feature_gate_reload_wiring_test.go covers wireFeatureGateReload —
// mirroring main_shutdown_test.go's TestWaitLoop_HUPTriggersReloadThenResumesWaiting,
// which proves the analogous wireRateLimitReload-style path for
// logging.level. This proves the FULL chain a real SIGHUP drives: a
// reloader.Reload call reaches the already-built *sso.Server's live
// admin_api gate — not just the Reloader's own internal bookkeeping.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	configreload "github.com/yangwb1123/snaplink/config/reload"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestWireFeatureGateReload_SIGHUPFlipsAdminAPILive(t *testing.T) {
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithFeatureGates(sso.FeatureGates{AdminAPI: sso.Bool(true)}),
	)
	h := srv.Handler()

	initial := &config.Config{FeatureGates: config.FeatureGatesConfig{AdminAPI: fgBoolPtr(true)}}
	next := &config.Config{FeatureGates: config.FeatureGatesConfig{AdminAPI: fgBoolPtr(false)}}
	reloader := configreload.New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	wireFeatureGateReload(reloader, srv)

	getStatus := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/endpoints", nil))
		return rec.Code
	}
	if got := getStatus(); got == http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/endpoints before reload = 404, want reachable")
	}

	res, err := reloader.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 1 {
		t.Fatalf("Applied = %v, want exactly one admin_api entry", res.Applied)
	}
	if len(res.Ignored) != 0 {
		t.Errorf("Ignored = %v, want none", res.Ignored)
	}

	if got := getStatus(); got != http.StatusNotFound {
		t.Errorf("GET /api/v1/admin/endpoints after SIGHUP-driven reload = %d, want 404 (gate flipped live, no restart)", got)
	}
}

// TestWireFeatureGateReload_WebSPAIgnoredWhenNoFSWired proves the wiring
// surfaces the documented asymmetry end-to-end too: a real binary that
// never wired an admin console / hosted login / portal filesystem gets
// Result.Ignored for a branding change, not a false Applied.
func TestWireFeatureGateReload_WebSPAIgnoredWhenNoFSWired(t *testing.T) {
	srv := sso.NewServer(sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()))
	_ = srv.Handler()

	initial := &config.Config{FeatureGates: config.FeatureGatesConfig{Branding: fgBoolPtr(true)}}
	next := &config.Config{FeatureGates: config.FeatureGatesConfig{Branding: fgBoolPtr(false)}}
	reloader := configreload.New(initial, func(context.Context) (*config.Config, error) { return next, nil }, nil)
	wireFeatureGateReload(reloader, srv)

	res, err := reloader.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want none (no SPA filesystem wired at boot)", res.Applied)
	}
	found := false
	for _, p := range res.Ignored {
		if p == "/feature_gates/branding" {
			found = true
		}
	}
	if !found {
		t.Errorf("Ignored = %v, want it to contain /feature_gates/branding", res.Ignored)
	}
}

func fgBoolPtr(b bool) *bool { return &b }
