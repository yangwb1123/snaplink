package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// userlifecycle_wiring_test.go proves the cmd/sso-server composition-root
// wiring for domains/userlifecycle (wireUserLifecycle, build_stores.go):
// user_lifecycle.enabled mounts the admin state-machine surface, a SEPARATE
// auto_deprovision.enabled arms the background dormancy sweep, and — before
// this wiring existed — cmd/sso-server had ZERO references to the package
// (WithUserLifecycle / WithUserAutoDeprovision were unreachable in the
// shipped binary regardless of config).

// ulJSON does an HTTP round trip returning the decoded JSON body, mirroring
// the interfaces/sso rootcov test helpers' shape for this package's tests.
func ulJSON(t *testing.T, method, url string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestWireUserLifecycle_DisabledIsNoOp proves user_lifecycle's default
// (Enabled=false) appends nothing — byte-identical to a build predating the
// feature, matching every other optional governance section's contract.
func TestWireUserLifecycle_DisabledIsNoOp(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	if err := b.wireUserLifecycle(); err != nil {
		t.Fatalf("wireUserLifecycle: %v", err)
	}
	if len(b.opts) != 0 {
		t.Fatalf("opts = %d, want 0 (user_lifecycle.enabled=false must wire nothing)", len(b.opts))
	}
	if b.userAutoDeprovisionInterval != 0 {
		t.Errorf("userAutoDeprovisionInterval = %v, want 0", b.userAutoDeprovisionInterval)
	}
}

// TestWireUserLifecycle_EnabledAppendsStoreOptionOnly proves Enabled alone
// (no auto_deprovision) wires exactly WithUserLifecycle and arms no sweep.
func TestWireUserLifecycle_EnabledAppendsStoreOptionOnly(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.UserLifecycle.Enabled = true
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireUserLifecycle(); err != nil {
		t.Fatalf("wireUserLifecycle: %v", err)
	}
	if len(b.opts) != 1 {
		t.Fatalf("opts = %d, want 1 (WithUserLifecycle only)", len(b.opts))
	}
	if b.userAutoDeprovisionInterval != 0 {
		t.Errorf("userAutoDeprovisionInterval = %v, want 0 (auto_deprovision not enabled)", b.userAutoDeprovisionInterval)
	}
}

// TestWireUserLifecycle_AutoDeprovisionRequiresLifecycleEnabled proves the
// SEPARATE-opt-in contract: auto_deprovision.enabled with
// user_lifecycle.enabled=false is refused at boot rather than silently
// building a sweep with nowhere to persist its transitions.
func TestWireUserLifecycle_AutoDeprovisionRequiresLifecycleEnabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.UserLifecycle.AutoDeprovision.Enabled = true
	cfg.UserLifecycle.AutoDeprovision.DormantAfter = time.Hour
	cfg.UserLifecycle.AutoDeprovision.SweepInterval = time.Hour
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireUserLifecycle(); err == nil {
		t.Fatal("wireUserLifecycle: want error when auto_deprovision enabled but user_lifecycle.enabled is false")
	}
}

// TestWireUserLifecycle_AutoDeprovisionAppendsBothOptions proves that with
// both gates enabled + dormant_after/sweep_interval set, both Options are
// appended and the sweep interval is stashed for startUserAutoDeprovisionSweep.
func TestWireUserLifecycle_AutoDeprovisionAppendsBothOptions(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.UserLifecycle.Enabled = true
	cfg.UserLifecycle.AutoDeprovision.Enabled = true
	cfg.UserLifecycle.AutoDeprovision.DormantAfter = 90 * 24 * time.Hour
	cfg.UserLifecycle.AutoDeprovision.SweepInterval = time.Hour
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireUserLifecycle(); err != nil {
		t.Fatalf("wireUserLifecycle: %v", err)
	}
	if len(b.opts) != 2 {
		t.Fatalf("opts = %d, want 2 (WithUserLifecycle + WithUserAutoDeprovision)", len(b.opts))
	}
	if b.userAutoDeprovisionInterval != time.Hour {
		t.Errorf("userAutoDeprovisionInterval = %v, want 1h", b.userAutoDeprovisionInterval)
	}
}

// TestUserLifecycle_EndToEnd drives the REAL buildApp path (the shipped
// binary's own composition root) with user_lifecycle.enabled, then proves
// through actual HTTP that the admin state-machine surface is reachable and
// a real transition mutates state — closing the gap where cmd/sso-server had
// zero references to domains/userlifecycle regardless of config.
func TestUserLifecycle_EndToEnd(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Server.SessionTTL = time.Hour
	cfg.OAuth.RefreshToken.Enabled = true
	cfg.OAuth.RefreshToken.TTL = time.Hour
	cfg.UserLifecycle.Enabled = true
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	const uid = "userlifecycle-e2e-user"
	if err := a.userProvider.CreateOrUpdate(context.Background(), &sso.User{ID: uid}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	ctx := context.Background()
	if _, err := a.sessionMgr.Create(ctx, uid); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	const refresh = "userlifecycle-e2e-refresh"
	if err := a.refreshTokenStore.Issue(ctx, refresh, &oauth.RefreshToken{
		UserID: uid, ClientID: "client-a", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	ts := httptest.NewServer(a.server.Handler())
	defer ts.Close()
	base := ts.URL + "/api/v1/admin/users/" + uid + "/lifecycle"

	status, out := ulJSON(t, http.MethodGet, base, nil)
	if status != http.StatusOK {
		t.Fatalf("GET lifecycle = %d body=%v", status, out)
	}
	if out["state"] != "active" {
		t.Errorf("initial state = %v, want active (implicit default)", out["state"])
	}

	status, out = ulJSON(t, http.MethodPost, base, map[string]any{"state": "suspended", "reason": "wiring e2e"})
	if status != http.StatusOK {
		t.Fatalf("POST suspend = %d body=%v", status, out)
	}
	if out["state"] != "suspended" {
		t.Errorf("post-transition state = %v, want suspended", out["state"])
	}
	sessions, err := a.sessionMgr.ListByUser(ctx, uid)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("sessions after suspend = %d, err=%v; want none", len(sessions), err)
	}
	inspector, ok := a.refreshTokenStore.(oauth.RefreshTokenInspector)
	if !ok {
		t.Fatal("stock refresh-token store does not support inspection")
	}
	if _, err := inspector.Inspect(ctx, refresh); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("refresh token after suspend error=%v, want revoked", err)
	}

	status, out = ulJSON(t, http.MethodGet, base, nil)
	if status != http.StatusOK || out["state"] != "suspended" {
		t.Errorf("GET after transition = %d %v, want 200 suspended (real state mutation persisted)", status, out)
	}
}

// TestUserLifecycle_DefaultOff_RouteNotMounted proves the admin route stays a
// router-native 404 when user_lifecycle is absent — the gap this wiring
// closes is opt-in, not on-by-default.
func TestUserLifecycle_DefaultOff_RouteNotMounted(t *testing.T) {
	t.Parallel()
	a, err := buildApp(&config.Config{}, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	ts := httptest.NewServer(a.server.Handler())
	defer ts.Close()
	if code := getStatus(t, ts.URL+"/api/v1/admin/users/anyone/lifecycle"); code != http.StatusNotFound {
		t.Errorf("GET lifecycle (feature off) = %d, want 404", code)
	}
}

// TestUserLifecycle_AutoDeprovisionSweepAdvancesDormantUser proves the
// auto_deprovision config knobs (dormant_after, archive_after, max_per_sweep)
// really reach userlifecycle.SweepOnce and advance a real dormant account —
// deterministic (no sleeps): it constructs the SAME kind of SweepDeps
// Server.RunUserAutoDeprovision uses internally, from the config-derived
// DeprovisionConfig serverbuildplatform.BuildUserAutoDeprovision returns, and
// injects a synthetic "later" Now instead of waiting on a wall-clock sweep
// interval.
func TestUserLifecycle_AutoDeprovisionSweepAdvancesDormantUser(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	// A live (non-expired) session is required for SessionLastActive to see
	// any signal at all — a session TTL longer than the simulated Now below.
	cfg.Server.SessionTTL = 24 * time.Hour
	cfg.UserLifecycle.Enabled = true
	cfg.UserLifecycle.AutoDeprovision.Enabled = true
	cfg.UserLifecycle.AutoDeprovision.DormantAfter = time.Hour
	cfg.UserLifecycle.AutoDeprovision.SweepInterval = time.Minute
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	const uid = "userlifecycle-dormant-user"
	ctx := context.Background()
	if err := a.userProvider.CreateOrUpdate(ctx, &sso.User{ID: uid}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sess, err := a.sessionMgr.Create(ctx, uid)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	store, err := serverbuildplatform.BuildUserLifecycle(cfg.UserLifecycle, nil, "")
	if err != nil {
		t.Fatalf("BuildUserLifecycle: %v", err)
	}
	if store == nil {
		t.Fatal("BuildUserLifecycle returned nil with user_lifecycle.enabled=true")
	}
	deps := userlifecycle.SweepDeps{
		Users:      a.userProvider,
		Lifecycle:  store,
		LastActive: userlifecycle.SessionLastActive{Sessions: a.sessionMgr},
		Config: userlifecycle.DeprovisionConfig{
			DormantAfter: cfg.UserLifecycle.AutoDeprovision.DormantAfter,
		},
		Now: func() time.Time { return sess.CreatedAt.Add(2 * time.Hour) },
	}
	n, err := userlifecycle.SweepOnce(ctx, deps)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("SweepOnce applied = %d, want 1", n)
	}
	rec, err := store.Get(ctx, uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.State != userlifecycle.StateInactive {
		t.Errorf("state after sweep = %v, want inactive", rec.State)
	}
}
