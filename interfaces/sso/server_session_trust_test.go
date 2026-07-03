package sso_test

// Drives the zero-trust min-trust gate (Server.RequireSessionTrust) end-to-end:
// a below-threshold session gets an RFC 9470 step-up challenge; a fresh session
// and an agent-unflagged high-trust session proceed; and every fail-open path
// (feature off, session missing) proceeds rather than denying. Uses the REAL
// MemorySessionManager (no mocks).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

func trustDecayCfg() sso.SessionTrustDecayConfig {
	return sso.SessionTrustDecayConfig{
		Interval:     5 * time.Minute,
		Factor:       0.95,
		Floor:        0.5,
		StepUpMaxAge: 300,
		InitialScore: 1.0,
	}
}

// newStaleSession seeds a session whose bound trust has decayed well below any
// sane threshold (baseline 2h in the past under a 5min/0.95 curve ≈ 0.29).
func newStaleSession(t *testing.T, mgr *defaultimpl.MemorySessionManager) string {
	t.Helper()
	s, err := mgr.CreateWithMeta(context.Background(), "u1", core.SessionMeta{
		TrustScore: 1.0, TrustSetAt: time.Now().Add(-2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return s.ID
}

func gateCtx() (*core.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/thing", nil)
	return core.NewContext(rec, req), rec
}

func TestRequireSessionTrust_ChallengesBelowThreshold(t *testing.T) {
	t.Parallel()
	mgr := defaultimpl.NewMemorySessionManager()
	srv := sso.NewServer(sso.WithSessionManager(mgr), sso.WithSessionTrustDecay(trustDecayCfg()))
	sessID := newStaleSession(t, mgr)

	ctx, rec := gateCtx()
	if !srv.RequireSessionTrust(ctx, sessID, 0.6) {
		t.Fatalf("expected challenge (true) for below-threshold session")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); !strings.Contains(wa, "insufficient_user_authentication") {
		t.Fatalf("WWW-Authenticate = %q, want an RFC 9470 step-up challenge", wa)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store on a credential challenge", cc)
	}
}

func TestRequireSessionTrust_AgentFlagChallenges(t *testing.T) {
	t.Parallel()
	mgr := defaultimpl.NewMemorySessionManager()
	srv := sso.NewServer(sso.WithSessionManager(mgr), sso.WithSessionTrustDecay(trustDecayCfg()))
	// Fresh, high-trust session — but the agent already flagged it.
	s, err := mgr.CreateWithMeta(context.Background(), "u1", core.SessionMeta{TrustScore: 1.0, TrustSetAt: time.Now()})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := mgr.MarkStepUp(context.Background(), s.ID); err != nil {
		t.Fatalf("mark: %v", err)
	}
	ctx, _ := gateCtx()
	if !srv.RequireSessionTrust(ctx, s.ID, 0.6) {
		t.Fatalf("agent-flagged session must be challenged even at full score")
	}
}

func TestRequireSessionTrust_ProceedsForFreshSession(t *testing.T) {
	t.Parallel()
	mgr := defaultimpl.NewMemorySessionManager()
	srv := sso.NewServer(sso.WithSessionManager(mgr), sso.WithSessionTrustDecay(trustDecayCfg()))
	s, err := mgr.CreateWithMeta(context.Background(), "u1", core.SessionMeta{TrustScore: 1.0, TrustSetAt: time.Now()})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	ctx, rec := gateCtx()
	if srv.RequireSessionTrust(ctx, s.ID, 0.6) {
		t.Fatalf("fresh full-trust session must proceed (no challenge)")
	}
	if rec.Code != http.StatusOK { // nothing written ⇒ recorder default 200
		t.Fatalf("recorder was written to (code %d); gate should be a no-op on proceed", rec.Code)
	}
}

func TestRequireSessionTrust_FailOpen(t *testing.T) {
	t.Parallel()
	mgr := defaultimpl.NewMemorySessionManager()

	// Feature OFF: gate proceeds regardless of session state (byte-identical).
	off := sso.NewServer(sso.WithSessionManager(mgr))
	sessID := newStaleSession(t, mgr)
	ctx, _ := gateCtx()
	if off.RequireSessionTrust(ctx, sessID, 0.6) {
		t.Fatalf("gate must be inert when WithSessionTrustDecay is unwired")
	}

	// Feature ON but session missing: fail-open (proceed), never deny.
	on := sso.NewServer(sso.WithSessionManager(mgr), sso.WithSessionTrustDecay(trustDecayCfg()))
	ctx2, _ := gateCtx()
	if on.RequireSessionTrust(ctx2, "does-not-exist", 0.6) {
		t.Fatalf("missing session must fail-open (proceed), not challenge")
	}

	// minTrust<=0 disables the gate for this operation.
	ctx3, _ := gateCtx()
	if on.RequireSessionTrust(ctx3, sessID, 0) {
		t.Fatalf("minTrust<=0 must proceed")
	}
}

func TestSessionTrustDecay_DefaultOffNoStamp(t *testing.T) {
	t.Parallel()
	// A session created without the feature carries no trust baseline — the
	// additive fields stay at their zero value (byte-identical to legacy rows).
	mgr := defaultimpl.NewMemorySessionManager()
	sso.NewServer(sso.WithSessionManager(mgr)) // no WithSessionTrustDecay
	s, err := mgr.Create(context.Background(), "u1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s.TrustScore != 0 || !s.TrustSetAt.IsZero() || s.StepUpRequired {
		t.Fatalf("default-off session carried trust state: score=%v setAt=%v flag=%v",
			s.TrustScore, s.TrustSetAt, s.StepUpRequired)
	}
}

func TestStartContinuousVerification_InertWhenOff(t *testing.T) {
	t.Parallel()
	// No feature wired ⇒ Start returns an already-closed channel (nothing runs).
	srv := sso.NewServer(sso.WithSessionManager(defaultimpl.NewMemorySessionManager()))
	done := srv.StartContinuousVerification(context.Background())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("StartContinuousVerification must be inert when the feature is off")
	}
}
