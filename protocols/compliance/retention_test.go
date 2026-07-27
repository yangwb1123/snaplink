package compliance_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestRetentionSweeper_DisabledIsNoOp(t *testing.T) {
	t.Parallel()
	sweeper := &compliance.RetentionSweeper{}
	rep, err := sweeper.Sweep(context.Background(), compliance.RetentionConfig{})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.SessionsDestroyed != 0 || rep.DormantAccountsErased != 0 || len(rep.Skipped) != 0 {
		t.Fatalf("expected a zero report when disabled, got %+v", rep)
	}
}

func TestRetentionSweeper_SessionTTLSweep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Minute)
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// "Now" is injected far past the 1-minute TTL, without any real sleep.
	fakeNow := time.Now().Add(2 * time.Hour)
	sweeper := &compliance.RetentionSweeper{Sessions: sessions, Now: func() time.Time { return fakeNow }}

	rep, err := sweeper.Sweep(ctx, compliance.RetentionConfig{Enabled: true, SessionTTLSweep: true})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.SessionsExpiredFound != 1 || rep.SessionsDestroyed != 1 {
		t.Fatalf("report = %+v, want 1 expired/destroyed", rep)
	}
	all, _ := sessions.ListAll(ctx)
	if len(all) != 0 {
		t.Fatalf("remaining sessions = %+v, want none (the only session had expired)", all)
	}
}

func TestRetentionSweeper_SessionTTLSweep_LeavesLiveSessionsAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(24 * time.Hour)
	live, err := sessions.Create(ctx, "u1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// "Now" is only 1 hour later — well within the 24-hour TTL.
	fakeNow := time.Now().Add(time.Hour)
	sweeper := &compliance.RetentionSweeper{Sessions: sessions, Now: func() time.Time { return fakeNow }}

	rep, err := sweeper.Sweep(ctx, compliance.RetentionConfig{Enabled: true, SessionTTLSweep: true})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.SessionsExpiredFound != 0 || rep.SessionsDestroyed != 0 {
		t.Fatalf("report = %+v, want no expired sessions found", rep)
	}
	all, _ := sessions.ListAll(ctx)
	if len(all) != 1 || all[0].ID != live.ID {
		t.Fatalf("remaining sessions = %+v, want the live session untouched", all)
	}
}

func TestRetentionSweeper_SessionTTLSweep_DryRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Minute)
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	fakeNow := time.Now().Add(2 * time.Hour)
	sweeper := &compliance.RetentionSweeper{Sessions: sessions, Now: func() time.Time { return fakeNow }}

	rep, err := sweeper.Sweep(ctx, compliance.RetentionConfig{Enabled: true, SessionTTLSweep: true, DryRun: true})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.SessionsExpiredFound != 1 || rep.SessionsDestroyed != 0 {
		t.Fatalf("report = %+v, want found=1 destroyed=0 under DryRun", rep)
	}
	all, _ := sessions.ListAll(ctx)
	if len(all) != 1 {
		t.Fatalf("DryRun must not destroy anything, got %d remaining", len(all))
	}
}

func TestRetentionSweeper_SessionTTLSweep_UnsupportedBackendIsSkipped(t *testing.T) {
	t.Parallel()
	sweeper := &compliance.RetentionSweeper{Sessions: unsupportedListAllSessionManager{}}
	rep, err := sweeper.Sweep(context.Background(), compliance.RetentionConfig{Enabled: true, SessionTTLSweep: true})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", rep.Errors)
	}
	found := false
	for _, s := range rep.Skipped {
		if strings.Contains(s, "sessions") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a sessions-related skip reason, got %v", rep.Skipped)
	}
}

// unsupportedListAllSessionManager is a minimal core.SessionManager whose
// ListAll refuses (core.ErrUnsupportedOperation), exercising the escape hatch
// documented on RetentionConfig.SessionTTLSweep / DormantAfter for backends
// too large to enumerate.
type unsupportedListAllSessionManager struct{}

func (unsupportedListAllSessionManager) Create(context.Context, string) (*core.Session, error) {
	return nil, core.ErrUnsupportedOperation
}
func (unsupportedListAllSessionManager) Get(context.Context, string) (*core.Session, error) {
	return nil, core.ErrUnsupportedOperation
}
func (unsupportedListAllSessionManager) Destroy(context.Context, string) error { return nil }
func (unsupportedListAllSessionManager) Refresh(context.Context, string) (*core.Session, error) {
	return nil, core.ErrUnsupportedOperation
}
func (unsupportedListAllSessionManager) ListByUser(context.Context, string) ([]*core.Session, error) {
	return nil, core.ErrUnsupportedOperation
}
func (unsupportedListAllSessionManager) ListAll(context.Context) ([]*core.Session, error) {
	return nil, core.ErrUnsupportedOperation
}

func TestRetentionSweeper_DormantAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager(24 * time.Hour)
	for _, id := range []string{"u_old", "u_recent", "u_none"} {
		if err := users.CreateOrUpdate(ctx, &core.User{ID: id}); err != nil {
			t.Fatalf("create user %s: %v", id, err)
		}
	}
	if _, err := sessions.Create(ctx, "u_old"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := sessions.Create(ctx, "u_recent"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	now := time.Now()

	sweeper := &compliance.RetentionSweeper{Users: users, Sessions: sessions, Now: func() time.Time { return now }}
	rep, err := sweeper.Sweep(ctx, compliance.RetentionConfig{Enabled: true, DormantAfter: time.Second})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	flagged := map[string]bool{}
	for _, id := range rep.DormantAccountsFlagged {
		flagged[id] = true
	}
	if !flagged["u_old"] {
		t.Errorf("expected u_old flagged, got %v", rep.DormantAccountsFlagged)
	}
	if flagged["u_recent"] {
		t.Errorf("u_recent should not be flagged, got %v", rep.DormantAccountsFlagged)
	}
	if flagged["u_none"] {
		t.Errorf("u_none (no session history) should not be flagged, got %v", rep.DormantAccountsFlagged)
	}
	if rep.DormantAccountsErased != 0 {
		t.Errorf("AutoEraseDormant was not set; expected 0 erasures, got %d", rep.DormantAccountsErased)
	}
}

func TestRetentionSweeper_AutoEraseDormant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager(24 * time.Hour)
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u_old"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := sessions.Create(ctx, "u_old"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	fakeNow := time.Now().Add(2 * time.Hour)

	eraser := &compliance.Eraser{Users: users}
	sweeper := &compliance.RetentionSweeper{Users: users, Sessions: sessions, Eraser: eraser, Now: func() time.Time { return fakeNow }}
	rep, err := sweeper.Sweep(ctx, compliance.RetentionConfig{Enabled: true, DormantAfter: time.Hour, AutoEraseDormant: true})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.DormantAccountsErased != 1 {
		t.Fatalf("DormantAccountsErased = %d, want 1", rep.DormantAccountsErased)
	}
	if _, err := users.GetByID(ctx, "u_old"); err == nil {
		t.Error("expected u_old to have been erased")
	}
}

func TestRetentionSweeper_AuditRetentionReport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sink := audit.NewMemorySink(0)
	rec := audit.New(sink, audit.WithClock(func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }))
	rec.Record(ctx, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess})
	rec2 := audit.New(sink, audit.WithClock(func() time.Time { return time.Now() }))
	rec2.Record(ctx, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess})

	sweeper := &compliance.RetentionSweeper{Auditor: rec}
	rep, err := sweeper.Sweep(ctx, compliance.RetentionConfig{Enabled: true, AuditReportMaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.AuditEventsPastRetention != 1 {
		t.Fatalf("AuditEventsPastRetention = %d, want 1 (only the 2020 event)", rep.AuditEventsPastRetention)
	}
}

func TestHandleAdminTriggerRetentionSweep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Minute)
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	fakeNow := time.Now().Add(2 * time.Hour)
	sweeper := &compliance.RetentionSweeper{Sessions: sessions, Now: func() time.Time { return fakeNow }}
	cfg := compliance.RetentionConfig{Enabled: true, SessionTTLSweep: true}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/compliance/retention-sweep", nil)
	hctx := core.NewContext(rec, req)
	compliance.HandleAdminTriggerRetentionSweep(sweeper, cfg, spi.NopLogger{}, hctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHandleAdminTriggerRetentionSweep_DryRunOverrideIsOneWay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sessions := defaultimpl.NewMemorySessionManager(time.Minute)
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	fakeNow := time.Now().Add(2 * time.Hour)
	sweeper := &compliance.RetentionSweeper{Sessions: sessions, Now: func() time.Time { return fakeNow }}
	// Standing config has DryRun already true; the request does NOT set it —
	// the sweep must still run as a dry run (the override can only add
	// DryRun, never remove it).
	cfg := compliance.RetentionConfig{Enabled: true, SessionTTLSweep: true, DryRun: true}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/compliance/retention-sweep", strings.NewReader(`{"dry_run":false}`))
	hctx := core.NewContext(rec, req)
	compliance.HandleAdminTriggerRetentionSweep(sweeper, cfg, spi.NopLogger{}, hctx)

	all, _ := sessions.ListAll(ctx)
	if len(all) != 1 {
		t.Fatalf("expected DryRun to still apply; session count = %d", len(all))
	}
}
