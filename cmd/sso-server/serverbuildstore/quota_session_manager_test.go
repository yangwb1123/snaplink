package serverbuildstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestQuotaSessionManagerDestroyReleasesOnce(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager()
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	wrapped := wrapQuotaSessionsForTest(t, raw, quotas)
	if err := quotas.IncrementUsage(t.Context(), "acme", core.ResourceSessions, 1); err != nil {
		t.Fatal(err)
	}
	session, err := raw.CreateWithMeta(t.Context(), "alice", core.SessionMeta{TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Destroy(t.Context(), session.ID); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Destroy(t.Context(), session.ID); err != nil {
		t.Fatal(err)
	}
	assertSessionUsage(t, quotas, "acme", 0)
}

func TestQuotaSessionManagerReconcilesExpiredGauge(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager(-time.Second)
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := quotas.SetQuota(t.Context(), "acme", &core.TenantQuota{MaxSessions: 1}); err != nil {
		t.Fatal(err)
	}
	if err := quotas.IncrementUsage(t.Context(), "acme", core.ResourceSessions, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.CreateWithMeta(t.Context(), "expired", core.SessionMeta{TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	wrapped := wrapQuotaSessionsForTest(t, raw, quotas)
	assertSessionUsage(t, quotas, "acme", 0)
	reconciler := wrapped.(core.TenantSessionQuotaReconciler)
	if err := reconciler.ReconcileTenantSessionQuota(t.Context(), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := quotas.IncrementUsage(t.Context(), "acme", core.ResourceSessions, 1); err != nil {
		t.Fatalf("fresh admission after expiry: %v", err)
	}
}

func TestQuotaSessionManagerDeleteTenantSkipsBreakGlassQuota(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager()
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	for range 2 {
		if err := quotas.IncrementUsage(t.Context(), "acme", core.ResourceSessions, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.CreateWithMeta(t.Context(), "member", core.SessionMeta{TenantID: "acme"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.CreateWithMeta(t.Context(), "support", core.SessionMeta{
		TenantID: "acme", Kind: core.SessionKindAdminImpersonation,
	}); err != nil {
		t.Fatal(err)
	}
	wrapped := wrapQuotaSessionsForTest(t, raw, quotas)
	index := wrapped.(core.SessionTenantIndex)
	deleted, err := index.DeleteByTenant(t.Context(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 {
		t.Fatalf("deleted = %d, want 3", deleted)
	}
	assertSessionUsage(t, quotas, "acme", 0)
}

func TestQuotaSessionManagerKeepsRealLimit(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager()
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := quotas.SetQuota(t.Context(), "acme", &core.TenantQuota{MaxSessions: 1}); err != nil {
		t.Fatal(err)
	}
	if err := quotas.IncrementUsage(t.Context(), "acme", core.ResourceSessions, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.CreateWithMeta(t.Context(), "alice", core.SessionMeta{TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	wrapped := wrapQuotaSessionsForTest(t, raw, quotas)
	reconciler := wrapped.(core.TenantSessionQuotaReconciler)
	if err := reconciler.ReconcileTenantSessionQuota(t.Context(), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := quotas.IncrementUsage(t.Context(), "acme", core.ResourceSessions, 1); !errors.Is(err, core.ErrQuotaExceeded) {
		t.Fatalf("second admission = %v, want quota exceeded", err)
	}
}

func TestQuotaSessionManagerOwnsAdmissionAndLifecycle(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager()
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := quotas.SetQuota(t.Context(), "acme", &core.TenantQuota{MaxSessions: 1}); err != nil {
		t.Fatal(err)
	}
	wrapped := wrapQuotaSessionsForTest(t, raw, quotas)
	creator := wrapped.(core.SessionMetaCreator)
	first, err := creator.CreateWithMeta(t.Context(), "alice", core.SessionMeta{TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Kind == core.SessionKindQuotaPending {
		t.Fatal("admitted session remained quota_pending")
	}
	if _, err := creator.CreateWithMeta(t.Context(), "bob", core.SessionMeta{TenantID: "acme"}); !errors.Is(err, core.ErrQuotaExceeded) {
		t.Fatalf("second create = %v, want quota exceeded", err)
	}
	assertSessionUsage(t, quotas, "acme", 1)
	if err := wrapped.Destroy(t.Context(), first.ID); err != nil {
		t.Fatal(err)
	}
	assertSessionUsage(t, quotas, "acme", 0)
}

func TestQuotaSessionManagerConcurrentAdmissionNeverExceedsLimit(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager()
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := quotas.SetQuota(t.Context(), "acme", &core.TenantQuota{MaxSessions: 3}); err != nil {
		t.Fatal(err)
	}
	creator := wrapQuotaSessionsForTest(t, raw, quotas).(core.SessionMetaCreator)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := creator.CreateWithMeta(t.Context(), string(rune('a'+i)), core.SessionMeta{TenantID: "acme"})
			if err == nil {
				admitted.Add(1)
				return
			}
			if !errors.Is(err, core.ErrQuotaExceeded) {
				t.Errorf("concurrent create: %v", err)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 3 {
		t.Fatalf("admitted = %d, want 3", admitted.Load())
	}
	assertSessionUsage(t, quotas, "acme", 3)
}

func TestQuotaSessionManagerHidesAndRecoversPendingSession(t *testing.T) {
	raw := memorystoreidentity.NewMemorySessionManager()
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	pending, err := raw.CreateWithMeta(t.Context(), "alice", core.SessionMeta{
		TenantID: "acme", Kind: core.SessionKindQuotaPending,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := quotas.ReserveResource(t.Context(), "acme", core.ResourceSessions, pending.ID); err != nil {
		t.Fatal(err)
	}
	aged := &agedQuotaSessionManager{
		MemorySessionManager: raw,
		createdAt:            map[string]time.Time{pending.ID: time.Now().Add(-sessionQuotaPendingGrace - time.Second)},
	}
	wrapped := wrapQuotaSessionsForTest(t, aged, quotas)
	if _, err := wrapped.Get(t.Context(), pending.ID); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("recovered pending Get = %v, want not found", err)
	}
	all, err := wrapped.ListAll(t.Context())
	if err != nil || len(all) != 0 {
		t.Fatalf("published sessions = %v err=%v, want empty", all, err)
	}
	assertSessionUsage(t, quotas, "acme", 0)
}

func wrapQuotaSessionsForTest(
	t *testing.T,
	raw core.SessionManager,
	quotas *memorystoreidentity.MemoryTenantQuotaStore,
) core.SessionManager {
	t.Helper()
	wrapped, err := WrapSessionManagerWithTenantQuota(t.Context(), raw, quotas, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

type agedQuotaSessionManager struct {
	*memorystoreidentity.MemorySessionManager
	createdAt map[string]time.Time
}

func (m *agedQuotaSessionManager) Get(ctx context.Context, id string) (*core.Session, error) {
	session, err := m.MemorySessionManager.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if createdAt, ok := m.createdAt[id]; ok {
		session.CreatedAt = createdAt
	}
	return session, nil
}

func assertSessionUsage(t *testing.T, quotas core.TenantQuotaStore, tenantID string, want int) {
	t.Helper()
	usage, err := quotas.GetUsage(t.Context(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.Sessions != want {
		t.Fatalf("session usage = %d, want %d", usage.Sessions, want)
	}
}
