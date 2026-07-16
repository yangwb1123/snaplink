package memorystoreidentity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func TestMemorySessionManager_CreateGet(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	s, err := m.Create(context.Background(), "u-alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == "" || s.UserID != "u-alice" {
		t.Errorf("session = %+v", s)
	}
	if s.IsExpired() {
		t.Error("fresh session should not be expired")
	}

	got, err := m.Get(context.Background(), s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != s.ID {
		t.Errorf("Get returned %+v", got)
	}
}

func TestMemorySessionManager_DefaultTTL(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager()
	if m.ttl != core.DefaultSessionDuration {
		t.Errorf("ttl = %v, want default %v", m.ttl, core.DefaultSessionDuration)
	}
}

func TestMemorySessionManager_OverrideTTL(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(7 * time.Minute)
	if m.ttl != 7*time.Minute {
		t.Errorf("ttl = %v, want override", m.ttl)
	}
}

func TestMemorySessionManager_GetMissingReturnsSentinel(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	if _, err := m.Get(context.Background(), "missing"); !errors.Is(err, core.ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionManager_Destroy(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	s, _ := m.Create(context.Background(), "u")
	if err := m.Destroy(context.Background(), s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := m.Get(context.Background(), s.ID); !errors.Is(err, core.ErrSessionNotFound) {
		t.Errorf("after destroy: err = %v", err)
	}
	// Destroying an unknown ID is a no-op (idempotent).
	if err := m.Destroy(context.Background(), "missing"); err != nil {
		t.Errorf("Destroy(missing): %v", err)
	}
}

func TestMemorySessionManager_RefreshBumpsExpiry(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Second)
	s, _ := m.Create(context.Background(), "u")
	old := s.ExpiresAt
	time.Sleep(2 * time.Millisecond)
	refreshed, err := m.Refresh(context.Background(), s.ID)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !refreshed.ExpiresAt.After(old) {
		t.Errorf("ExpiresAt = %v, want > %v", refreshed.ExpiresAt, old)
	}
}

func TestMemorySessionManager_RefreshMissing(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	if _, err := m.Refresh(context.Background(), "missing"); !errors.Is(err, core.ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}

// TestMemorySessionManager_RefreshRefusesExpired pins the security
// invariant — a captured session id past its expiry MUST NOT be
// resurrectable by calling Refresh. Pre-fix this test failed: the
// old Refresh just bumped ExpiresAt without checking IsExpired.
func TestMemorySessionManager_RefreshRefusesExpired(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(10 * time.Millisecond)
	s, _ := m.Create(context.Background(), "alice")
	time.Sleep(20 * time.Millisecond) // session past ExpiresAt
	if _, err := m.Refresh(context.Background(), s.ID); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("expired Refresh: got %v, want ErrSessionNotFound", err)
	}
}

// TestMemorySessionManager_RefreshRefusesRevoked covers the
// admin-revocation case — operator revokes a session, attacker
// captures the id, tries to extend. MUST fail.
func TestMemorySessionManager_RefreshRefusesRevoked(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	s, _ := m.Create(context.Background(), "alice")
	// Mark revoked directly via the underlying map (admin
	// revocation path; SDK exposes Destroy + revoke methods that
	// vary by store, but the Revoked field on the struct is the
	// canonical signal).
	stored, _ := m.Get(context.Background(), s.ID)
	stored.Revoked = true
	if _, err := m.Refresh(context.Background(), s.ID); !errors.Is(err, core.ErrSessionNotFound) {
		t.Fatalf("revoked Refresh: got %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionManager_ListByUser(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	_, _ = m.Create(context.Background(), "alice")
	_, _ = m.Create(context.Background(), "alice")
	_, _ = m.Create(context.Background(), "bob")

	alices, _ := m.ListByUser(context.Background(), "alice")
	if len(alices) != 2 {
		t.Errorf("alice sessions = %d, want 2", len(alices))
	}
	bobs, _ := m.ListByUser(context.Background(), "bob")
	if len(bobs) != 1 {
		t.Errorf("bob sessions = %d, want 1", len(bobs))
	}
	none, _ := m.ListByUser(context.Background(), "carol")
	if len(none) != 0 {
		t.Errorf("carol sessions = %d, want 0", len(none))
	}
}

func TestMemorySessionManager_ListAll(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	_, _ = m.Create(context.Background(), "alice")
	_, _ = m.Create(context.Background(), "bob")
	all, _ := m.ListAll(context.Background())
	if len(all) != 2 {
		t.Errorf("all sessions = %d, want 2", len(all))
	}
}

func TestMemorySessionManager_ConcurrentCreates(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, _ = m.Create(context.Background(), "u")
		}()
	}
	wg.Wait()
	got, _ := m.ListAll(context.Background())
	if len(got) != n {
		t.Errorf("got %d sessions, want %d", len(got), n)
	}
}

func TestMemorySessionManager_CreateWithMeta(t *testing.T) {
	t.Parallel()
	mgr := NewMemorySessionManager(time.Hour)
	ctx := context.Background()
	s, err := mgr.CreateWithMeta(ctx, "alice", core.SessionMeta{IP: "10.0.0.1", UserAgent: "UA/1"})
	if err != nil {
		t.Fatalf("CreateWithMeta: %v", err)
	}
	if s.IP != "10.0.0.1" || s.UserAgent != "UA/1" {
		t.Fatalf("created meta = %q / %q", s.IP, s.UserAgent)
	}
	got, _ := mgr.Get(ctx, s.ID)
	if got.IP != "10.0.0.1" || got.UserAgent != "UA/1" {
		t.Errorf("Get meta = %q / %q", got.IP, got.UserAgent)
	}
	plain, _ := mgr.Create(ctx, "bob")
	if plain.IP != "" || plain.UserAgent != "" {
		t.Errorf("plain Create meta should be empty, got %q / %q", plain.IP, plain.UserAgent)
	}
}

// TestMemorySessionManager_DeleteByTenant pins the bulk-revocation seam used on
// tenant suspension: only the target tenant's sessions are removed, sessions of
// other tenants (and untagged sessions) survive.
func TestMemorySessionManager_DeleteByTenant(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	ctx := context.Background()
	// Two sessions for tenant acme, one for globex, one untagged.
	_, _ = m.CreateWithMeta(ctx, "alice", core.SessionMeta{TenantID: "acme"})
	_, _ = m.CreateWithMeta(ctx, "bob", core.SessionMeta{TenantID: "acme"})
	keepTenant, _ := m.CreateWithMeta(ctx, "carol", core.SessionMeta{TenantID: "globex"})
	keepUntagged, _ := m.Create(ctx, "dave")

	n, err := m.DeleteByTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}
	// Other tenant + untagged sessions survive.
	if _, err := m.Get(ctx, keepTenant.ID); err != nil {
		t.Errorf("globex session destroyed: %v", err)
	}
	if _, err := m.Get(ctx, keepUntagged.ID); err != nil {
		t.Errorf("untagged session destroyed: %v", err)
	}
	all, _ := m.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("remaining sessions = %d, want 2", len(all))
	}
	// Idempotent re-run + empty tenant is a no-op (not a wildcard).
	if n, _ := m.DeleteByTenant(ctx, "acme"); n != 0 {
		t.Errorf("re-delete = %d, want 0", n)
	}
	if n, _ := m.DeleteByTenant(ctx, ""); n != 0 {
		t.Errorf("empty tenant deleted %d, want 0 (no wildcard)", n)
	}
	all, _ = m.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("empty-tenant delete must not wipe store, remaining = %d", len(all))
	}
}

// TestMemorySessionManager_TrustRoundTrip proves the trust-decay fields
// round-trip through CreateWithMeta and that MarkStepUp / SetTrust
// (core.SessionTrustManager) persist — parity with the sqlite peer.
func TestMemorySessionManager_TrustRoundTrip(t *testing.T) {
	t.Parallel()
	m := NewMemorySessionManager(time.Hour)
	ctx := context.Background()
	base := time.Now().Add(-30 * time.Minute)

	s, err := m.CreateWithMeta(ctx, "alice", core.SessionMeta{TrustScore: 0.8, TrustSetAt: base})
	if err != nil {
		t.Fatalf("CreateWithMeta: %v", err)
	}
	got, _ := m.Get(ctx, s.ID)
	if got.TrustScore != 0.8 || !got.TrustSetAt.Equal(base) || got.StepUpRequired {
		t.Fatalf("trust not round-tripped: %#v", got)
	}

	if err := m.MarkStepUp(ctx, s.ID); err != nil {
		t.Fatalf("MarkStepUp: %v", err)
	}
	if got, _ := m.Get(ctx, s.ID); !got.StepUpRequired {
		t.Fatalf("MarkStepUp did not persist")
	}

	newBase := time.Now()
	if err := m.SetTrust(ctx, s.ID, 0.5, newBase); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	got2, _ := m.Get(ctx, s.ID)
	if got2.TrustScore != 0.5 || !got2.TrustSetAt.Equal(newBase) || got2.StepUpRequired {
		t.Fatalf("SetTrust state wrong: %#v", got2)
	}

	// Missing rows are no-ops (not errors).
	if err := m.MarkStepUp(ctx, "nope"); err != nil {
		t.Errorf("MarkStepUp missing = %v, want nil", err)
	}
	if err := m.SetTrust(ctx, "nope", 0.9, newBase); err != nil {
		t.Errorf("SetTrust missing = %v, want nil", err)
	}
}

// TestMemorySessionManager_MaxEntriesRejectsAtCapacity proves the opt-in
// MaxEntries cap rejects a new session once the store is full, and that
// destroying a session frees up room again.
func TestMemorySessionManager_MaxEntriesRejectsAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemorySessionManager(time.Hour)
	m.MaxEntries = 2

	s1, err := m.Create(ctx, "u-1")
	if err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	if _, err := m.Create(ctx, "u-2"); err != nil {
		t.Fatalf("Create 2: %v", err)
	}
	if _, err := m.Create(ctx, "u-3"); !errors.Is(err, ErrStoreAtCapacity) {
		t.Fatalf("Create 3 (over capacity) = %v, want ErrStoreAtCapacity", err)
	}

	if err := m.Destroy(ctx, s1.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := m.Create(ctx, "u-4"); err != nil {
		t.Fatalf("Create after freeing a slot: %v", err)
	}
}

// TestMemorySessionManager_MaxEntriesZeroIsUnbounded proves the default
// (MaxEntries unset) never rejects a Create.
func TestMemorySessionManager_MaxEntriesZeroIsUnbounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemorySessionManager(time.Hour)
	for i := 0; i < 50; i++ {
		if _, err := m.Create(ctx, "u"); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}
}

// TestMemorySessionManager_ReaperSweepsExpiredSessions proves StartReaper
// removes an expired session that no Get/ListByUser call ever revisits, and
// that Close stops the sweep loop cleanly.
func TestMemorySessionManager_ReaperSweepsExpiredSessions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemorySessionManager(time.Millisecond) // sessions expire almost immediately
	defer func() { _ = m.Close() }()

	s, err := m.Create(ctx, "u-alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // let it expire

	m.StartReaper(5 * time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.RLock()
		_, present := m.sessions[s.ID]
		m.mu.RUnlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired session never swept from the map")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
