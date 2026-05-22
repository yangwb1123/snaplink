package defaultimpl

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
)

func TestMemorySessionManager_CreateGet(t *testing.T) {
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
	m := NewMemorySessionManager()
	if m.ttl != sso.DefaultSessionDuration {
		t.Errorf("ttl = %v, want default %v", m.ttl, sso.DefaultSessionDuration)
	}
}

func TestMemorySessionManager_OverrideTTL(t *testing.T) {
	m := NewMemorySessionManager(7 * time.Minute)
	if m.ttl != 7*time.Minute {
		t.Errorf("ttl = %v, want override", m.ttl)
	}
}

func TestMemorySessionManager_GetMissingReturnsSentinel(t *testing.T) {
	m := NewMemorySessionManager(time.Hour)
	if _, err := m.Get(context.Background(), "missing"); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionManager_Destroy(t *testing.T) {
	m := NewMemorySessionManager(time.Hour)
	s, _ := m.Create(context.Background(), "u")
	if err := m.Destroy(context.Background(), s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := m.Get(context.Background(), s.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Errorf("after destroy: err = %v", err)
	}
	// Destroying an unknown ID is a no-op (idempotent).
	if err := m.Destroy(context.Background(), "missing"); err != nil {
		t.Errorf("Destroy(missing): %v", err)
	}
}

func TestMemorySessionManager_RefreshBumpsExpiry(t *testing.T) {
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
	m := NewMemorySessionManager(time.Hour)
	if _, err := m.Refresh(context.Background(), "missing"); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}

// TestMemorySessionManager_RefreshRefusesExpired pins the security
// invariant — a captured session id past its expiry MUST NOT be
// resurrectable by calling Refresh. Pre-fix this test failed: the
// old Refresh just bumped ExpiresAt without checking IsExpired.
func TestMemorySessionManager_RefreshRefusesExpired(t *testing.T) {
	m := NewMemorySessionManager(10 * time.Millisecond)
	s, _ := m.Create(context.Background(), "alice")
	time.Sleep(20 * time.Millisecond) // session past ExpiresAt
	if _, err := m.Refresh(context.Background(), s.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("expired Refresh: got %v, want ErrSessionNotFound", err)
	}
}

// TestMemorySessionManager_RefreshRefusesRevoked covers the
// admin-revocation case — operator revokes a session, attacker
// captures the id, tries to extend. MUST fail.
func TestMemorySessionManager_RefreshRefusesRevoked(t *testing.T) {
	m := NewMemorySessionManager(time.Hour)
	s, _ := m.Create(context.Background(), "alice")
	// Mark revoked directly via the underlying map (admin
	// revocation path; SDK exposes Destroy + revoke methods that
	// vary by store, but the Revoked field on the struct is the
	// canonical signal).
	stored, _ := m.Get(context.Background(), s.ID)
	stored.Revoked = true
	if _, err := m.Refresh(context.Background(), s.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("revoked Refresh: got %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionManager_ListByUser(t *testing.T) {
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
	m := NewMemorySessionManager(time.Hour)
	_, _ = m.Create(context.Background(), "alice")
	_, _ = m.Create(context.Background(), "bob")
	all, _ := m.ListAll(context.Background())
	if len(all) != 2 {
		t.Errorf("all sessions = %d, want 2", len(all))
	}
}

func TestMemorySessionManager_ConcurrentCreates(t *testing.T) {
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
