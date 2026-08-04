package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestSessionManager_CreateGetDestroy(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	sm, err := NewSessionManager(cfg, 0)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	s, err := sm.Create(ctx, "user1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if s.UserID != "user1" {
		t.Fatalf("expected user1, got %s", s.UserID)
	}
	if s.ExpiresAt.Before(time.Now()) {
		t.Fatal("session already expired")
	}

	got, err := sm.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != s.ID {
		t.Fatalf("expected id=%s, got %s", s.ID, got.ID)
	}

	if err := sm.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := sm.Get(ctx, s.ID); err != sso.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after destroy, got %v", err)
	}
}

func TestSessionManager_CreateWithMeta(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	sm, err := NewSessionManager(cfg, 0)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	authTime := time.Now().UTC().Add(-time.Minute).Truncate(time.Nanosecond)
	s, err := sm.CreateWithMeta(ctx, "user2", sso.SessionMeta{
		IP:        "10.0.0.1",
		UserAgent: "test-agent",
		TenantID:  "tenant-abc",
		DeviceID:  "device-1", ClientID: "client-1", AuthorizedScopes: []string{"openid", "admin"}, AuthTime: authTime,
	})
	if err != nil {
		t.Fatalf("CreateWithMeta: %v", err)
	}
	if s.IP != "10.0.0.1" {
		t.Fatalf("expected IP 10.0.0.1, got %s", s.IP)
	}
	if s.UserAgent != "test-agent" {
		t.Fatalf("expected UserAgent test-agent, got %s", s.UserAgent)
	}
	if s.TenantID != "tenant-abc" {
		t.Fatalf("expected TenantID tenant-abc, got %s", s.TenantID)
	}
	if err := sm.SetAuthorizedScopes(ctx, s.ID, []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	if err := sm.MarkStepUp(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	got, err := sm.Get(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "client-1" || got.DeviceID != "device-1" || !got.AuthTime.Equal(authTime) || !got.StepUpRequired {
		t.Fatalf("authorization metadata did not round-trip: %+v", got)
	}
	if len(got.AuthorizedScopes) != 1 || got.AuthorizedScopes[0] != "openid" {
		t.Fatalf("scopes=%v", got.AuthorizedScopes)
	}
}

func TestSessionManager_Refresh(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	ttl := 10 * time.Minute
	sm, err := NewSessionManager(cfg, ttl)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	s, err := sm.Create(ctx, "user1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	oldExpiry := s.ExpiresAt

	// Refresh before expiry should succeed and extend.
	time.Sleep(10 * time.Millisecond) // ensure measurable difference
	refreshed, err := sm.Refresh(ctx, s.ID)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !refreshed.ExpiresAt.After(oldExpiry) {
		t.Fatal("Refresh should extend expiry")
	}

	// Destroy then Refresh must fail.
	if err := sm.Destroy(ctx, s.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := sm.Refresh(ctx, s.ID); err != sso.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after destroy, got %v", err)
	}
}

func TestSessionManager_ListByUser(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	sm, err := NewSessionManager(cfg, 0)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	s1, err := sm.Create(ctx, "user1")
	if err != nil {
		t.Fatalf("Create s1: %v", err)
	}
	s2, err := sm.Create(ctx, "user1")
	if err != nil {
		t.Fatalf("Create s2: %v", err)
	}
	sm.Create(ctx, "user2") // other user

	sessions, err := sm.ListByUser(ctx, "user1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions for user1, got %d", len(sessions))
	}
	ids := map[string]bool{s1.ID: true, s2.ID: true}
	for _, s := range sessions {
		if !ids[s.ID] {
			t.Fatalf("unexpected session id %s", s.ID)
		}
	}
}

func TestSessionManager_DeleteByTenant(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	sm, err := NewSessionManager(cfg, 0)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	s1, err := sm.CreateWithMeta(ctx, "user1", sso.SessionMeta{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Create s1: %v", err)
	}
	s2, err := sm.CreateWithMeta(ctx, "user2", sso.SessionMeta{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Create s2: %v", err)
	}
	sm.CreateWithMeta(ctx, "user3", sso.SessionMeta{TenantID: "t2"}) // other tenant

	n, err := sm.DeleteByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deleted, got %d", n)
	}

	// Check t1 sessions are gone.
	if _, err := sm.Get(ctx, s1.ID); err != sso.ErrSessionNotFound {
		t.Fatalf("s1 should be gone, got %v", err)
	}
	if _, err := sm.Get(ctx, s2.ID); err != sso.ErrSessionNotFound {
		t.Fatalf("s2 should be gone, got %v", err)
	}

	// Empty tenantID must be a no-op.
	n, err = sm.DeleteByTenant(ctx, "")
	if err != nil {
		t.Fatalf("DeleteByTenant empty: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 for empty tenantID, got %d", n)
	}
}

func TestSessionManager_ListByTenant(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	sm, err := NewSessionManager(cfg, 0)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	sm.CreateWithMeta(ctx, "user1", sso.SessionMeta{TenantID: "t1"})
	sm.CreateWithMeta(ctx, "user2", sso.SessionMeta{TenantID: "t1"})
	sm.CreateWithMeta(ctx, "user3", sso.SessionMeta{TenantID: "t2"})

	sessions, err := sm.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions for t1, got %d", len(sessions))
	}

	// Empty tenantID must return empty.
	empty, err := sm.ListByTenant(ctx, "")
	if err != nil {
		t.Fatalf("ListByTenant empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected 0 for empty tenantID, got %d", len(empty))
	}
}

func TestSessionManager_ExpiredSessionNotFound(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	// Use a very short TTL so the session expires quickly.
	sm, err := NewSessionManager(cfg, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	s, err := sm.Create(ctx, "user1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wait for expiry.
	time.Sleep(50 * time.Millisecond)

	if _, err := sm.Get(ctx, s.ID); err != sso.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after expiry, got %v", err)
	}
}

func TestSessionManager_InterfaceGuards(t *testing.T) {
	// Compile-time interface checks.
	var _ sso.SessionManager = (*SessionManager)(nil)
	var _ sso.SessionMetaCreator = (*SessionManager)(nil)
	var _ sso.SessionTenantIndex = (*SessionManager)(nil)
	var _ sso.SessionTenantLister = (*SessionManager)(nil)
}
