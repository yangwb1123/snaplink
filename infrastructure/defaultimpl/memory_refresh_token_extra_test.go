package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

func mkRefresh(uid, cid, fam string) *oauth.RefreshToken {
	return &oauth.RefreshToken{
		UserID:    uid,
		ClientID:  cid,
		FamilyID:  fam,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Scopes:    []string{"openid"},
	}
}

func TestMemoryRefreshTokenStore_Inspect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(ctx, "rt", mkRefresh("u", "c", ""))

	got, err := s.Inspect(ctx, "rt")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.UserID != "u" || got.ClientID != "c" {
		t.Errorf("inspected = %+v", got)
	}
	// Inspect is non-destructive — a subsequent Consume still works.
	if _, err := s.Consume(ctx, "rt"); err != nil {
		t.Errorf("Consume after Inspect: %v", err)
	}
}

func TestMemoryRefreshTokenStore_InspectUnknownAndExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	if _, err := s.Inspect(ctx, "nope"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Inspect(unknown) = %v", err)
	}

	expired := mkRefresh("u", "c", "")
	expired.ExpiresAt = time.Now().Add(-time.Second)
	_ = s.Issue(ctx, "old", expired)
	if _, err := s.Inspect(ctx, "old"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Inspect(expired) = %v", err)
	}
	// The expired entry was lazily GC'd by Inspect.
	if _, err := s.Inspect(ctx, "old"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Inspect(expired re-read) = %v", err)
	}
}

func TestMemoryRefreshTokenStore_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(ctx, "rt", mkRefresh("u", "c", "fam-1"))

	if err := s.Delete(ctx, "rt"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Inspect(ctx, "rt"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("after delete = %v", err)
	}
	// Idempotent.
	if err := s.Delete(ctx, "rt"); err != nil {
		t.Errorf("Delete(idempotent) = %v", err)
	}
	// The family marker is also wiped — a later Consume of the same token
	// must NOT surface a stale reuse-detection event.
	if _, err := s.Consume(ctx, "rt"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Consume after delete = %v, want plain not-found (no reuse)", err)
	}
}

func TestMemoryRefreshTokenStore_DeleteAllForSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(ctx, "a1", mkRefresh("alice", "app-x", ""))
	_ = s.Issue(ctx, "a2", mkRefresh("alice", "app-x", ""))
	_ = s.Issue(ctx, "a3", mkRefresh("alice", "app-y", ""))
	_ = s.Issue(ctx, "b1", mkRefresh("bob", "app-x", ""))

	// Empty userID is a no-op.
	if n, _ := s.DeleteAllForSubject(ctx, "", "app-x"); n != 0 {
		t.Errorf("empty user = %d, want 0", n)
	}

	// (alice, app-x): two deleted, app-y survives.
	n, err := s.DeleteAllForSubject(ctx, "alice", "app-x")
	if err != nil {
		t.Fatalf("DeleteAllForSubject: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2", n)
	}
	if _, err := s.Inspect(ctx, "a3"); err != nil {
		t.Errorf("app-y token destroyed: %v", err)
	}
	if _, err := s.Inspect(ctx, "b1"); err != nil {
		t.Errorf("bob token destroyed: %v", err)
	}

	// Empty clientID = all clients for the user.
	n, _ = s.DeleteAllForSubject(ctx, "alice", "")
	if n != 1 {
		t.Errorf("all-client delete = %d, want 1", n)
	}
}

func TestMemoryRefreshTokenStore_CountForSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(ctx, "a1", mkRefresh("alice", "app-x", ""))
	_ = s.Issue(ctx, "a2", mkRefresh("alice", "app-y", ""))
	_ = s.Issue(ctx, "b1", mkRefresh("bob", "app-x", ""))

	if n, _ := s.CountForSubject(ctx, "", "app-x"); n != 0 {
		t.Errorf("empty user count = %d, want 0", n)
	}
	if n, _ := s.CountForSubject(ctx, "alice", "app-x"); n != 1 {
		t.Errorf("alice app-x count = %d, want 1", n)
	}
	if n, _ := s.CountForSubject(ctx, "alice", ""); n != 2 {
		t.Errorf("alice all-client count = %d, want 2", n)
	}
	// Count is non-destructive.
	if n, _ := s.CountForSubject(ctx, "alice", ""); n != 2 {
		t.Errorf("re-count = %d, want 2 (non-destructive)", n)
	}
}

func TestMemoryRefreshTokenStore_DeleteFamilyClearsReuseMarker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(ctx, "leaf1", mkRefresh("u", "c", "fam"))
	_ = s.Issue(ctx, "leaf2", mkRefresh("u", "c", "fam"))

	// Empty family is a no-op.
	if n, _ := s.DeleteFamily(ctx, ""); n != 0 {
		t.Errorf("DeleteFamily(empty) = %d, want 0", n)
	}
	// Unknown family is idempotent (0, nil).
	if n, _ := s.DeleteFamily(ctx, "ghost"); n != 0 {
		t.Errorf("DeleteFamily(ghost) = %d, want 0", n)
	}

	n, err := s.DeleteFamily(ctx, "fam")
	if err != nil {
		t.Fatalf("DeleteFamily: %v", err)
	}
	if n != 2 {
		t.Errorf("DeleteFamily deleted %d active tokens, want 2", n)
	}
	// After family deletion, presenting a member is a plain not-found — the
	// reuse-detection marker is gone, so no stale family-kill is triggered.
	if _, err := s.Consume(ctx, "leaf1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("Consume after DeleteFamily = %v, want plain not-found", err)
	}
}

func TestMemoryRefreshTokenStore_ReuseDetectionThenFamilyKill(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(ctx, "leaf", mkRefresh("u", "c", "fam"))

	// First consume rotates the leaf out.
	if _, err := s.Consume(ctx, "leaf"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// Replay of the consumed leaf is detected as reuse (family marker kept).
	rt, err := s.Consume(ctx, "leaf")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Fatalf("replay = %v, want ErrRefreshTokenReused", err)
	}
	if rt == nil || rt.FamilyID != "fam" {
		t.Errorf("reuse result must carry FamilyID for the kill; got %+v", rt)
	}
}
