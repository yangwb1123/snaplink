package memorystoreoauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreoauth"
	"github.com/snaplink/sso/protocols/oauth"
)

// seedExpiryToken issues one refresh token expiring `in` from now, for the
// ListExpiring "calendar" tests below.
func seedExpiryToken(t *testing.T, s *memorystoreoauth.MemoryRefreshTokenStore, token, userID, clientID string, in time.Duration) {
	t.Helper()
	if err := s.Issue(context.Background(), token, &oauth.RefreshToken{
		UserID: userID, ClientID: clientID, ExpiresAt: time.Now().Add(in),
	}); err != nil {
		t.Fatalf("seed Issue(%s): %v", token, err)
	}
}

// TestMemoryRefreshTokenStore_ListExpiring_OrderedAndFiltered proves the
// expiry-calendar read returns only ACTIVE tokens expiring at-or-before the
// cutoff, soonest-first, and never leaks the raw token value.
func TestMemoryRefreshTokenStore_ListExpiring_OrderedAndFiltered(t *testing.T) {
	t.Parallel()
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()

	seedExpiryToken(t, s, "soon", "u1", "c1", time.Minute)
	seedExpiryToken(t, s, "later", "u2", "c1", time.Hour)
	seedExpiryToken(t, s, "far", "u3", "c2", 30*24*time.Hour)
	seedExpiryToken(t, s, "already-expired", "u4", "c1", -time.Minute)

	entries, err := s.ListExpiring(ctx, time.Now().Add(2*time.Hour), 0)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2 (soon, later); got %+v", len(entries), entries)
	}
	if entries[0].UserID != "u1" || entries[1].UserID != "u2" {
		t.Fatalf("order = %v, want soonest-first (u1, u2)", entries)
	}
	if !entries[0].ExpiresAt.Before(entries[1].ExpiresAt) {
		t.Errorf("entries not soonest-first: %+v", entries)
	}
	for _, e := range entries {
		if e.Thumbprint == "" {
			t.Errorf("Thumbprint empty for %+v", e)
		}
		if e.Thumbprint == "soon" || e.Thumbprint == "later" {
			t.Errorf("Thumbprint leaked the raw token value: %q", e.Thumbprint)
		}
	}
}

// TestMemoryRefreshTokenStore_ListExpiring_RespectsLimit proves a positive
// limit truncates the result while still returning the soonest entries.
func TestMemoryRefreshTokenStore_ListExpiring_RespectsLimit(t *testing.T) {
	t.Parallel()
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()

	seedExpiryToken(t, s, "t1", "u1", "c1", time.Minute)
	seedExpiryToken(t, s, "t2", "u2", "c1", 2*time.Minute)
	seedExpiryToken(t, s, "t3", "u3", "c1", 3*time.Minute)

	entries, err := s.ListExpiring(ctx, time.Now().Add(time.Hour), 2)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].UserID != "u1" || entries[1].UserID != "u2" {
		t.Fatalf("limit did not keep the soonest entries: %+v", entries)
	}
}

// TestMemoryRefreshTokenStore_ListExpiring_Empty proves an empty store (or a
// cutoff with no matches) returns an empty, non-nil-error slice.
func TestMemoryRefreshTokenStore_ListExpiring_Empty(t *testing.T) {
	t.Parallel()
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	entries, err := s.ListExpiring(context.Background(), time.Now().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len(entries) = %d, want 0", len(entries))
	}
}

// Compile-time interface check mirroring the store's own — belt-and-braces
// against a future accidental signature drift.
var _ oauth.RefreshTokenExpiryLister = (*memorystoreoauth.MemoryRefreshTokenStore)(nil)
