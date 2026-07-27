package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/protocols/oauth"

	_ "modernc.org/sqlite"
)

// TestRefreshTokenStore_ListExpiring_OrderedAndFiltered mirrors the memory
// backend's contract: only ACTIVE tokens expiring at-or-before the cutoff,
// soonest-first, thumbprint only (never the raw token).
func TestRefreshTokenStore_ListExpiring_OrderedAndFiltered(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := sqlite.NewRefreshTokenStoreWithDB(db) // runs migration internally
	ctx := context.Background()

	issue := func(tok, user, client string, in time.Duration) {
		if err := s.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: user, ClientID: client, ExpiresAt: time.Now().Add(in),
		}); err != nil {
			t.Fatalf("issue %s: %v", tok, err)
		}
	}
	issue("soon", "u1", "c1", time.Minute)
	issue("later", "u2", "c1", time.Hour)
	issue("far", "u3", "c2", 30*24*time.Hour)
	issue("already-expired", "u4", "c1", -time.Minute)

	entries, err := s.ListExpiring(ctx, time.Now().Add(2*time.Hour), 0)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2 (soon, later); got %+v", len(entries), entries)
	}
	if entries[0].UserID != "u1" || entries[1].UserID != "u2" {
		t.Fatalf("order = %+v, want soonest-first (u1, u2)", entries)
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

// TestRefreshTokenStore_ListExpiring_RespectsLimit proves a positive limit
// truncates the result while keeping the soonest entries.
func TestRefreshTokenStore_ListExpiring_RespectsLimit(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := sqlite.NewRefreshTokenStoreWithDB(db)
	ctx := context.Background()

	issue := func(tok, user string, in time.Duration) {
		if err := s.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: user, ClientID: "c1", ExpiresAt: time.Now().Add(in),
		}); err != nil {
			t.Fatalf("issue %s: %v", tok, err)
		}
	}
	issue("t1", "u1", time.Minute)
	issue("t2", "u2", 2*time.Minute)
	issue("t3", "u3", 3*time.Minute)

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

// TestRefreshTokenStore_ListExpiring_Empty proves an empty store returns an
// empty, non-error slice.
func TestRefreshTokenStore_ListExpiring_Empty(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := sqlite.NewRefreshTokenStoreWithDB(db)

	entries, err := s.ListExpiring(context.Background(), time.Now().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len(entries) = %d, want 0", len(entries))
	}
}

// Compile-time interface check mirroring the store's own.
var _ oauth.RefreshTokenExpiryLister = (*sqlite.RefreshTokenStore)(nil)
