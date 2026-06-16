package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl/sqlite"

	_ "modernc.org/sqlite"
)

func newRevocationStore(t *testing.T) *sqlite.RevocationStore {
	t.Helper()
	s, err := sqlite.NewRevocationStore("file:" + filepath.Join(t.TempDir(), "rev.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestRevocationStore_RevokeLoadRoundTrip proves a revoked token surfaces in
// Load (the boot re-seed path) and that re-revoking the same token is an
// idempotent upsert that updates the expiry rather than erroring.
func TestRevocationStore_RevokeLoadRoundTrip(t *testing.T) {
	s := newRevocationStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Unix()

	if err := s.Revoke(ctx, "tok-a", exp); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Idempotent upsert: re-revoke with a later exp overwrites.
	later := time.Now().Add(2 * time.Hour).Unix()
	if err := s.Revoke(ctx, "tok-a", later); err != nil {
		t.Fatalf("Revoke (upsert): %v", err)
	}

	got, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got["tok-a"] != later {
		t.Errorf("Load[tok-a] = %d, want %d (upserted exp)", got["tok-a"], later)
	}
	if len(got) != 1 {
		t.Errorf("Load returned %d entries, want 1", len(got))
	}
}

// TestRevocationStore_LoadPrunesExpired proves Load drops rows whose exp has
// passed (lazy GC) so the boot-time deny-set never re-seeds a token that is
// already rejected on expiry anyway.
func TestRevocationStore_LoadPrunesExpired(t *testing.T) {
	s := newRevocationStore(t)
	ctx := context.Background()
	_ = s.Revoke(ctx, "live", time.Now().Add(time.Hour).Unix())
	_ = s.Revoke(ctx, "dead", time.Now().Add(-time.Hour).Unix())

	got, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := got["dead"]; ok {
		t.Errorf("expired token still loaded")
	}
	if _, ok := got["live"]; !ok {
		t.Errorf("live token not loaded")
	}
}

// TestRevocationStore_Prune isolates Prune from Load's own now()-based prune
// so the strictly-before-cutoff semantics are observable on the raw table.
func TestRevocationStore_Prune(t *testing.T) {
	s := newRevocationStore(t)
	ctx := context.Background()
	_ = s.Revoke(ctx, "keep", 1000)
	_ = s.Revoke(ctx, "drop", 100)

	if err := s.Prune(ctx, 500); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM revocations WHERE token = 'drop'`).Scan(&n); err != nil {
		t.Fatalf("count drop: %v", err)
	}
	if n != 0 {
		t.Errorf("drop survived Prune(500): count=%d", n)
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM revocations WHERE token = 'keep'`).Scan(&n); err != nil {
		t.Fatalf("count keep: %v", err)
	}
	if n != 1 {
		t.Errorf("keep removed by Prune(500): count=%d", n)
	}
}

// TestRevocationStore_WithDBSharesPool proves the shared-pool constructor
// migrates the namespace and stays usable on the caller-owned handle.
func TestRevocationStore_WithDBSharesPool(t *testing.T) {
	db := newSharedDB(t)
	s := sqlite.NewRevocationStoreWithDB(db)
	ctx := context.Background()
	if err := s.Revoke(ctx, "x", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err := s.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := got["x"]; !ok {
		t.Errorf("token not persisted via WithDB store")
	}
}
