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

// TestRefreshTokenStore_FamilyCreatedAtRoundTrip proves the absolute-max-
// lifetime cap's input (FamilyCreatedAt) survives a fresh-schema Issue and
// is returned by both Inspect (non-destructive) and Consume (single-use).
func TestRefreshTokenStore_FamilyCreatedAtRoundTrip(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := sqlite.NewRefreshTokenStoreWithDB(db)
	ctx := context.Background()

	// Truncate to seconds: the column round-trips via UnixNano, but the test
	// only needs to prove propagation, not sub-second precision.
	created := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := s.Issue(ctx, "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyCreatedAt: created,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	insp, err := s.Inspect(ctx, "tok")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !insp.FamilyCreatedAt.Equal(created) {
		t.Fatalf("Inspect FamilyCreatedAt = %v, want %v", insp.FamilyCreatedAt, created)
	}
	cons, err := s.Consume(ctx, "tok")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !cons.FamilyCreatedAt.Equal(created) {
		t.Fatalf("Consume FamilyCreatedAt = %v, want %v", cons.FamilyCreatedAt, created)
	}
}

// TestRefreshTokenStore_FamilyCreatedAtAdditiveMigration proves the v6
// migration is additive + backward-compatible: a row written to a pre-v6
// schema (no family_created_at column) reads back a ZERO FamilyCreatedAt
// after the store's constructor runs the migration — the sentinel that
// SKIPS the absolute-max-lifetime check rather than fabricating a start
// time — and NEW rows on the migrated schema persist their value normally.
func TestRefreshTokenStore_FamilyCreatedAtAdditiveMigration(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	// legacyRefreshTokensDDL (shared with the generation additive-migration
	// test) predates BOTH generation (v5) and family_created_at (v6).
	if _, err := db.ExecContext(ctx, legacyRefreshTokensDDL); err != nil {
		t.Fatalf("legacy ddl: %v", err)
	}
	now := time.Now()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (token, user_id, client_id, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"legacy-tok", "u", "c", now.UnixNano(), now.Add(time.Hour).UnixNano(),
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	// Constructor runs migrations, including v6 (ALTER ADD family_created_at DEFAULT 0).
	s := sqlite.NewRefreshTokenStoreWithDB(db)

	insp, err := s.Inspect(ctx, "legacy-tok")
	if err != nil {
		t.Fatalf("Inspect legacy: %v", err)
	}
	if !insp.FamilyCreatedAt.IsZero() {
		t.Fatalf("legacy row FamilyCreatedAt = %v, want zero (additive default)", insp.FamilyCreatedAt)
	}

	// A NEW row on the migrated schema persists its value normally.
	created := now.Add(-time.Hour).Truncate(time.Second)
	if err := s.Issue(ctx, "new-tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyCreatedAt: created,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue new: %v", err)
	}
	cons, err := s.Consume(ctx, "new-tok")
	if err != nil {
		t.Fatalf("Consume new: %v", err)
	}
	if !cons.FamilyCreatedAt.Equal(created) {
		t.Fatalf("new row Consume FamilyCreatedAt = %v, want %v", cons.FamilyCreatedAt, created)
	}
}
