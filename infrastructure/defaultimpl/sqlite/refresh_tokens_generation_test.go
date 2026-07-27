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

// TestRefreshTokenStore_GenerationRoundTrip proves the rotation-generation
// counter survives a fresh-schema Issue and is returned by both Inspect
// (non-destructive) and Consume (single-use).
func TestRefreshTokenStore_GenerationRoundTrip(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := sqlite.NewRefreshTokenStoreWithDB(db)
	ctx := context.Background()

	if err := s.Issue(ctx, "tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", Generation: 5,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	insp, err := s.Inspect(ctx, "tok")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if insp.Generation != 5 {
		t.Fatalf("Inspect Generation = %d, want 5", insp.Generation)
	}
	cons, err := s.Consume(ctx, "tok")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if cons.Generation != 5 {
		t.Fatalf("Consume Generation = %d, want 5", cons.Generation)
	}
}

// legacyRefreshTokensDDL is the pre-v5 baseline (every column EXCEPT generation)
// — a database provisioned before the max_refresh_depth feature. Used to prove
// the v5 additive migration backfills generation with a 0 DEFAULT.
const legacyRefreshTokensDDL = `
CREATE TABLE refresh_tokens (
    token                  TEXT    PRIMARY KEY,
    user_id                TEXT    NOT NULL,
    client_id              TEXT    NOT NULL,
    provider               TEXT    NOT NULL DEFAULT '',
    scopes                 TEXT    NOT NULL DEFAULT '[]',
    attributes             TEXT    NOT NULL DEFAULT '{}',
    issued_at              INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    family_id              TEXT    NOT NULL DEFAULT '',
    resources              TEXT    NOT NULL DEFAULT '[]',
    authorization_details  TEXT    NOT NULL DEFAULT '',
    sid                    TEXT    NOT NULL DEFAULT '',
    amr                    TEXT    NOT NULL DEFAULT '[]',
    acr                    TEXT    NOT NULL DEFAULT '',
    auth_time              INTEGER NOT NULL DEFAULT 0,
    confirmation_jkt       TEXT    NOT NULL DEFAULT ''
);`

// TestRefreshTokenStore_GenerationAdditiveMigration proves the v5 migration is
// additive + backward-compatible: a row written to a pre-v5 schema (no
// generation column) reads back Generation 0 after the store's constructor runs
// the migration, and NEW rows on the migrated schema persist their generation.
func TestRefreshTokenStore_GenerationAdditiveMigration(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	// Provision a legacy (pre-v5) table and seed a row the old code wrote.
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

	// Constructor runs migrations, including v5 (ALTER ADD generation DEFAULT 0).
	s := sqlite.NewRefreshTokenStoreWithDB(db)

	insp, err := s.Inspect(ctx, "legacy-tok")
	if err != nil {
		t.Fatalf("Inspect legacy: %v", err)
	}
	if insp.Generation != 0 {
		t.Fatalf("legacy row Generation = %d, want 0 (additive default)", insp.Generation)
	}

	// A NEW row on the migrated schema persists its generation normally.
	if err := s.Issue(ctx, "new-tok", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", Generation: 7,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Issue new: %v", err)
	}
	cons, err := s.Consume(ctx, "new-tok")
	if err != nil {
		t.Fatalf("Consume new: %v", err)
	}
	if cons.Generation != 7 {
		t.Fatalf("new row Generation = %d, want 7", cons.Generation)
	}
}
