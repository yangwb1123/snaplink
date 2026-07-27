package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite"
)

// TestMigration_RefreshTokensBackfillsLegacyColumns proves the
// refresh_tokens migrations upgrade a pre-family-tracker database: an old
// table missing family_id/resources/authorization_details/sid (v1) and the
// later amr/acr/auth_time auth-context columns (v3) gets them all added,
// preserving existing rows, and is stamped at the latest version.
func TestMigration_RefreshTokensBackfillsLegacyColumns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Legacy schema: the 8 original columns, none of the 4 later ones.
	if _, err := db.Exec(`CREATE TABLE refresh_tokens (
		token TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
		provider TEXT NOT NULL DEFAULT '', scopes TEXT NOT NULL DEFAULT '[]',
		attributes TEXT NOT NULL DEFAULT '{}', issued_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("legacy table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO refresh_tokens (token,user_id,client_id,issued_at,expires_at)
		VALUES ('old','u','c',1,2)`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	// NewRefreshTokenStoreWithDB returns only the store (no error) — the
	// migration runs best-effort inside it.
	_ = sqlite.NewRefreshTokenStoreWithDB(db)

	// The later columns must now exist (a SELECT referencing them succeeds) —
	// including the v3 RFC 9068 auth-context columns (amr/acr/auth_time), the
	// v4 RFC 9449 DPoP key-binding column (confirmation_jkt), the v5
	// token-policy max_refresh_depth column (generation), and the v6
	// absolute-max-lifetime column (family_created_at).
	if _, err := db.Exec(`SELECT family_id, resources, authorization_details, sid,
		amr, acr, auth_time, confirmation_jkt, generation, family_created_at FROM refresh_tokens`); err != nil {
		t.Errorf("legacy columns not backfilled: %v", err)
	}
	// The backfilled generation column defaults to 0 on the pre-existing row.
	var gen int
	if err := db.QueryRow(`SELECT generation FROM refresh_tokens WHERE token='old'`).Scan(&gen); err != nil {
		t.Errorf("generation not readable: %v", err)
	} else if gen != 0 {
		t.Errorf("legacy row generation = %d, want 0", gen)
	}
	// Existing row preserved.
	var token string
	if err := db.QueryRow(`SELECT token FROM refresh_tokens WHERE token='old'`).Scan(&token); err != nil {
		t.Errorf("legacy row lost: %v", err)
	}
	if v, _ := migrate.CurrentVersion(ctx, db, "refresh_tokens"); v != 6 {
		t.Errorf("version = %d, want 6", v)
	}
}

// TestMigration_AuthCodesBackfillsDPoPBindingColumn proves the auth_codes v2
// migration adds confirmation_jkt (RFC 9449 §10) to a database created before
// that migration existed, preserving existing rows.
func TestMigration_AuthCodesBackfillsDPoPBindingColumn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "ac.db")

	// Seed a pre-v2 database directly (bypassing the store entirely) so it
	// looks exactly like a database created before the DPoP-binding column
	// existed: the original 11 columns, no confirmation_jkt, and the schema
	// version table already stamped at v1 (matches a real upgrade — the v1
	// boot that created this table ran before v2 was added).
	seed, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := seed.Exec(`CREATE TABLE auth_codes (
		code TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL DEFAULT '', scopes TEXT NOT NULL DEFAULT '[]',
		nonce TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '',
		attributes TEXT NOT NULL DEFAULT '{}', code_challenge TEXT NOT NULL DEFAULT '',
		code_challenge_method TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("legacy table: %v", err)
	}
	if _, err := seed.Exec(`INSERT INTO auth_codes (code,user_id,client_id,expires_at)
		VALUES ('old','u','c',2)`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := migrate.Run(ctx, seed, "auth_codes", []migrate.Migration{
		{Version: 1, Name: "baseline", SQL: `SELECT 1`},
	}); err != nil {
		t.Fatalf("stamp v1: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed: %v", err)
	}

	// NewAuthCodeStore reopens the SAME file and runs the real migration
	// set — exactly what a pre-upgrade deployment's next boot does.
	st, err := sqlite.NewAuthCodeStore(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if _, err := st.DB().Exec(`SELECT confirmation_jkt FROM auth_codes`); err != nil {
		t.Errorf("confirmation_jkt not backfilled: %v", err)
	}
	// v3 backfills the OIDC §5.5 claims-parameter column on the same boot.
	if _, err := st.DB().Exec(`SELECT requested_claims FROM auth_codes`); err != nil {
		t.Errorf("requested_claims not backfilled: %v", err)
	}
	var code string
	if err := st.DB().QueryRow(`SELECT code FROM auth_codes WHERE code='old'`).Scan(&code); err != nil {
		t.Errorf("legacy row lost: %v", err)
	}
	if _, err := st.DB().Exec(`SELECT auth_time, amr, acr, resources, authorization_details, sid FROM auth_codes`); err != nil {
		t.Errorf("v4 auth-context columns not backfilled: %v", err)
	}
	// The store's real migration set doesn't stop at v2 — a pre-v2 database
	// booting today also picks up the v3 requested_claims backfill and the v4
	// RFC 9068 auth-context backfill (auth_codes_test.go covers each in
	// isolation) in the same upgrade pass.
	if v, _ := migrate.CurrentVersion(ctx, st.DB(), "auth_codes"); v != 4 {
		t.Errorf("version = %d, want 4", v)
	}
}

// TestBusyTimeoutPragma verifies that the modernc.org/sqlite driver
// honours the `_pragma=busy_timeout(N)` DSN form. The old mattn-style
// `_busy_timeout=N` is silently ignored by this driver; using the wrong
// form left every store with no busy timeout configured, causing immediate
// SQLITE_BUSY errors under write contention.
func TestBusyTimeoutPragma(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", v)
	}
}

// TestMigration_PerStoreNamespacesShareOneDB is the production
// single-DSN case: several stores constructed against the SAME sso.db
// each track their schema version under an independent namespace, so
// one store's future migration never disturbs another's history.
func TestMigration_PerStoreNamespacesShareOneDB(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "sso.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Construct three stores (each runs its baseline) against one DB.
	if _, err := sqlite.NewPARStoreWithDB(db); err != nil {
		t.Fatalf("PAR: %v", err)
	}
	if _, err := sqlite.NewMFAChallengeStoreWithDB(db); err != nil {
		t.Fatalf("MFA: %v", err)
	}
	if _, err := sqlite.NewPairwiseSubjectStoreWithDB(db); err != nil {
		t.Fatalf("pairwise: %v", err)
	}

	for _, ns := range []string{"par", "mfa_challenges", "pairwise"} {
		v, err := migrate.CurrentVersion(ctx, db, ns)
		if err != nil {
			t.Fatalf("CurrentVersion(%s): %v", ns, err)
		}
		if v != 1 {
			t.Errorf("namespace %s version = %d, want 1", ns, v)
		}
	}

	// Each namespace has its OWN version table — confirm they're distinct
	// rows in distinct tables, not a shared one.
	for _, table := range []string{
		"schema_migrations_par", "schema_migrations_mfa_challenges", "schema_migrations_pairwise",
	} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Errorf("version table %s missing: %v", table, err)
		} else if n != 1 {
			t.Errorf("%s has %d rows, want 1", table, n)
		}
	}
}
