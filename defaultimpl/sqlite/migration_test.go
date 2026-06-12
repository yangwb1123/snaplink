package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl/sqlite"
	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite"
)

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigration_RefreshTokensBackfillsLegacyColumns proves the
// refresh_tokens Func migration upgrades a pre-family-tracker database:
// an old table missing family_id/resources/authorization_details/sid
// gets them added (preserving existing rows), and is stamped v1.
func TestMigration_RefreshTokensBackfillsLegacyColumns(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

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

	// The 4 columns must now exist (a SELECT referencing them succeeds).
	if _, err := db.Exec(`SELECT family_id, resources, authorization_details, sid FROM refresh_tokens`); err != nil {
		t.Errorf("legacy columns not backfilled: %v", err)
	}
	// Existing row preserved.
	var token string
	if err := db.QueryRow(`SELECT token FROM refresh_tokens WHERE token='old'`).Scan(&token); err != nil {
		t.Errorf("legacy row lost: %v", err)
	}
	// After running all migrations, the version is the highest declared.
	if v, _ := migrate.CurrentVersion(ctx, db, "refresh_tokens"); v != sqlite.RefreshTokensMaxVersion() {
		t.Errorf("version = %d, want %d (RefreshTokensMaxVersion)", v, sqlite.RefreshTokensMaxVersion())
	}
}

// TestMigration_PerStoreNamespacesShareOneDB is the production
// single-DSN case: several stores constructed against the SAME sso.db
// each track their schema version under an independent namespace, so
// one store's future migration never disturbs another's history.
func TestMigration_PerStoreNamespacesShareOneDB(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "sso.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

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

// TestMaxVersion_Consistency verifies that each XxxMaxVersion() function
// agrees with the live schema version stamped by the store's own constructor.
// This catches any mismatch between the declared migration slice and the
// value advertised to the boot guard (migrate.CheckSchema).
//
// Stores that use explicit migration slices (refresh_tokens, ciba_requests)
// are verified by constructing them against a fresh DB and comparing the
// recorded version to XxxMaxVersion(). Stores that use ensureSchema with a
// single baseline migration are verified by asserting XxxMaxVersion() == 1
// and that construction stamps exactly v1.
func TestMaxVersion_Consistency(t *testing.T) {
	ctx := context.Background()

	// --- Stores with explicit, versioned migration slices ---

	t.Run("refresh_tokens", func(t *testing.T) {
		db := openSQLite(t)
		_ = sqlite.NewRefreshTokenStoreWithDB(db)
		live, err := migrate.CurrentVersion(ctx, db, "refresh_tokens")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if want := sqlite.RefreshTokensMaxVersion(); live != want {
			t.Errorf("live schema v%d != RefreshTokensMaxVersion() %d", live, want)
		}
	})

	t.Run("ciba_requests", func(t *testing.T) {
		db := openSQLite(t)
		if _, err := sqlite.NewCIBAStoreWithDB(db); err != nil {
			t.Fatalf("NewCIBAStoreWithDB: %v", err)
		}
		live, err := migrate.CurrentVersion(ctx, db, "ciba_requests")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if want := sqlite.CIBARequestsMaxVersion(); live != want {
			t.Errorf("live schema v%d != CIBARequestsMaxVersion() %d", live, want)
		}
	})

	// --- Stores that use ensureSchema (single baseline, always v1) ---

	// Spot-check a sample of v1 stores: construction stamps v1 and
	// XxxMaxVersion() == 1. All v1 stores use the same ensureSchema
	// path, so one representative sub-test per store is sufficient.

	t.Run("sessions", func(t *testing.T) {
		if want := sqlite.SessionsMaxVersion(); want != 1 {
			t.Errorf("SessionsMaxVersion() = %d, want 1", want)
		}
		db := openSQLite(t)
		if _, err := sqlite.NewSessionManagerWithDB(db, time.Hour); err != nil {
			t.Fatalf("NewSessionManagerWithDB: %v", err)
		}
		live, err := migrate.CurrentVersion(ctx, db, "sessions")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if live != 1 {
			t.Errorf("live schema v%d, want 1", live)
		}
	})

	t.Run("clients", func(t *testing.T) {
		want := sqlite.ClientsMaxVersion()
		if want < 1 {
			t.Errorf("ClientsMaxVersion() = %d, want >= 1", want)
		}
		// Use the DSN constructor so migrations run and stamp the version.
		dsn := "file:" + filepath.Join(t.TempDir(), "clients.db")
		store, err := sqlite.NewClientStore(dsn)
		if err != nil {
			t.Fatalf("NewClientStore: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		live, err := migrate.CurrentVersion(ctx, store.DB(), "clients")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if live != want {
			t.Errorf("live schema v%d != ClientsMaxVersion() %d", live, want)
		}
	})

	t.Run("auth_codes", func(t *testing.T) {
		want := sqlite.AuthCodesMaxVersion()
		if want < 1 {
			t.Errorf("AuthCodesMaxVersion() = %d, want >= 1", want)
		}
		dsn := "file:" + filepath.Join(t.TempDir(), "auth_codes.db")
		store, err := sqlite.NewAuthCodeStore(dsn)
		if err != nil {
			t.Fatalf("NewAuthCodeStore: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		live, err := migrate.CurrentVersion(ctx, store.DB(), "auth_codes")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if live != want {
			t.Errorf("live schema v%d != AuthCodesMaxVersion() %d", live, want)
		}
	})

	t.Run("users", func(t *testing.T) {
		if want := sqlite.UsersMaxVersion(); want != 1 {
			t.Errorf("UsersMaxVersion() = %d, want 1", want)
		}
		dsn := "file:" + filepath.Join(t.TempDir(), "users.db")
		store, err := sqlite.NewUserProvider(dsn)
		if err != nil {
			t.Fatalf("NewUserProvider: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		live, err := migrate.CurrentVersion(ctx, store.DB(), "users")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if live != 1 {
			t.Errorf("live schema v%d, want 1", live)
		}
	})

	t.Run("device_codes", func(t *testing.T) {
		if want := sqlite.DeviceCodesMaxVersion(); want != 1 {
			t.Errorf("DeviceCodesMaxVersion() = %d, want 1", want)
		}
		dsn := "file:" + filepath.Join(t.TempDir(), "device_codes.db")
		store, err := sqlite.NewDeviceCodeStore(dsn)
		if err != nil {
			t.Fatalf("NewDeviceCodeStore: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		live, err := migrate.CurrentVersion(ctx, store.DB(), "device_codes")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if live != 1 {
			t.Errorf("live schema v%d, want 1", live)
		}
	})

	t.Run("par", func(t *testing.T) {
		if want := sqlite.PARMaxVersion(); want != 1 {
			t.Errorf("PARMaxVersion() = %d, want 1", want)
		}
		db := openSQLite(t)
		if _, err := sqlite.NewPARStoreWithDB(db); err != nil {
			t.Fatalf("NewPARStoreWithDB: %v", err)
		}
		live, err := migrate.CurrentVersion(ctx, db, "par")
		if err != nil {
			t.Fatalf("CurrentVersion: %v", err)
		}
		if live != 1 {
			t.Errorf("live schema v%d, want 1", live)
		}
	})
}
