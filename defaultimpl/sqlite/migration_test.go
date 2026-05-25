package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/defaultimpl/sqlite"
	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite"
)

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
