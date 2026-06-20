package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/platform/migrate"
)

// TestMigration_IndependentNamespacesOnSharedDB proves the user and
// session stores track their schema versions independently even when
// pointed at the SAME database (the cluster-shared single-DSN case):
// each gets its own schema_migrations_<ns> table, both stamped v1.
func TestMigration_IndependentNamespacesOnSharedDB(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "wa.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	us, err := NewUserStoreWithDB(db)
	if err != nil {
		t.Fatalf("NewUserStoreWithDB: %v", err)
	}
	defer func() { _ = us.Close() }()
	ss, err := NewSessionStoreWithDB(db)
	if err != nil {
		t.Fatalf("NewSessionStoreWithDB: %v", err)
	}
	defer func() { _ = ss.Close() }()

	for _, ns := range []string{"webauthn_users", "webauthn_sessions"} {
		v, err := migrate.CurrentVersion(ctx, db, ns)
		if err != nil {
			t.Fatalf("CurrentVersion(%s): %v", ns, err)
		}
		if v != 1 {
			t.Errorf("namespace %s version = %d, want 1", ns, v)
		}
	}
}
