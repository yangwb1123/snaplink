package sqlite_test

import (
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/permissions/permissionstest"
	permsqlite "github.com/snaplink/sso/permissions/sqlite"
)

// TestSQLiteProvider_Conformance runs the shared Provider
// conformance suite against the SQLite peer. Pinned-in
// equivalence with the memory peer (see
// permissions/memory_conformance_test.go) is the whole point —
// operators swapping backends should see no behavior differences.
func TestSQLiteProvider_Conformance(t *testing.T) {
	permissionstest.ConformanceSuite{
		Factory: func(t *testing.T) permissions.Provider {
			t.Helper()
			dir := t.TempDir()
			dsn := "file:" + filepath.Join(dir, "p.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
			p, err := permsqlite.New(dsn)
			if err != nil {
				t.Fatalf("permsqlite.New: %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })
			return p
		},
	}.Run(t)
}
