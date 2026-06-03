package sqlite

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// uniqDSN returns a process-unique shared-cache in-memory DSN so each store gets
// an isolated DB that survives as long as the pool holds a connection.
func uniqDSN(name string) string {
	return fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", name, time.Now().UnixNano())
}

// openSharedDB opens a process-unique shared-cache in-memory *sql.DB for the
// WithDB / shared-pool tests. t.Cleanup closes it.
func openSharedDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", uniqDSN(name))
	if err != nil {
		t.Fatalf("open shared db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping shared db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
