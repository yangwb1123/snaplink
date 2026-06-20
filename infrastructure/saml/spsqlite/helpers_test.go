package sqlite

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openSharedDB opens a process-unique shared-cache in-memory *sql.DB for the
// WithDB / shared-pool tests (several SAML stores on one DB). t.Cleanup closes
// it.
func openSharedDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", name, time.Now().UnixNano())
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open shared db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping shared db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
