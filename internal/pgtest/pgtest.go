// Package pgtest gives each PostgreSQL integration test its own empty schema.
//
// Integration tests across different packages run concurrently (`go test ./...`
// runs package binaries in parallel) but historically shared one database and
// prepared it with TRUNCATE. A TRUNCATE takes ACCESS EXCLUSIVE and deletes rows
// a peer package is asserting on, so packages failed in a combination-dependent
// way: green when run alone, red under the full suite. Giving every test a
// private schema removes the shared mutable state entirely, so tests can run in
// parallel and repeatedly without truncating each other.
//
// Only compiled for tests that need it; the package has no Snaplink imports.
package pgtest

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// dsnEnv names the environment variable holding the integration DSN.
const dsnEnv = "SSO_TEST_POSTGRES_DSN"

// sequence disambiguates two tests whose sanitized names collide.
var sequence atomic.Uint64

// Schema returns a DSN whose search_path points at a private, empty schema, and
// removes that schema when the test ends. It skips the test when no DSN is
// configured, so CI without a database still exercises nothing here.
func Schema(t *testing.T) string {
	t.Helper()
	base := os.Getenv(dsnEnv)
	if base == "" {
		t.Skipf("%s not set — skipping PostgreSQL integration test", dsnEnv)
	}

	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}

	// Registered before the DROP cleanup because cleanups run LIFO and only
	// after this function's defers. Closing the pool in a defer here would make
	// the DROP hit a closed pool, fail silently, and leak the schema; the next
	// run would then abort on "schema already exists".
	t.Cleanup(func() { _ = admin.Close() })

	name := uniqueName(t.Name())
	if _, err := admin.ExecContext(context.Background(), "CREATE SCHEMA "+name); err != nil {
		t.Fatalf("create schema %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+name+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", name, err)
		}
	})

	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + "search_path=" + name
}

// uniqueName derives a schema name from the test name. Postgres truncates
// identifiers at 63 bytes, so the suffix is preserved and the readable prefix
// is clipped rather than letting the identifier be silently cut mid-token.
func uniqueName(testName string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(testName) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	const suffixDigits = 6
	prefix := b.String()
	if len(prefix) > 63-suffixDigits-1 {
		prefix = prefix[:63-suffixDigits-1]
	}
	return fmt.Sprintf("%s_%06d", prefix, sequence.Add(1))
}
