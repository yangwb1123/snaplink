package migrate_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	// File-backed (not :memory:) so multiple connections/goroutines share
	// one database, and busy_timeout lets BEGIN IMMEDIATE serialize
	// instead of failing fast under contention.
	dsn := "file:" + filepath.Join(t.TempDir(), "m.db") + "?_busy_timeout=5000"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func current(t *testing.T, db *sql.DB, ns string) int {
	t.Helper()
	v, err := migrate.CurrentVersion(context.Background(), db, ns)
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	return v
}

func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

var base = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: `CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY, name TEXT)`},
}

func TestRun_FreshApply(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	if err := migrate.Run(ctx, db, "demo", base); err != nil {
		t.Fatalf("run: %v", err)
	}
	if v := current(t, db, "demo"); v != 1 {
		t.Errorf("version = %d, want 1", v)
	}
	// Table actually exists + is usable.
	if _, err := db.Exec(`INSERT INTO widgets (id, name) VALUES ('a', 'A')`); err != nil {
		t.Errorf("insert into migrated table: %v", err)
	}
}

func TestRun_Idempotent(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	for i := range 3 {
		if err := migrate.Run(ctx, db, "demo", base); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if v := current(t, db, "demo"); v != 1 {
		t.Errorf("version = %d, want 1 after repeated runs", v)
	}
	if n := rowCount(t, db, "schema_migrations_demo"); n != 1 {
		t.Errorf("version table has %d rows, want 1 (no double-record)", n)
	}
}

func TestRun_Incremental(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	if err := migrate.Run(ctx, db, "demo", base); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	next := append(append([]migrate.Migration{}, base...),
		migrate.Migration{Version: 2, Name: "add_color", SQL: `ALTER TABLE widgets ADD COLUMN color TEXT`})
	if err := migrate.Run(ctx, db, "demo", next); err != nil {
		t.Fatalf("incremental: %v", err)
	}
	if v := current(t, db, "demo"); v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
	if _, err := db.Exec(`INSERT INTO widgets (id, name, color) VALUES ('a', 'A', 'red')`); err != nil {
		t.Errorf("v2 column missing: %v", err)
	}
}

// TestRun_AdoptsExistingSchema is the critical adoption path: a database
// that already has the tables (created the pre-migration way) must
// accept the idempotent baseline without error and be stamped v1 — no
// data loss, no "table already exists" failure.
func TestRun_AdoptsExistingSchema(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	// Simulate a pre-migration DB: create the table directly + seed data.
	if _, err := db.Exec(`CREATE TABLE widgets (id TEXT PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO widgets (id, name) VALUES ('keep', 'me')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := migrate.Run(ctx, db, "demo", base); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if v := current(t, db, "demo"); v != 1 {
		t.Errorf("version = %d, want 1 after adoption", v)
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM widgets WHERE id='keep'`).Scan(&name); err != nil || name != "me" {
		t.Errorf("pre-existing data lost: name=%q err=%v", name, err)
	}
}

// TestRun_FailureRollsBack proves a failing migration leaves no partial
// version record (atomic application).
func TestRun_FailureRollsBack(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	bad := []migrate.Migration{
		{Version: 1, Name: "ok", SQL: `CREATE TABLE IF NOT EXISTS t1 (id TEXT)`},
		{Version: 2, Name: "broken", SQL: `THIS IS NOT SQL`},
	}
	if err := migrate.Run(ctx, db, "demo", bad); err == nil {
		t.Fatal("expected error from broken migration")
	}
	// Whole transaction rolled back: even v1 must not be recorded.
	if v := current(t, db, "demo"); v != 0 {
		t.Errorf("version = %d, want 0 (full rollback on failure)", v)
	}
}

func TestRun_Validation(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	cases := map[string][]migrate.Migration{
		"non-positive version": {{Version: 0, Name: "z", SQL: "SELECT 1"}},
		"non-ascending":        {{Version: 2, Name: "a", SQL: "SELECT 1"}, {Version: 1, Name: "b", SQL: "SELECT 1"}},
		"duplicate":            {{Version: 1, Name: "a", SQL: "SELECT 1"}, {Version: 1, Name: "b", SQL: "SELECT 1"}},
	}
	for name, ms := range cases {
		if err := migrate.Run(ctx, db, "demo", ms); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	if err := migrate.Run(ctx, db, "Bad-NS", base); err == nil {
		t.Error("invalid namespace: expected error")
	}
}

// TestRun_RejectsRolledBackBinary is the upper-bound guard: a DB
// forward-migrated to v2 must REFUSE an older binary that only knows up to
// v1 (the canary-rollback foot-gun) instead of silently skipping every
// migration and serving on a schema it doesn't understand. The loop
// applies nothing in this case, so the post-loop guard is the only catch.
func TestRun_RejectsRolledBackBinary(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	// Forward-migrate to v2 with a "newer binary".
	v2 := append(append([]migrate.Migration{}, base...),
		migrate.Migration{Version: 2, Name: "add_color", SQL: `ALTER TABLE widgets ADD COLUMN color TEXT`})
	if err := migrate.Run(ctx, db, "demo", v2); err != nil {
		t.Fatalf("forward to v2: %v", err)
	}
	if v := current(t, db, "demo"); v != 2 {
		t.Fatalf("setup version = %d, want 2", v)
	}

	// Now an OLDER binary (knows only up to v1) boots against the v2 DB.
	err := migrate.Run(ctx, db, "demo", base)
	if err == nil {
		t.Fatal("expected error: older binary must refuse a forward-migrated DB")
	}
	for _, want := range []string{`"demo"`, "v2", "v1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q (operator needs the version mismatch spelled out)", err, want)
		}
	}
	// The guard rejects before COMMIT, so the recorded version is untouched.
	if v := current(t, db, "demo"); v != 2 {
		t.Errorf("version = %d, want 2 (guard must not mutate the DB)", v)
	}
}

// TestRun_UpperBoundNormalCases proves the guard is inert for every
// non-rollback case: fresh apply, same-version re-run, and a forward
// upgrade all return nil (equal-or-lower DB version behaves as before).
func TestRun_UpperBoundNormalCases(t *testing.T) {
	ctx := context.Background()
	v2 := append(append([]migrate.Migration{}, base...),
		migrate.Migration{Version: 2, Name: "add_color", SQL: `ALTER TABLE widgets ADD COLUMN color TEXT`})

	t.Run("fresh apply (DB v0 < maxKnown)", func(t *testing.T) {
		db := openDB(t)
		if err := migrate.Run(ctx, db, "demo", v2); err != nil {
			t.Fatalf("fresh apply: %v", err)
		}
		if v := current(t, db, "demo"); v != 2 {
			t.Errorf("version = %d, want 2", v)
		}
	})

	t.Run("same-version re-run (DB == maxKnown)", func(t *testing.T) {
		db := openDB(t)
		if err := migrate.Run(ctx, db, "demo", v2); err != nil {
			t.Fatalf("first run: %v", err)
		}
		if err := migrate.Run(ctx, db, "demo", v2); err != nil {
			t.Fatalf("same-version re-run must not error: %v", err)
		}
	})

	t.Run("forward upgrade v1->v2", func(t *testing.T) {
		db := openDB(t)
		if err := migrate.Run(ctx, db, "demo", base); err != nil {
			t.Fatalf("v1: %v", err)
		}
		if err := migrate.Run(ctx, db, "demo", v2); err != nil {
			t.Fatalf("v1->v2 upgrade must not error: %v", err)
		}
		if v := current(t, db, "demo"); v != 2 {
			t.Errorf("version = %d, want 2", v)
		}
	})
}

func TestCurrentVersion_MissingTableIsZero(t *testing.T) {
	db := openDB(t)
	if v := current(t, db, "never_run"); v != 0 {
		t.Errorf("version = %d, want 0 for unmigrated namespace", v)
	}
}

func TestRun_FuncMigration(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	ran := false
	ms := []migrate.Migration{
		{Version: 1, Name: "func_step", Func: func(ctx context.Context, x migrate.Execer) error {
			ran = true
			_, err := x.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS fromfunc (id TEXT)`)
			return err
		}},
	}
	if err := migrate.Run(ctx, db, "demo", ms); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !ran {
		t.Fatal("func migration not invoked")
	}
	if _, err := db.Exec(`INSERT INTO fromfunc (id) VALUES ('a')`); err != nil {
		t.Errorf("func-created table not usable: %v", err)
	}
	// Idempotent: second run skips the already-applied func.
	ran = false
	if err := migrate.Run(ctx, db, "demo", ms); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if ran {
		t.Error("func migration re-ran after being recorded")
	}
}

func TestRun_FuncErrorRollsBack(t *testing.T) {
	db := openDB(t)
	ms := []migrate.Migration{
		{Version: 1, Name: "boom", Func: func(_ context.Context, _ migrate.Execer) error {
			return errInTest
		}},
	}
	if err := migrate.Run(context.Background(), db, "demo", ms); err == nil {
		t.Fatal("expected func error to propagate")
	}
	if v := current(t, db, "demo"); v != 0 {
		t.Errorf("version = %d, want 0 after func failure", v)
	}
}

func TestRun_RejectsBothOrNeitherSQLAndFunc(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	both := []migrate.Migration{{Version: 1, Name: "both", SQL: "SELECT 1", Func: func(context.Context, migrate.Execer) error { return nil }}}
	if err := migrate.Run(ctx, db, "demo", both); err == nil {
		t.Error("expected error when both SQL and Func set")
	}
	neither := []migrate.Migration{{Version: 1, Name: "neither"}}
	if err := migrate.Run(ctx, db, "demo2", neither); err == nil {
		t.Error("expected error when neither SQL nor Func set")
	}
}

var errInTest = errTest("boom")

type errTest string

func (e errTest) Error() string { return string(e) }

func TestStatus_ReportsPerNamespace(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	// Two namespaces at different versions.
	if err := migrate.Run(ctx, db, "alpha", []migrate.Migration{
		{Version: 1, Name: "a1", SQL: `CREATE TABLE IF NOT EXISTS a (x TEXT)`},
		{Version: 2, Name: "a2", SQL: `CREATE TABLE IF NOT EXISTS a2 (x TEXT)`},
	}); err != nil {
		t.Fatalf("alpha: %v", err)
	}
	if err := migrate.Run(ctx, db, "beta", base); err != nil {
		t.Fatalf("beta: %v", err)
	}

	st, err := migrate.Status(ctx, db)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st) != 2 {
		t.Fatalf("got %d namespaces, want 2: %+v", len(st), st)
	}
	// Sorted by namespace: alpha, beta.
	if st[0].Namespace != "alpha" || st[0].Version != 2 || st[0].Name != "a2" {
		t.Errorf("alpha status = %+v, want {alpha 2 a2}", st[0])
	}
	if st[1].Namespace != "beta" || st[1].Version != 1 {
		t.Errorf("beta status = %+v, want {beta 1}", st[1])
	}
	if st[0].AppliedAt.IsZero() {
		t.Error("applied_at not populated")
	}
}

func TestStatus_EmptyDBNoNamespaces(t *testing.T) {
	st, err := migrate.Status(context.Background(), openDB(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st) != 0 {
		t.Errorf("got %d namespaces on empty DB, want 0", len(st))
	}
}

// TestRun_ConcurrentRunnersSerialize simulates replicas booting together
// against one database: every Run must succeed and the version must be
// recorded exactly once (BEGIN IMMEDIATE serialization, no double-apply).
func TestRun_ConcurrentRunnersSerialize(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	const replicas = 8
	var wg sync.WaitGroup
	errs := make(chan error, replicas)
	for range replicas {
		wg.Go(func() {
			errs <- migrate.Run(ctx, db, "demo", base)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent run failed: %v", err)
		}
	}
	if v := current(t, db, "demo"); v != 1 {
		t.Errorf("version = %d, want 1", v)
	}
	if n := rowCount(t, db, "schema_migrations_demo"); n != 1 {
		t.Errorf("version recorded %d times, want exactly 1", n)
	}
}
