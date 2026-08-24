package auditstore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/audit"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// TestClassify_Table drives the dialect classifier: postgres iff the DSN
// begins with postgres:// or postgresql:// (case-insensitive); everything
// else is a sqlite DSN (path or file: URI). The classification is total
// and unambiguous, so the same opener dispatches without a second state
// flag.
func TestClassify_Table(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		dsn  string
		want Dialect
	}{
		{"postgres scheme", "postgres://user@localhost:5432/sso?sslmode=disable", DialectPostgres},
		{"postgresql scheme", "postgresql://user:pw@db:5432/sso", DialectPostgres},
		{"postgres uppercase scheme", "POSTGRES://user@db/sso", DialectPostgres},
		{"postgresql mixed case scheme", "PostgreSQl://user@db/sso", DialectPostgres},
		{"plain sqlite path", "/var/lib/sso/audit.db", DialectSQLite},
		{"relative sqlite path", "audit.db", DialectSQLite},
		{"sqlite file uri", "file:/var/lib/sso/audit.db?_journal=WAL", DialectSQLite},
		{"sqlite file uri mode ro", "file:audit.db?mode=ro", DialectSQLite},
		{"in-memory sqlite", ":memory:", DialectSQLite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.dsn); got != tc.want {
				t.Errorf("Classify(%q) = %v, want %v", tc.dsn, got, tc.want)
			}
		})
	}
}

// seedSQLiteStore writes n hash-chained events (stock Recorder +
// WithHashChain → sqlite.Sink) into a fresh store at dsn and closes it.
func seedSQLiteStore(t *testing.T, dsn string, n int) {
	t.Helper()
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer func() { _ = sink.Close() }()
	rec := audit.New(sink, audit.WithHashChain())
	for i := range n {
		rec.Record(context.Background(), &audit.Event{
			ID:      "evt-" + string(rune('a'+i)),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
			ActorID: "user",
		})
	}
}

// TestOpenReadOnly_SQLiteChainOrder proves the shared opener + reader
// return the store's events in CHAIN ORDER (oldest first) so
// audit.VerifyChain accepts them directly — the same reversal discipline
// the --from-url path uses, now over a durable store.
func TestOpenReadOnly_SQLiteChainOrder(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedSQLiteStore(t, dsn, 5)

	st, err := OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = st.Close() }()

	events, truncated, err := ReadChain(context.Background(), st, 0, 500)
	if err != nil {
		t.Fatalf("ReadChain: %v", err)
	}
	if truncated {
		t.Error("ReadChain reported truncation with limit=0")
	}
	if len(events) != 5 {
		t.Fatalf("ReadChain returned %d events, want 5", len(events))
	}
	if err := audit.VerifyChain(events); err != nil {
		t.Errorf("chain order broken: %v", err)
	}
}

// TestOpenReadOnly_SQLitePagingMirrorsSink drives the store directly with
// a small page size and confirms ReadChain assembles the same chain as a
// single full read — the pagination path a >1000-event store exercises.
func TestOpenReadOnly_SQLitePagingMirrorsSink(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedSQLiteStore(t, dsn, 7)

	st, err := OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = st.Close() }()

	paged, _, err := ReadChain(context.Background(), st, 0, 3)
	if err != nil {
		t.Fatalf("ReadChain pageSize=3: %v", err)
	}
	full, _, err := ReadChain(context.Background(), st, 0, 500)
	if err != nil {
		t.Fatalf("ReadChain full: %v", err)
	}
	if len(paged) != len(full) {
		t.Fatalf("paged len=%d, full len=%d", len(paged), len(full))
	}
	for i := range full {
		if paged[i].Hash != full[i].Hash {
			t.Errorf("event %d hash mismatch: paged %q full %q", i, paged[i].Hash, full[i].Hash)
		}
	}
}

// TestReadChain_LimitKeepsOldestPrefix pins the truncation semantics: a
// --limit cap keeps the OLDEST `limit` events (the genesis-anchored
// prefix VerifyChain accepts), reports truncated=true, and never asserts
// the prefix head is the chain tip. An exact fill is NOT truncation.
func TestReadChain_LimitKeepsOldestPrefix(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedSQLiteStore(t, dsn, 10)

	st, err := OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Full read for ground truth (chain order).
	full, _, err := ReadChain(context.Background(), st, 0, 500)
	if err != nil {
		t.Fatalf("ReadChain full: %v", err)
	}

	events, truncated, err := ReadChain(context.Background(), st, 5, 500)
	if err != nil {
		t.Fatalf("ReadChain: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("limit=5 returned %d events, want 5", len(events))
	}
	if !truncated {
		t.Error("limit=5 over a 10-event store must report truncated")
	}
	for i := range events {
		if events[i].Hash != full[i].Hash {
			t.Errorf("event %d is not the genesis prefix: got %q want %q", i, events[i].Hash, full[i].Hash)
		}
	}
	if err := audit.VerifyChain(events); err != nil {
		t.Errorf("the truncated prefix must verify as a genesis chain: %v", err)
	}

	// Exact fill: 10 events capped at limit=10 must NOT report truncation.
	all, truncated, err := ReadChain(context.Background(), st, 10, 500)
	if err != nil {
		t.Fatalf("ReadChain limit=10: %v", err)
	}
	if len(all) != 10 || truncated {
		t.Errorf("exact fill: len=%d truncated=%v, want (10, false)", len(all), truncated)
	}
}

// TestReadChain_EmptyStore returns an empty chain with no truncation, so
// audit-verify prints its existing "no events to verify" (exit 0).
func TestReadChain_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "empty.db")
	seedSQLiteStore(t, dsn, 0)

	st, err := OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = st.Close() }()

	events, truncated, err := ReadChain(context.Background(), st, 0, 500)
	if err != nil {
		t.Fatalf("ReadChain: %v", err)
	}
	if len(events) != 0 || truncated {
		t.Errorf("empty store: len=%d truncated=%v, want (0, false)", len(events), truncated)
	}
}

// TestOpenReadOnly_SchemaMismatchFailsClosed seeds a store, rewrites its
// recorded schema version, and confirms the read-only opener rejects it
// with a version diagnostic instead of reading through a query path it
// cannot understand.
func TestOpenReadOnly_SchemaMismatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedSQLiteStore(t, dsn, 2)

	// Rewrite the recorded version (v3) to v99 — the offline tool must
	// fail closed, never migrate and never read.
	db, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open store for tamper: %v", err)
	}
	if _, err := db.DB().ExecContext(context.Background(),
		"UPDATE schema_migrations_audit SET version = 99 WHERE version = 1"); err != nil {
		t.Fatalf("rewrite version: %v", err)
	}
	_ = db.Close()

	_, err = OpenReadOnly(dsn)
	if err == nil {
		t.Fatal("OpenReadOnly must fail closed on a schema-version mismatch")
	}
	if got := err.Error(); !strings.Contains(got, "schema version mismatch") {
		t.Errorf("diagnostic does not name the mismatch: %v", got)
	}
	// The file must not have been re-migrated back to v3 by the open.
	db2, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("reopen after failed open: %v", err)
	}
	defer func() { _ = db2.Close() }()
	var live int
	if err := db2.DB().QueryRowContext(context.Background(),
		"SELECT MAX(version) FROM schema_migrations_audit").Scan(&live); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if live != 99 {
		t.Errorf("open mutated the store: version=%d, want 99 (never migrate)", live)
	}
}

// TestOpenReadOnly_ROHandleDoesNotCreateFiles pins the read-only contract
// against a nonexistent path under a genuine read-only handle: the opener
// must fail rather than create an empty file on disk. (A plain path DSN
// opens READWRITE|CREATE at the driver level — the pre-existing sqlite
// behavior the usage text's "append ?mode=ro" addresses — so this test
// uses the explicit read-only form.)
func TestOpenReadOnly_ROHandleDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "nope.db") + "?mode=ro"
	if _, err := OpenReadOnly(dsn); err == nil {
		t.Fatal("OpenReadOnly over a missing sqlite file must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "nope.db")); !os.IsNotExist(err) {
		t.Errorf("open created a file (read-only tool must not write)")
	}
}

// TestOpenReadOnly_PostgresChain (REQ-5 coordination): the SAME shared
// opener + reader that serves sqlite serves a postgres store under
// SSO_TEST_POSTGRES_DSN (repo skip convention) — one opener, both
// dialects, chain order preserved.
func TestOpenReadOnly_PostgresChain(t *testing.T) {
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres auditstore test")
	}
	pg, err := postgres.NewAuditSink(postgres.Config{DSN: dsn}) // writable: test setup migrates
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	defer func() { _ = pg.Close() }()
	if _, err := pg.DB().ExecContext(context.Background(), "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}
	rec := audit.New(pg, audit.WithHashChain())
	for i := range 5 {
		rec.Record(context.Background(), &audit.Event{
			ID:      "pevt-" + string(rune('a'+i)),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
		})
	}

	st, err := OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("OpenReadOnly(postgres): %v", err)
	}
	defer func() { _ = st.Close() }()
	events, truncated, err := ReadChain(context.Background(), st, 0, 500)
	if err != nil {
		t.Fatalf("ReadChain: %v", err)
	}
	if truncated || len(events) != 5 {
		t.Fatalf("len=%d truncated=%v, want (5, false)", len(events), truncated)
	}
	if err := audit.VerifyChain(events); err != nil {
		t.Errorf("postgres chain order broken: %v", err)
	}
	head, err := pg.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if events[len(events)-1].Hash != head {
		t.Errorf("ReadChain head %q != postgres chain head %q", events[len(events)-1].Hash, head)
	}
}
