package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// seedAuditStore writes n hash-chained events into the postgres audit
// store at cfg.DSN (migrating via the WRITABLE constructor — test code is
// allowed to; the read-only opener never is), then returns a fresh
// read-only handle for the assertions.
func seedAuditStore(t *testing.T, cfg Config, n int) {
	t.Helper()
	ctx := context.Background()
	s, err := NewAuditSink(cfg) // writable path: migrates (test setup only)
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, "TRUNCATE audit_events"); err != nil {
		_ = s.Close()
		t.Fatalf("truncate audit_events: %v", err)
	}
	rec := audit.New(s, audit.WithHashChain())
	for i := range n {
		rec.Record(ctx, &audit.Event{
			ID:      "evt-" + string(rune('a'+i)),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
			ActorID: "user",
		})
	}
	_ = s.Close()
}

// TestOpenAuditReadOnly_PagesNewestFirst (REQ-2 criterion 1): the opener
// returns a QueryPager whose Query pages newest-first with Limit/Offset
// identical to the live store rows.
func TestOpenAuditReadOnly_PagesNewestFirst(t *testing.T) {
	cfg := testConfig(t) // skips without SSO_TEST_POSTGRES_DSN
	seedAuditStore(t, cfg, 7)

	s, err := OpenAuditReadOnly(cfg)
	if err != nil {
		t.Fatalf("OpenAuditReadOnly: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// First page: the 3 newest events.
	page1, err := s.Query(ctx, audit.Query{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("Query page1: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 len=%d, want 3", len(page1))
	}
	// Second page continues newest-first with no overlap.
	page2, err := s.Query(ctx, audit.Query{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatalf("Query page2: %v", err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2 len=%d, want 3", len(page2))
	}
	seen := map[string]bool{}
	for _, e := range append(append([]*audit.Event{}, page1...), page2...) {
		if seen[e.ID] {
			t.Fatalf("duplicate event across pages: %s", e.ID)
		}
		seen[e.ID] = true
	}
	// Ordering matches the sink's own newest-first semantics: the live
	// store's first row (LastHash query order) is page1[0].
	head, err := s.LastHash(ctx)
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if page1[0].Hash != head {
		t.Errorf("page1[0].Hash=%q != chain head %q (must be newest-first)", page1[0].Hash, head)
	}
}

// TestOpenAuditReadOnly_ChainVerify (REQ-2 criteria 1+3 / A1 for the
// store leg): events paged through the read-only opener assemble into a
// chain audit.VerifyChain accepts; after one row's hash is flipped the
// chain breaks.
func TestOpenAuditReadOnly_ChainVerify(t *testing.T) {
	cfg := testConfig(t)
	seedAuditStore(t, cfg, 5)

	s, err := OpenAuditReadOnly(cfg)
	if err != nil {
		t.Fatalf("OpenAuditReadOnly: %v", err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	all, err := s.Query(ctx, audit.Query{Limit: 1000})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// newest-first from the store; reverse into chain order.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if err := audit.VerifyChain(all); err != nil {
		t.Fatalf("clean chain must verify: %v", err)
	}

	// Flip one hash (write path — test setup; the read-only opener still
	// only reads).
	w, err := NewAuditSink(cfg)
	if err != nil {
		t.Fatalf("open writable: %v", err)
	}
	if _, err := w.db.ExecContext(ctx, "UPDATE audit_events SET hash = 'deadbeef' WHERE id = 'evt-c'"); err != nil {
		_ = w.Close()
		t.Fatalf("flip hash: %v", err)
	}
	_ = w.Close()

	all, err = s.Query(ctx, audit.Query{Limit: 1000})
	if err != nil {
		t.Fatalf("Query after flip: %v", err)
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if err := audit.VerifyChain(all); err == nil {
		t.Error("flipped hash must break the chain")
	}
}

// TestOpenAuditReadOnly_SchemaMismatchFailsClosed (REQ-2 criterion 2 /
// REQ-1 criterion 2): a store whose schema_migrations_audit version is
// behind the binary fails with a found-vs-expected diagnostic and zero
// DDL executed.
func TestOpenAuditReadOnly_SchemaMismatchFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	seedAuditStore(t, cfg, 2)

	// Rewind the recorded version to 0 (delete the row) — the binary
	// expects v2 for the audit namespace.
	w, err := NewAuditSink(cfg)
	if err != nil {
		t.Fatalf("open writable: %v", err)
	}
	if _, err := w.db.ExecContext(context.Background(), "DELETE FROM schema_migrations_audit"); err != nil {
		_ = w.Close()
		t.Fatalf("rewind version: %v", err)
	}
	_ = w.Close()

	_, err = OpenAuditReadOnly(cfg)
	if err == nil {
		t.Fatal("OpenAuditReadOnly must fail closed on a version mismatch")
	}
	msg := err.Error()
	if !strings.Contains(msg, "schema version mismatch") || !strings.Contains(msg, "v0") || !strings.Contains(msg, "v2") {
		t.Errorf("diagnostic must name found vs expected version: %v", msg)
	}
	// The version table must still be empty — the opener never ran DDL.
	probe, err := Open(cfg) // raw pool: dial/ping only, never migrates
	if err != nil {
		t.Fatalf("open probe: %v", err)
	}
	defer func() { _ = probe.Close() }()
	var n int
	if err := probe.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM schema_migrations_audit").Scan(&n); err != nil {
		t.Fatalf("count version rows: %v", err)
	}
	if n != 0 {
		t.Errorf("version table has %d rows after a failed read-only open, want 0 (no DDL)", n)
	}
}

// TestOpenAuditReadOnly_EmptyStoreMatchesLastHash: on an empty store the
// opener succeeds (version matches) and the chain head is genesis.
func TestOpenAuditReadOnly_EmptyStoreMatchesLastHash(t *testing.T) {
	cfg := testConfig(t)
	seedAuditStore(t, cfg, 0)

	s, err := OpenAuditReadOnly(cfg)
	if err != nil {
		t.Fatalf("OpenAuditReadOnly: %v", err)
	}
	defer func() { _ = s.Close() }()
	events, err := s.Query(context.Background(), audit.Query{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("empty store returned %d events", len(events))
	}
	head, err := s.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if head != audit.GenesisHash {
		t.Errorf("empty store head=%q, want genesis", head)
	}
}
