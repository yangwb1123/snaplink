package auditverify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pgbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/audit"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// seedDSNSQLite writes n hash-chained events (stock Recorder +
// WithHashChain → sqlite.Sink) into a fresh store at dsn and closes it,
// leaving a durable chain for the CLI's --dsn mode.
func seedDSNSQLite(t *testing.T, dsn string, n int) {
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

// storeHead returns the newest event's hash (the chain head) from the
// store at dsn, matching what the CLI must print as head=.
func storeHead(t *testing.T, dsn string) string {
	t.Helper()
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = sink.Close() }()
	events, err := sink.Query(context.Background(), audit.Query{Limit: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) == 0 {
		return ""
	}
	return events[0].Hash // newest-first
}

// storeEvents loads every row through the sink's QueryPager in chain
// order (the same reader the CLI drives) for byte-consistency asserts.
func storeEvents(t *testing.T, dsn string) []*audit.Event {
	t.Helper()
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = sink.Close() }()
	events, err := sink.Query(context.Background(), audit.Query{Limit: 10000})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events
}

// TestRun_DSN_CleanChain (REQ-1 criterion 1): --dsn over a stock-written
// sqlite store exits 0 and prints exactly
// "chain verified: N event(s), head=<H>" with H the last stored row's hash.
func TestRun_DSN_CleanChain(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 5)

	code, out, _ := runVerify(t, "--dsn", dsn)
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	want := fmt.Sprintf("chain verified: 5 event(s), head=%s", storeHead(t, dsn))
	if out != want {
		t.Errorf("stdout:\n got %q\nwant %q", out, want)
	}
}

// TestRun_DSN_EmptyStore exits 0 with the legacy empty-store line.
func TestRun_DSN_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "empty.db")
	seedDSNSQLite(t, dsn, 0)

	code, out, _ := runVerify(t, "--dsn", dsn)
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	if out != "no events to verify" {
		t.Errorf("stdout %q, want %q", out, "no events to verify")
	}
}

// TestRun_DSN_FlippedHash (REQ-1 criterion 2 / A1): one row's hash
// overwritten → exit 1 and "chain BROKEN" on stderr, no other change.
func TestRun_DSN_FlippedHash(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 5)
	flipHash(t, dsn, "evt-c")

	code, out, errOut := runVerify(t, "--dsn", dsn)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if !strings.Contains(errOut, "chain BROKEN") {
		t.Errorf("stderr missing chain BROKEN:\n%s", errOut)
	}
	if out != "" {
		t.Errorf("stdout must be empty on a broken chain, got %q", out)
	}
}

// TestRun_DSN_ByteConsistency (REQ-1 criterion 3 / A2): over the same
// rows, the CLI exit equals 0 iff audit.VerifyChain returns nil, and the
// printed head equals events[len-1].Hash.
func TestRun_DSN_ByteConsistency(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(t *testing.T, dsn string)
	}{
		{"clean", nil},
		{"flipped", func(t *testing.T, dsn string) { flipHash(t, dsn, "evt-b") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dsn := filepath.Join(dir, "audit.db")
			seedDSNSQLite(t, dsn, 6)
			if tc.mut != nil {
				tc.mut(t, dsn)
			}
			code, out, _ := runVerify(t, "--dsn", dsn)
			events := storeEvents(t, dsn)
			verifyErr := audit.VerifyChain(events)
			if (code == 0) != (verifyErr == nil) {
				t.Errorf("CLI exit=%d but VerifyChain err=%v over the same rows", code, verifyErr)
			}
			if verifyErr == nil {
				want := fmt.Sprintf("chain verified: 6 event(s), head=%s", events[len(events)-1].Hash)
				if out != want {
					t.Errorf("stdout %q, want %q", out, want)
				}
			}
		})
	}
}

// TestRun_DSN_TruncationHonesty (REQ-1 criterion 5): --limit 5 over a
// 10-event store prints the prefix-verified line and exits 1; with
// --checkpoint added it fails fast with the truncation message and no
// chain-verified output.
func TestRun_DSN_TruncationHonesty(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 10)

	code, out, errOut := runVerify(t, "--dsn", dsn, "--limit", "5")
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (prefix not the full chain)", code)
	}
	if !strings.Contains(out, "prefix verified: 5 event(s) — truncated by --limit 5") {
		t.Errorf("stdout missing honest truncation line:\n%q", out)
	}
	if !strings.Contains(out, "head=") {
		t.Errorf("stdout must still name the prefix head:\n%q", out)
	}
	if strings.Contains(errOut, "chain BROKEN") {
		t.Errorf("a verified prefix must not print chain BROKEN:\n%s", errOut)
	}

	// Checkpoint-anchored: fail fast BEFORE any verification output.
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	head := storeHead(t, dsn)
	cp := signedCheckpoint(t, signer, 3, head)
	cpPath := filepath.Join(t.TempDir(), "cp.json")
	writeCheckpoint(t, cpPath, cp)

	code, out, errOut = runVerify(t, "--dsn", dsn, "--limit", "5", "--checkpoint", cpPath)
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (truncated before the attested head)", code)
	}
	if !strings.Contains(errOut, "truncated by --limit 5") {
		t.Errorf("stderr missing fail-fast truncation message:\n%s", errOut)
	}
	if strings.Contains(out, "chain verified") {
		t.Errorf("anchored run must not print chain verified:\n%q", out)
	}
}

// TestRun_DSN_ExactFillNotTruncated pins the probe: an exact --limit
// fill over a store with exactly that many rows is NOT truncation.
func TestRun_DSN_ExactFillNotTruncated(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 10)

	code, out, _ := runVerify(t, "--dsn", dsn, "--limit", "10")
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (exact fill is not truncation)", code)
	}
	if !strings.Contains(out, "chain verified: 10 event(s)") {
		t.Errorf("stdout %q, want full-chain verified line", out)
	}
}

// TestRun_DSN_Misuse (REQ-1 criterion 4): --dsn with --from-file,
// --from-url, or --bearer is exit-2 CLI misuse with a diagnostic.
func TestRun_DSN_Misuse(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 2)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"with-from-file", []string{"--dsn", dsn, "--from-file", "x.json"}, "mutually exclusive"},
		{"with-from-url", []string{"--dsn", dsn, "--from-url", "https://x"}, "mutually exclusive"},
		{"with-bearer", []string{"--dsn", dsn, "--bearer", "t"}, "not applicable with --dsn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runVerify(t, tc.args...)
			if code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, errOut)
			}
		})
	}
}

// TestRun_DSN_SchemaMismatch (REQ-1 criterion 6): a store whose schema
// version does not match the binary exits 1 with a schema diagnostic and
// no verification output.
func TestRun_DSN_SchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 3)

	db, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open store for tamper: %v", err)
	}
	if _, err := db.DB().ExecContext(context.Background(),
		"UPDATE schema_migrations_audit SET version = 99 WHERE version = 1"); err != nil {
		t.Fatalf("rewrite version: %v", err)
	}
	_ = db.Close()

	code, out, errOut := runVerify(t, "--dsn", dsn)
	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if !strings.Contains(errOut, "schema version mismatch") {
		t.Errorf("stderr missing schema diagnostic:\n%s", errOut)
	}
	if out != "" {
		t.Errorf("no verification output on a schema mismatch, got %q", out)
	}
}

// TestRun_DSN_AnchorHashFailsClosed composes the --anchor-hash segment
// path with the DSN source (A3 — anchored verification is source-
// agnostic): the DSN reader returns the full chain from genesis, so a
// non-genesis boundary anchor is inconsistent with the rows and the
// segment check fails closed. The genesis anchor is expressed by
// OMITTING the flag (checkMisuse rejects an explicit empty value).
func TestRun_DSN_AnchorHashFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedDSNSQLite(t, dsn, 5)

	events := storeEvents(t, dsn)
	anchor := events[1].PrevHash // a mid-chain boundary the full read cannot satisfy
	code, out, errOut := runVerify(t, "--dsn", dsn, "--anchor-hash", anchor)
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (segment start does not match the full chain)", code)
	}
	if !strings.Contains(errOut, "chain BROKEN") {
		t.Errorf("stderr missing chain BROKEN:\n%s", errOut)
	}
	if out != "" {
		t.Errorf("no stdout on a failed segment, got %q", out)
	}
}

func flipHash(t *testing.T, dsn, id string) {
	t.Helper()
	db, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open store for tamper: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.DB().ExecContext(context.Background(),
		"UPDATE audit_events SET hash = 'deadbeef' WHERE id = ?", id); err != nil {
		t.Fatalf("flip hash: %v", err)
	}
}

// TestRun_DSN_Postgres (REQ-2 criteria 1-3): the clean / flipped /
// byte-consistency behavior holds verbatim against a postgres store under
// SSO_TEST_POSTGRES_DSN (repo skip convention); the dialect classifier and
// misuse cases already run everywhere without a live DB.
func TestRun_DSN_Postgres(t *testing.T) {
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres audit-verify --dsn test")
	}
	pg, err := pgbackend.NewAuditSink(pgbackend.Config{DSN: dsn}) // writable: test setup migrates
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	defer func() { _ = pg.Close() }()
	if _, err := pg.DB().ExecContext(context.Background(), "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}
	rec := audit.New(pg, audit.WithHashChain())
	for i := range 6 {
		rec.Record(context.Background(), &audit.Event{
			ID:      "pevt-" + string(rune('a'+i)),
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
		})
	}

	// Clean chain: exit 0, head matches the store chain head.
	code, out, _ := runVerify(t, "--dsn", dsn)
	if code != 0 {
		t.Fatalf("clean postgres exit=%d, want 0", code)
	}
	head, err := pg.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	want := fmt.Sprintf("chain verified: 6 event(s), head=%s", head)
	if out != want {
		t.Errorf("stdout %q, want %q", out, want)
	}

	// Flipped hash: exit 1 + chain BROKEN.
	if _, err := pg.DB().ExecContext(context.Background(),
		"UPDATE audit_events SET hash = 'deadbeef' WHERE id = 'pevt-c'"); err != nil {
		t.Fatalf("flip hash: %v", err)
	}
	code, out, errOut := runVerify(t, "--dsn", dsn)
	if code != 1 {
		t.Fatalf("flipped postgres exit=%d, want 1", code)
	}
	if !strings.Contains(errOut, "chain BROKEN") {
		t.Errorf("stderr missing chain BROKEN:\n%s", errOut)
	}
	if out != "" {
		t.Errorf("stdout must be empty on a broken chain, got %q", out)
	}
}
