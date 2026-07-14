package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth/oauthspi"
)

func newCIBAPushDeadLetterStoreForTest(t *testing.T, dsn string) *CIBAPushDeadLetterStore {
	t.Helper()
	s, err := NewCIBAPushDeadLetterStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAPushDeadLetterStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testDeadLetterDSN(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return "file:" + filepath.Join(dir, "ciba_deadletter.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
}

func samplePushPayload(authReqID string) oauthspi.PushPayload {
	return oauthspi.PushPayload{
		AuthReqID:    authReqID,
		AccessToken:  "at-" + authReqID,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "rt-" + authReqID,
		IDToken:      "idt-" + authReqID,
	}
}

// TestCIBAPushDeadLetterStore_RecordAndReplayRoundTrip proves Record
// persists the full push payload and Replay returns it verbatim, so an
// operator's replay tooling gets exactly what NotifyPush tried (and
// failed) to deliver.
func TestCIBAPushDeadLetterStore_RecordAndReplayRoundTrip(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	ctx := context.Background()

	payload := samplePushPayload("areq-1")
	if err := s.Record(ctx, "dl-1", payload, errors.New("connection refused")); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := s.Replay(ctx, "dl-1")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if *got != payload {
		t.Fatalf("Replay mismatch: got %+v, want %+v", *got, payload)
	}
}

// TestCIBAPushDeadLetterStore_RecordNilErrorAllowed proves Record tolerates
// a nil delivery error (defensive — the interface signature accepts one
// but a caller might record without a captured error).
func TestCIBAPushDeadLetterStore_RecordNilErrorAllowed(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	ctx := context.Background()
	if err := s.Record(ctx, "dl-nilerr", samplePushPayload("areq-nilerr"), nil); err != nil {
		t.Fatalf("Record with nil error: %v", err)
	}
	if _, err := s.Replay(ctx, "dl-nilerr"); err != nil {
		t.Fatalf("Replay: %v", err)
	}
}

// TestCIBAPushDeadLetterStore_RecordEmptyDeliveryIDMintsID mirrors the
// in-memory peer's defensive fallback: an empty deliveryID still
// produces a retrievable entry rather than silently failing.
func TestCIBAPushDeadLetterStore_RecordEmptyDeliveryIDMintsID(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	ctx := context.Background()
	if err := s.Record(ctx, "", samplePushPayload("areq-auto"), errors.New("boom")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	ids, err := s.ListUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("want exactly one non-empty minted id, got %v", ids)
	}
}

// TestCIBAPushDeadLetterStore_RecordOverwritesAndResetsAcked proves a
// re-Record of the same deliveryID (e.g. a second failed push for the
// same auth_req_id) overwrites the prior entry AND resets Acked — a
// fresh failure means a fresh replay is owed, mirroring the in-memory
// peer's unconditional map overwrite.
func TestCIBAPushDeadLetterStore_RecordOverwritesAndResetsAcked(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	ctx := context.Background()

	if err := s.Record(ctx, "dl-dup", samplePushPayload("areq-v1"), errors.New("e1")); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if err := s.Acknowledge(ctx, "dl-dup"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	// Re-record under the same id with a different payload.
	if err := s.Record(ctx, "dl-dup", samplePushPayload("areq-v2"), errors.New("e2")); err != nil {
		t.Fatalf("second Record: %v", err)
	}
	got, err := s.Replay(ctx, "dl-dup")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got.AuthReqID != "areq-v2" {
		t.Fatalf("payload not overwritten: got %+v", *got)
	}
	ids, err := s.ListUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(ids) != 1 || ids[0] != "dl-dup" {
		t.Fatalf("re-recorded entry should be unacknowledged again, got %v", ids)
	}
}

// TestCIBAPushDeadLetterStore_ListUnacknowledgedOrderingAndAcknowledge
// proves ListUnacknowledged returns oldest-failure-first (so an
// operator's replay loop drains in FIFO order) and that Acknowledge
// removes an entry from the unacknowledged set without deleting it
// (Replay must still work after Acknowledge).
func TestCIBAPushDeadLetterStore_ListUnacknowledgedOrderingAndAcknowledge(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	ctx := context.Background()

	if err := s.Record(ctx, "dl-a", samplePushPayload("areq-a"), errors.New("e")); err != nil {
		t.Fatalf("Record a: %v", err)
	}
	time.Sleep(2 * time.Millisecond) // ensure distinct created_at ordering
	if err := s.Record(ctx, "dl-b", samplePushPayload("areq-b"), errors.New("e")); err != nil {
		t.Fatalf("Record b: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := s.Record(ctx, "dl-c", samplePushPayload("areq-c"), errors.New("e")); err != nil {
		t.Fatalf("Record c: %v", err)
	}

	ids, err := s.ListUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(ids) != 3 || ids[0] != "dl-a" || ids[1] != "dl-b" || ids[2] != "dl-c" {
		t.Fatalf("want [dl-a dl-b dl-c] oldest-first, got %v", ids)
	}

	if err := s.Acknowledge(ctx, "dl-b"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	ids, err = s.ListUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("ListUnacknowledged after ack: %v", err)
	}
	if len(ids) != 2 || ids[0] != "dl-a" || ids[1] != "dl-c" {
		t.Fatalf("want [dl-a dl-c] after acking dl-b, got %v", ids)
	}

	// Acknowledged entries stay Replay-able (Acknowledge marks resolved,
	// it does not delete — an operator can still audit what was sent).
	if _, err := s.Replay(ctx, "dl-b"); err != nil {
		t.Fatalf("Replay after Acknowledge should still succeed: %v", err)
	}
}

// TestCIBAPushDeadLetterStore_ReplayMissingReturnsError proves an
// unknown deliveryID surfaces as an error (not a silent zero-value)
// so operator tooling can distinguish "nothing to replay" from
// "replayed empty payload".
func TestCIBAPushDeadLetterStore_ReplayMissingReturnsError(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	if _, err := s.Replay(context.Background(), "ghost"); err == nil {
		t.Fatal("Replay of missing id: want error, got nil")
	}
}

// TestCIBAPushDeadLetterStore_AcknowledgeMissingReturnsError proves
// Acknowledge on an unknown id errors rather than silently no-op'ing,
// so a caller can tell a real acknowledgment from a typo'd id.
func TestCIBAPushDeadLetterStore_AcknowledgeMissingReturnsError(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	if err := s.Acknowledge(context.Background(), "ghost"); err == nil {
		t.Fatal("Acknowledge of missing id: want error, got nil")
	}
}

// TestCIBAPushDeadLetterStore_PersistsAcrossReopen is the whole point of a
// SQLite peer over the in-memory one: entries recorded before a restart
// must still be there (and still repliable) after the process reopens
// the same DB file — the operator's dead-letter visibility must survive
// a restart, unlike the in-memory store.
func TestCIBAPushDeadLetterStore_PersistsAcrossReopen(t *testing.T) {
	t.Parallel()
	dsn := testDeadLetterDSN(t)

	first, err := NewCIBAPushDeadLetterStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAPushDeadLetterStore (first): %v", err)
	}
	ctx := context.Background()
	payload := samplePushPayload("areq-restart")
	if err := first.Record(ctx, "dl-restart", payload, errors.New("network unreachable")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the SAME file — simulates the process restarting with the
	// dead-letter queue as its only surviving record of the failure.
	second, err := NewCIBAPushDeadLetterStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAPushDeadLetterStore (reopen): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	ids, err := second.ListUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("ListUnacknowledged after reopen: %v", err)
	}
	if len(ids) != 1 || ids[0] != "dl-restart" {
		t.Fatalf("entry lost across reopen: got %v", ids)
	}
	got, err := second.Replay(ctx, "dl-restart")
	if err != nil {
		t.Fatalf("Replay after reopen: %v", err)
	}
	if *got != payload {
		t.Fatalf("payload not preserved across reopen: got %+v, want %+v", *got, payload)
	}
	if err := second.Acknowledge(ctx, "dl-restart"); err != nil {
		t.Fatalf("Acknowledge after reopen: %v", err)
	}
}

// TestCIBAPushDeadLetterStore_NewWithDBSharesConnection proves the
// WithDB constructor wires the same schema onto a caller-supplied
// *sql.DB, matching the sibling stores' shared-pool convention (a
// single-DSN deployment where every store shares one connection pool).
func TestCIBAPushDeadLetterStore_NewWithDBSharesConnection(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	s, err := NewCIBAPushDeadLetterStoreWithDB(db)
	if err != nil {
		t.Fatalf("NewCIBAPushDeadLetterStoreWithDB: %v", err)
	}
	if s.DB() != db {
		t.Fatal("WithDB store should reuse the supplied *sql.DB")
	}
	if err := s.Record(context.Background(), "dl-shared", samplePushPayload("areq-shared"), errors.New("e")); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// TestCIBAPushDeadLetterStore_PingAfterCloseErrors mirrors the
// sibling stores' Ping-after-Close convention (PushApprovalStore,
// CIBAStore): callers wiring [sso.WithReadyCheck] must see a closed
// store report unhealthy rather than panic.
func TestCIBAPushDeadLetterStore_PingAfterCloseErrors(t *testing.T) {
	t.Parallel()
	s := newCIBAPushDeadLetterStoreForTest(t, testDeadLetterDSN(t))
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping after Close: want error, got nil")
	}
	// Close is idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
