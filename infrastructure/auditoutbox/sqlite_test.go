package auditoutbox

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/audit"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// newWiredPair builds the B4-5 wiring on one temp sqlite file: the audit
// sink with the outbox store as its same-transaction appender, plus a
// chain-stamping recorder. reader is a second handle on the same file
// (no appender) used to prove rows are durably committed. Both stores
// share the file; the outbox runs its own schema namespace.
func newWiredPair(t *testing.T) (reader, sink *auditsqlite.Sink, outbox *SQLiteOutboxStore, rec *audit.Recorder) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "governance.db")
	reader, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("audit sink: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	outbox, err = NewSQLiteOutboxStore(dsn)
	if err != nil {
		t.Fatalf("outbox store: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	sink, err = auditsqlite.New(dsn, auditsqlite.WithTxAppender(outbox))
	if err != nil {
		t.Fatalf("audit sink with appender: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	rec = audit.New(sink, audit.WithHashChain())
	return reader, sink, outbox, rec
}

// TestSQLiteOutboxStore_InTxAppend proves the core B4-5 contract: a
// login-failure audit record commits its outbox fact in the SAME
// transaction (both rows visible to a fresh connection immediately), and
// the fact carries the chain hash linkage.
func TestSQLiteOutboxStore_InTxAppend(t *testing.T) {
	reader, _, outbox, rec := newWiredPair(t)
	ctx := context.Background()
	rec.Record(ctx, &audit.Event{
		ID: "lf-1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: time.Now().UTC(), TenantID: "tenant-1", ClientID: "client-1",
		Reason: "invalid_credentials",
	})

	pending, err := outbox.Pending(ctx)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("facts: got %d want 1 (fact must commit with the audit row)", len(pending))
	}
	fact := pending[0]
	if fact.TenantID != "tenant-1" || fact.Payload[PayloadKeyReason] != "invalid_credentials" {
		t.Errorf("fact projection: %+v", fact)
	}
	// Chain linkage: the fact's audit_hash equals the persisted event's Hash.
	ev, err := reader.Get(ctx, "lf-1")
	if err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if fact.Payload[PayloadKeyAuditHash] != ev.Hash || ev.Hash == "" {
		t.Errorf("audit_hash linkage: fact=%q event hash=%q", fact.Payload[PayloadKeyAuditHash], ev.Hash)
	}
}

// TestSQLiteOutboxStore_NonPermittedClassNoFact proves the sqlite path
// applies the same fail-closed class gate: only login_failure writes a
// fact row, other classes only write the audit row.
func TestSQLiteOutboxStore_NonPermittedClassNoFact(t *testing.T) {
	_, sink, outbox, rec := newWiredPair(t)
	rec.Record(context.Background(), &audit.Event{
		ID: "ok-1", Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(), TenantID: "tenant-1",
	})
	pending, err := outbox.Pending(context.Background())
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("facts for non-permitted class: %+v", pending)
	}
	if _, err := sink.Get(context.Background(), "ok-1"); err != nil {
		t.Errorf("audit row missing: %v", err)
	}
}

// TestSQLiteOutboxStore_ClaimCompleteRoundTrip drives the relay
// lifecycle over the durable store, including the single-delivery
// guarantee and lease-lost protection.
func TestSQLiteOutboxStore_ClaimCompleteRoundTrip(t *testing.T) {
	_, _, outbox, rec := newWiredPair(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rec.Record(ctx, &audit.Event{
		ID: "lf-2", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: now, TenantID: "tenant-1", Reason: "bad_password",
	})

	claimed, err := outbox.ClaimOutbox(ctx, "relay-1", now, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != "lf-2" {
		t.Fatalf("claimed: %+v", claimed)
	}
	// A second owner cannot complete someone else's lease.
	if err := outbox.CompleteOutbox(ctx, "lf-2", "relay-2", now); !errors.Is(err, commerce.ErrOutboxLeaseLost) {
		t.Fatalf("foreign complete: err=%v want ErrOutboxLeaseLost", err)
	}
	if err := outbox.CompleteOutbox(ctx, "lf-2", "relay-1", now); err != nil {
		t.Fatalf("complete: %v", err)
	}
	again, err := outbox.ClaimOutbox(ctx, "relay-1", now.Add(time.Hour), time.Minute, 10)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("delivered fact re-claimed: %+v", again)
	}
}

// TestSQLiteOutboxStore_FailDeadReplay covers the retry/dead/replay
// transitions the relay's bounded-retry policy relies on.
func TestSQLiteOutboxStore_FailDeadReplay(t *testing.T) {
	_, _, outbox, rec := newWiredPair(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rec.Record(ctx, &audit.Event{
		ID: "lf-3", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: now, TenantID: "tenant-1",
	})
	claimed, err := outbox.ClaimOutbox(ctx, "relay-1", now, time.Minute, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %+v", err, claimed)
	}
	if err := outbox.FailOutbox(ctx, "lf-3", "relay-1", "transport", now, now.Add(time.Minute), 3); err != nil {
		t.Fatalf("fail: %v", err)
	}
	// Back to pending (attempts < max) after the backoff window: reclaimable.
	reclaimed, err := outbox.ClaimOutbox(ctx, "relay-1", now.Add(2*time.Minute), time.Minute, 10)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim after fail: %v %+v", err, reclaimed)
	}
	// Exhaust attempts -> dead.
	if err := outbox.FailOutbox(ctx, "lf-3", "relay-1", "transport", now, now, 1); err != nil {
		t.Fatalf("fail to dead: %v", err)
	}
	dead, err := outbox.ListDeadOutbox(ctx, 10)
	if err != nil || len(dead) != 1 || dead[0].Status != commerce.OutboxDead {
		t.Fatalf("dead: %v %+v", err, dead)
	}
	if err := outbox.ReplayOutbox(ctx, "lf-3", now); err != nil {
		t.Fatalf("replay: %v", err)
	}
	final, err := outbox.ClaimOutbox(ctx, "relay-1", now, time.Minute, 10)
	if err != nil || len(final) != 1 {
		t.Fatalf("replay reclaim: %v %+v", err, final)
	}
}
