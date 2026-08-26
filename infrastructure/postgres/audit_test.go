package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// freshAuditSink opens a writable audit sink and TRUNCATEs the shared
// audit_events table. Callers must NOT run in parallel: a concurrent
// TRUNCATE (or a parallel peer's assertions) would wipe or leak rows on
// the same table, so every test in this file runs sequentially.
func freshAuditSink(t *testing.T) *AuditSink {
	t.Helper()
	s, err := NewAuditSink(testConfig(t))
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestAudit_CheckpointStoreRoundTrip(t *testing.T) {
	s := freshAuditSink(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, "TRUNCATE audit_checkpoints"); err != nil {
		t.Fatalf("truncate audit_checkpoints: %v", err)
	}
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := signedAuditCheckpoint(t, signer, 4, time.Unix(1700000300, 123).UTC(), "head-4", "head-3")
	if err := s.Append(ctx, checkpoint); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := s.Latest(ctx)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if !audit.CheckpointEqual(got, checkpoint) || !bytes.Equal(got.Signature, checkpoint.Signature) || !bytes.Equal(got.SignerKey, checkpoint.SignerKey) {
		t.Fatalf("checkpoint round-trip changed data: got=%+v want=%+v", got, checkpoint)
	}
	list, err := s.List(ctx, checkpoint.Checkpoint.Timestamp, 1)
	if err != nil || len(list) != 1 || list[0].Checkpoint.Sequence != checkpoint.Checkpoint.Sequence {
		t.Fatalf("List = (%v, %v), want checkpoint sequence %d", list, err, checkpoint.Checkpoint.Sequence)
	}
}

func signedAuditCheckpoint(t *testing.T, signer audit.CheckpointSigner, sequence int64, timestamp time.Time, head, previous string) *audit.SignedCheckpoint {
	t.Helper()
	checkpoint := audit.Checkpoint{Sequence: sequence, Timestamp: timestamp, HeadHash: head, PrevHash: previous}
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}
	signature, err := signer.Sign(raw)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	return &audit.SignedCheckpoint{Checkpoint: checkpoint, Signature: signature, SignerKey: signer.PublicKey()}
}

func TestAudit_RecordGetQuery(t *testing.T) {
	s := freshAuditSink(t)
	ctx := context.Background()
	base := time.Now().UTC()

	ev := &audit.Event{
		Type: "login", Outcome: "success", Timestamp: base,
		ActorID: "alice", ClientID: "c1", TenantID: "t1", RequestID: "req-1",
		Metadata: map[string]string{"ip": "1.2.3.4"}, PrevHash: "g", Hash: "h1",
		ServerVersion: "v1.2.3",
	}
	if err := s.Record(ctx, ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if ev.ID == "" {
		t.Fatal("Record must fill an empty ID")
	}
	got, err := s.Get(ctx, ev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ActorID != "alice" || got.Metadata["ip"] != "1.2.3.4" || got.Hash != "h1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	// Regression guard: ServerVersion (audit.WithServerVersion) must survive
	// the round trip — it was previously dropped entirely by this backend's
	// schema/insert/scan (no column at all), the same shape already fixed for
	// the sqlite peer's migrationV3.
	if got.ServerVersion != "v1.2.3" {
		t.Fatalf("ServerVersion round-trip lost: got %q, want %q", got.ServerVersion, "v1.2.3")
	}
	if got.Timestamp.UnixNano() != base.UnixNano() {
		t.Fatalf("nanosecond round-trip lost: got %d want %d", got.Timestamp.UnixNano(), base.UnixNano())
	}
	// Missing → ErrEventNotFound.
	if _, err := s.Get(ctx, "nope"); err != audit.ErrEventNotFound {
		t.Fatalf("Get(missing) = %v, want ErrEventNotFound", err)
	}
}

func TestAudit_QueryFilterOrderAndFacets(t *testing.T) {
	s := freshAuditSink(t)
	ctx := context.Background()
	base := time.Now().UTC()
	mk := func(i int, typ, outcome, client string) *audit.Event {
		return &audit.Event{Type: audit.EventType(typ), Outcome: audit.Outcome(outcome),
			Timestamp: base.Add(time.Duration(i) * time.Second), ClientID: client, ActorID: "a"}
	}
	evs := []*audit.Event{
		mk(0, "login", "success", "c1"),
		mk(1, "login", "failure", "c1"),
		mk(2, "token", "success", "c2"),
	}
	if err := s.RecordBatch(ctx, evs); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}

	// Filter by type=login → 2, newest-first.
	logins, err := s.Query(ctx, audit.Query{Type: "login"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(logins) != 2 || logins[0].Outcome != "failure" {
		t.Fatalf("Query(type=login) = %d events, newest=%v; want 2 newest-first", len(logins), logins[0].Outcome)
	}

	// Facets over the whole set.
	f, err := s.Facets(ctx, audit.Query{})
	if err != nil {
		t.Fatalf("Facets: %v", err)
	}
	if f.Total != 3 || f.Outcomes["success"] != 2 || f.Types["login"] != 2 || f.Clients["c1"] != 2 {
		t.Fatalf("Facets mismatch: %+v", f)
	}
}

func TestAudit_PruneAndLastHash(t *testing.T) {
	s := freshAuditSink(t)
	ctx := context.Background()
	base := time.Now().UTC()

	// LastHash on empty table → "".
	if h, err := s.LastHash(ctx); err != nil || h != "" {
		t.Fatalf("LastHash(empty) = (%q, %v), want (\"\", nil)", h, err)
	}

	old := &audit.Event{Type: "x", Outcome: "success", Timestamp: base.Add(-2 * time.Hour), Hash: "old"}
	recent := &audit.Event{Type: "x", Outcome: "success", Timestamp: base, Hash: "recent"}
	if err := s.RecordBatch(ctx, []*audit.Event{old, recent}); err != nil {
		t.Fatalf("RecordBatch: %v", err)
	}

	// LastHash returns the most-recent event's hash (ts DESC, seq DESC tie-break).
	if h, err := s.LastHash(ctx); err != nil || h != "recent" {
		t.Fatalf("LastHash = (%q, %v), want (\"recent\", nil)", h, err)
	}

	// Prune everything older than 1h ago → removes the old one only.
	n, err := s.Prune(ctx, base.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("Prune removed %d, want 1", n)
	}
	remaining, _ := s.Query(ctx, audit.Query{})
	if len(remaining) != 1 || remaining[0].Hash != "recent" {
		t.Fatalf("after prune: %d events, want 1 (recent)", len(remaining))
	}
	// Zero time is a no-op.
	if n, err := s.Prune(ctx, time.Time{}); err != nil || n != 0 {
		t.Fatalf("Prune(zero) = (%d, %v), want (0, nil)", n, err)
	}
}
