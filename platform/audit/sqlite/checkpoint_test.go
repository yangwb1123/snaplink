package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

func TestCheckpointStore_MigrationCreatesIndependentTable(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	ctx := context.Background()

	var eventTables, checkpointTables int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'`).Scan(&eventTables); err != nil {
		t.Fatalf("audit_events probe: %v", err)
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'audit_checkpoints'`).Scan(&checkpointTables); err != nil {
		t.Fatalf("audit_checkpoints probe: %v", err)
	}
	if eventTables != 1 || checkpointTables != 1 {
		t.Fatalf("tables = events:%d checkpoints:%d, want one of each", eventTables, checkpointTables)
	}

	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(audit_checkpoints)`)
	if err != nil {
		t.Fatalf("checkpoint columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := make([]string, 0, 6)
	for rows.Next() {
		var cid int
		var name, typ string
		var defaultValue any
		var notNull, primaryKey int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("checkpoint column scan: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("checkpoint columns rows: %v", err)
	}
	want := []string{"sequence", "ts_unix_ns", "head_hash", "prev_hash", "signature", "signer_key"}
	if len(got) != len(want) {
		t.Fatalf("checkpoint columns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("checkpoint column %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCheckpointStore_AppendLatestRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	want := signedCheckpointFixture(t, signer, 7, time.Unix(1700000000, 123).UTC(), "head-7", "head-6")
	if err := s.Append(context.Background(), want); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := s.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if !audit.CheckpointEqual(got, want) {
		t.Fatalf("checkpoint round-trip differs: got=%+v want=%+v", got, want)
	}
	if !bytes.Equal(got.Signature, want.Signature) || !bytes.Equal(got.SignerKey, want.SignerKey) {
		t.Fatalf("signature/key bytes changed: got signature=%x key=%x", got.Signature, got.SignerKey)
	}
	if err := audit.VerifyCheckpointSignature(got); err != nil {
		t.Fatalf("round-tripped signature invalid: %v", err)
	}
}

func TestCheckpointStore_ListSinceInclusiveAscendingAndLimit(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000100, 0).UTC()
	for _, fixture := range []*audit.SignedCheckpoint{
		signedCheckpointFixture(t, signer, 3, base.Add(2*time.Minute), "head-3", "head-2"),
		signedCheckpointFixture(t, signer, 1, base, "head-1", ""),
		signedCheckpointFixture(t, signer, 2, base.Add(time.Minute), "head-2", "head-1"),
	} {
		if err := s.Append(context.Background(), fixture); err != nil {
			t.Fatalf("Append sequence %d: %v", fixture.Checkpoint.Sequence, err)
		}
	}

	list, err := s.List(context.Background(), base.Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("List since: %v", err)
	}
	if len(list) != 2 || list[0].Checkpoint.Sequence != 2 || list[1].Checkpoint.Sequence != 3 {
		t.Fatalf("List since = %v, want sequences [2 3]", checkpointSequences(list))
	}
	limited, err := s.List(context.Background(), base.Add(time.Minute), 1)
	if err != nil {
		t.Fatalf("List limited: %v", err)
	}
	if len(limited) != 1 || limited[0].Checkpoint.Sequence != 2 {
		t.Fatalf("List limited = %v, want sequence [2]", checkpointSequences(limited))
	}
	unlimited, err := s.List(context.Background(), time.Time{}, -1)
	if err != nil {
		t.Fatalf("List unlimited: %v", err)
	}
	if len(unlimited) != 3 || unlimited[0].Checkpoint.Sequence != 1 || unlimited[2].Checkpoint.Sequence != 3 {
		t.Fatalf("List unlimited = %v, want sequences [1 2 3]", checkpointSequences(unlimited))
	}
}

func TestCheckpointStore_EmptyNilDuplicateAndClosed(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	ctx := context.Background()
	latest, err := s.Latest(ctx)
	if err != nil || latest != nil {
		t.Fatalf("Latest(empty) = (%v, %v), want (nil, nil)", latest, err)
	}
	empty, err := s.List(ctx, time.Time{}, 0)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("List(empty) = (%v, %v), want non-nil empty list", empty, err)
	}
	if err := s.Append(ctx, nil); err == nil {
		t.Fatal("Append(nil) must fail")
	}

	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	c := signedCheckpointFixture(t, signer, 1, time.Unix(1700000200, 0).UTC(), "head", "")
	if err := s.Append(ctx, c); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if err := s.Append(ctx, c); err == nil {
		t.Fatal("Append duplicate sequence must fail")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Append(ctx, c); err == nil {
		t.Fatal("Append after Close must fail")
	}
	if _, err := s.Latest(ctx); err == nil {
		t.Fatal("Latest after Close must fail")
	}
	if _, err := s.List(ctx, time.Time{}, 0); err == nil {
		t.Fatal("List after Close must fail")
	}
	var nilSink *Sink
	if _, err := nilSink.Latest(ctx); err == nil {
		t.Fatal("Latest on nil sink must fail")
	}
}

func TestCheckpointStore_NotaryRestartsWithDurableSequence(t *testing.T) {
	t.Parallel()
	dsn := "file:" + t.TempDir() + "/audit.db"
	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	sink1, err := New(dsn)
	if err != nil {
		t.Fatalf("New sink1: %v", err)
	}
	notary1 := audit.NewNotary(&checkpointTip{hash: "head-1"}, sink1, signer, time.Hour, nil, nil)
	first, err := notary1.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("first CheckpointNow: %v", err)
	}
	if first == nil || first.Checkpoint.Sequence != 1 {
		t.Fatalf("first checkpoint = %+v, want sequence 1", first)
	}
	if err := sink1.Close(); err != nil {
		t.Fatalf("close sink1: %v", err)
	}

	sink2, err := New(dsn)
	if err != nil {
		t.Fatalf("New sink2: %v", err)
	}
	t.Cleanup(func() { _ = sink2.Close() })
	notary2 := audit.NewNotary(&checkpointTip{hash: "head-2"}, sink2, signer, time.Hour, nil, nil)
	second, err := notary2.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("second CheckpointNow: %v", err)
	}
	if second == nil || second.Checkpoint.Sequence != 2 {
		t.Fatalf("second checkpoint = %+v, want sequence 2", second)
	}
	if second.Checkpoint.PrevHash != first.Checkpoint.HeadHash {
		t.Fatalf("second PrevHash = %q, want prior head %q", second.Checkpoint.PrevHash, first.Checkpoint.HeadHash)
	}
}

type checkpointTip struct{ hash string }

func (t *checkpointTip) LastHash(context.Context) (string, error) { return t.hash, nil }

func signedCheckpointFixture(t *testing.T, signer audit.CheckpointSigner, sequence int64, timestamp time.Time, head, previous string) *audit.SignedCheckpoint {
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
	return &audit.SignedCheckpoint{
		Checkpoint: checkpoint,
		Signature:  append([]byte{}, signature...),
		SignerKey:  append([]byte{}, signer.PublicKey()...),
	}
}

func checkpointSequences(checkpoints []*audit.SignedCheckpoint) []int64 {
	sequences := make([]int64, len(checkpoints))
	for i, checkpoint := range checkpoints {
		sequences[i] = checkpoint.Checkpoint.Sequence
	}
	return sequences
}
