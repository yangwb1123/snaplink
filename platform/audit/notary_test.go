package audit

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// fakeTip is a controllable ChainTip.
type fakeTip struct {
	hash string
	err  error
}

func (f *fakeTip) LastHash(context.Context) (string, error) { return f.hash, f.err }

// recordingTip is a ChainTip over a live recorder's durable sink: it returns
// the last recorded event's Hash, exactly like a real durable sink.
type recordingTip struct {
	rec *Recorder
	snk *MemorySink
}

func (r *recordingTip) LastHash(ctx context.Context) (string, error) {
	events, err := r.snk.Query(ctx, Query{})
	if err != nil {
		return "", err
	}
	if len(events) == 0 {
		return "", nil
	}
	// Query returns newest-first; the tip is the NEWEST event's hash.
	return events[0].Hash, nil
}

func TestNotary_CheckpointsChainHead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sink := NewMemorySink(20)
	rec := New(sink, WithHashChain())
	tip := &recordingTip{rec: rec, snk: sink}

	// Record three events (chain seeded from genesis by the recorder).
	rec.Record(ctx, &Event{Type: EventLoginFailure, Outcome: OutcomeFailure, ActorID: "a"})
	rec.Record(ctx, &Event{Type: EventTokenIssued, Outcome: OutcomeSuccess, ActorID: "b"})
	rec.Record(ctx, &Event{Type: EventTokenRevoked, Outcome: OutcomeSuccess, ActorID: "c"})

	store := NewMemoryCheckpointStore()
	signer, err := NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatal(err)
	}
	notary := NewNotary(tip, store, signer, time.Hour, rec, nil)

	cp, err := notary.CheckpointNow(ctx)
	if err != nil {
		t.Fatalf("CheckpointNow: %v", err)
	}
	if cp == nil {
		t.Fatal("no checkpoint produced for a non-empty chain")
	}
	if cp.Checkpoint.Sequence != 1 || cp.Checkpoint.HeadHash == "" {
		t.Fatalf("checkpoint = %+v", cp.Checkpoint)
	}
	events, _ := sink.Query(ctx, Query{})
	if cp.Checkpoint.HeadHash != events[0].Hash {
		t.Errorf("checkpoint head %q != recorded chain head %q", cp.Checkpoint.HeadHash, events[len(events)-1].Hash)
	}
	// The checkpoint is self-verifying.
	if err := VerifyCheckpointSignature(cp); err != nil {
		t.Fatalf("signature invalid: %v", err)
	}
	// A second call with an unchanged head produces nothing new.
	again, err := notary.CheckpointNow(ctx)
	if err != nil || again != nil {
		t.Fatalf("unchanged head produced checkpoint %v, %v", again, err)
	}
}

func TestNotary_VerificationClosesLastEventBlindSpot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sink := NewMemorySink(20)
	rec := New(sink, WithHashChain())
	tip := &recordingTip{rec: rec, snk: sink}

	rec.Record(ctx, &Event{Type: EventLoginFailure, Outcome: OutcomeFailure, ActorID: "a"})
	rec.Record(ctx, &Event{Type: EventTokenIssued, Outcome: OutcomeSuccess, ActorID: "b"})

	store := NewMemoryCheckpointStore()
	signer, _ := NewEd25519CheckpointSigner()
	notary := NewNotary(tip, store, signer, time.Hour, nil, nil)
	cp, err := notary.CheckpointNow(ctx)
	if err != nil || cp == nil {
		t.Fatalf("checkpoint: %v %v", cp, err)
	}

	events, _ := sink.Query(ctx, Query{})
	// Query returns newest-first; the verifier needs chain order (oldest
	// first, which is also the recorded order).
	slices.Reverse(events)
	// The replayed chain verifies against the checkpoint.
	if err := VerifyChainAgainstCheckpoint(events, cp); err != nil {
		t.Fatalf("verify against checkpoint: %v", err)
	}

	// Tamper with the LAST event (the chain's blind spot): change its
	// content AND recompute its hash, so the internal chain still verifies
	// (no later event contradicts it) — the exact attack the chain alone
	// cannot see. Only the checkpoint attestation exposes it.
	events[len(events)-1].Reason = "tampered"
	events[len(events)-1].Hash = eventHash(events[len(events)-1])
	if err := VerifyChain(events); err != nil {
		t.Fatalf("internal chain no longer verifies (test setup): %v", err)
	}
	if err := VerifyChainAgainstCheckpoint(events, cp); err == nil {
		t.Fatal("tampered last event verified against the checkpoint — blind spot not closed")
	}

	// A forged checkpoint (wrong key) is rejected at the signature layer.
	forger, _ := NewEd25519CheckpointSigner()
	forged, _ := forger.Sign([]byte("forged"))
	forgedCP := &SignedCheckpoint{Checkpoint: cp.Checkpoint, Signature: forged, SignerKey: forger.PublicKey()}
	if err := VerifyChainAgainstCheckpoint(events, forgedCP); err == nil {
		t.Fatal("forged checkpoint verified")
	}
}

func TestNotary_TipErrorFailsOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryCheckpointStore()
	signer, _ := NewEd25519CheckpointSigner()
	notary := NewNotary(&fakeTip{err: errors.New("sink down")}, store, signer, time.Hour, nil, nil)

	if _, err := notary.CheckpointNow(ctx); err == nil {
		t.Fatal("tip error must surface")
	}
	latest, _ := store.Latest(ctx)
	if latest != nil {
		t.Fatal("failed checkpoint must not be stored")
	}
}

func TestNotary_StartStopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	tip := &fakeTip{hash: "abc"}
	store := NewMemoryCheckpointStore()
	signer, _ := NewEd25519CheckpointSigner()
	done := StartNotary(ctx, tip, store, signer, 20*time.Millisecond, nil, nil)
	// Wait for at least one checkpoint by polling — race builds schedule the
	// notary goroutine late under full-suite load, so a fixed sleep is flaky.
	deadline := time.Now().Add(2 * time.Second)
	for {
		latest, _ := store.Latest(ctx)
		if latest != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("loop did not checkpoint")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notary loop did not stop on cancel")
	}
}
