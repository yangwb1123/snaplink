package snapshot_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/encryptionaesgcm"
	"github.com/snaplink/sso/interfaces/snapshot/storagefile"
	"github.com/snaplink/sso/interfaces/snapshot/storageinline"
)

// makeAESKey returns a deterministic 32-byte AES-256 key for tests.
func makeAESKey(b byte) []byte {
	k := make([]byte, aesgcm.KeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

// TestPipeline_AESGCM_Roundtrip proves the aes-256-gcm sealer round-trips a
// snapshot through Save/Load with the matching key.
func TestPipeline_AESGCM_Roundtrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	sealer, err := aesgcm.New(makeAESKey(0x11))
	if err != nil {
		t.Fatalf("aesgcm.New: %v", err)
	}
	st := inline.New()
	saver := &snapshot.Pipeline{Sealer: sealer}
	if err := saver.Save(ctx, snap, st, "snap-aes"); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The persisted body must NOT contain plaintext markers — it's encrypted.
	raw, _ := st.Get(ctx, "snap-aes")
	if bytes.Contains(raw, []byte(snap.SnapshotID)) && bytes.Contains(raw, []byte("\"clients\"")) {
		t.Errorf("ciphertext body appears to leak plaintext resources")
	}

	loaderSealer, _ := aesgcm.New(makeAESKey(0x11))
	loader := &snapshot.Pipeline{Sealer: loaderSealer}
	got, err := loader.Load(ctx, st, "snap-aes")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id drift: %q vs %q", got.SnapshotID, snap.SnapshotID)
	}
	if len(got.Resources.Clients) != len(snap.Resources.Clients) {
		t.Errorf("client count drift: %d vs %d", len(got.Resources.Clients), len(snap.Resources.Clients))
	}
}

// TestPipeline_AESGCM_WrongKeyFails proves opening with a different key fails
// (AEAD authentication tag rejects it).
func TestPipeline_AESGCM_WrongKeyFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	sealer, _ := aesgcm.New(makeAESKey(0x22))
	st := inline.New()
	saver := &snapshot.Pipeline{Sealer: sealer}
	if err := saver.Save(ctx, snap, st, "snap-aes"); err != nil {
		t.Fatalf("save: %v", err)
	}

	wrong, _ := aesgcm.New(makeAESKey(0x33))
	loader := &snapshot.Pipeline{Sealer: wrong}
	if _, err := loader.Load(ctx, st, "snap-aes"); err == nil {
		t.Errorf("expected open failure with wrong AES key, got nil")
	}
}

// TestPipeline_FileStorage_FullCycle exercises the full Save -> List ->
// Load -> PruneOldest path against the on-disk file.Storage backend (the
// production storage), proving the snapshot package composes with it.
func TestPipeline_FileStorage_FullCycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)

	st, err := file.New(t.TempDir())
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}
	p := &snapshot.Pipeline{} // JSON + noop sealer

	// Save several snapshots under time-ordered names so PruneOldest has
	// real entries to reason about.
	names := []string{
		"snap_2026-01-01T00-00-00Z_aaa",
		"snap_2026-01-02T00-00-00Z_bbb",
		"snap_2026-01-03T00-00-00Z_ccc",
	}
	for _, n := range names {
		snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
		snap.SnapshotID = n
		if err := p.Save(ctx, snap, st, n); err != nil {
			t.Fatalf("save %s: %v", n, err)
		}
	}

	listed, err := st.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("listed %d files, want 3 (%v)", len(listed), listed)
	}

	// Load one back and confirm it decodes.
	got, err := p.Load(ctx, st, names[0])
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SnapshotID != names[0] {
		t.Errorf("snapshot_id = %q, want %q", got.SnapshotID, names[0])
	}
	if len(got.Resources.Clients) != 2 {
		t.Errorf("clients = %d, want 2", len(got.Resources.Clients))
	}

	// Retention: keep 1, the two oldest must be pruned.
	deleted, err := snapshot.PruneOldest(ctx, st, 1)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("pruned %d, want 2 (%v)", len(deleted), deleted)
	}
	remaining, _ := st.List(ctx)
	if len(remaining) != 1 || remaining[0] != names[2] {
		t.Errorf("remaining = %v, want only %q", remaining, names[2])
	}
}

// TestPipeline_AESGCM_AlgorithmMismatchAgainstFile proves a noop loader
// refuses an aes-gcm-sealed envelope (algorithm guard) even off disk.
func TestPipeline_AESGCM_AlgorithmMismatchAgainstFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	st, err := file.New(t.TempDir())
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}
	sealer, _ := aesgcm.New(makeAESKey(0x44))
	saver := &snapshot.Pipeline{Sealer: sealer}
	if err := saver.Save(ctx, snap, st, "snap-x"); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Default pipeline = noop sealer → algorithm mismatch.
	if _, err := (&snapshot.Pipeline{}).Load(ctx, st, "snap-x"); err == nil {
		t.Errorf("want algorithm mismatch loading aes-gcm envelope with noop sealer")
	}
}
