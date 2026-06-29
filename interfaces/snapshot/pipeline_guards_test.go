package snapshot_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/storageinline"
	"github.com/snaplink/sso/platform/bootstrap/memory"
)

// TestPipeline_Save_NilGuards pins the two argument guards on Save.
func TestPipeline_Save_NilGuards(t *testing.T) {
	t.Parallel()
	p := &snapshot.Pipeline{}
	if err := p.Save(context.Background(), nil, inline.New(), "n"); err == nil {
		t.Error("Save(nil snapshot) must error")
	}
	snap := &snapshot.Snapshot{SnapshotID: "x", SchemaVersion: snapshot.SchemaVersion}
	if err := p.Save(context.Background(), snap, nil, "n"); err == nil {
		t.Error("Save(nil storage) must error")
	}
}

// TestPipeline_Load_NilStorage pins the nil-storage guard on Load.
func TestPipeline_Load_NilStorage(t *testing.T) {
	t.Parallel()
	p := &snapshot.Pipeline{}
	if _, err := p.Load(context.Background(), nil, "n"); err == nil {
		t.Error("Load(nil storage) must error")
	}
}

// TestPipeline_Load_GarbageEnvelope proves Load rejects non-envelope bytes
// (the json.Unmarshal failure branch).
func TestPipeline_Load_GarbageEnvelope(t *testing.T) {
	t.Parallel()
	st := inline.New()
	if err := st.Put(context.Background(), "g", []byte("{not an envelope")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := (&snapshot.Pipeline{}).Load(context.Background(), st, "g"); err == nil {
		t.Error("Load(garbage envelope) must error")
	}
}

// TestPipeline_Load_UnknownEnvelopeVersion proves the envelope-version guard.
func TestPipeline_Load_UnknownEnvelopeVersion(t *testing.T) {
	t.Parallel()
	st := inline.New()
	// Minimal envelope JSON with a bogus version.
	raw := []byte(`{"envelope_version":"99","snapshot_id":"x","codec":"json","encryption_algorithm":"none","plaintext_sha256_hex":"00","body":""}`)
	if err := st.Put(context.Background(), "v", raw); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := (&snapshot.Pipeline{}).Load(context.Background(), st, "v"); err == nil {
		t.Error("Load(unknown envelope version) must error")
	}
}

// TestAdvanceBootstrap_NoNamespace covers the branch where neither the
// Restorer nor the snapshot carries a namespace: advance is a reasoned no-op.
func TestAdvanceBootstrap_NoNamespace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Snapshot with empty BootstrapState namespace.
	snap := &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap_empty-ns",
		SourceNamespace: "ns", // Validate requires this, but it's NOT the bootstrap ns.
	}
	r := &snapshot.Restorer{
		Clients: defaultimpl.NewMemoryClientStore(),
		Tracker: memory.New(),
		// Namespace empty AND snap.BootstrapState.Namespace empty.
	}
	rep, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !rep.Bootstrap.Attempted || !rep.Bootstrap.NoOp {
		t.Errorf("expected attempted no-op for missing namespace: %+v", rep.Bootstrap)
	}
	if rep.Bootstrap.Reason == "" {
		t.Errorf("expected a reason for the no-op")
	}
}
