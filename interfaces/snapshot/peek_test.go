package snapshot_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"
)

func TestPeekEnvelope_RoundTrip(t *testing.T) {
	t.Parallel()
	pipe := &snapshot.Pipeline{}
	st := inline.New()
	snap := &snapshot.Snapshot{SnapshotID: "snap-peek-1", SchemaVersion: snapshot.SchemaVersion}

	if err := pipe.Save(context.Background(), snap, st, snap.SnapshotID); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := st.Get(context.Background(), snap.SnapshotID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	env, err := snapshot.PeekEnvelope(raw)
	if err != nil {
		t.Fatalf("PeekEnvelope: %v", err)
	}
	if env.SnapshotID != "snap-peek-1" {
		t.Errorf("SnapshotID = %q", env.SnapshotID)
	}
	if env.Codec == "" {
		t.Error("Codec empty — header should always carry it")
	}
	if env.ChecksumSHA256 == "" {
		t.Error("ChecksumSHA256 empty")
	}
	// Body must be cleared so callers can't accidentally treat the peek
	// result like a full load.
	if env.Body != nil {
		t.Errorf("Body = %v, want nil", env.Body)
	}
}

func TestPeekEnvelope_RejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := snapshot.PeekEnvelope([]byte("not even json")); err == nil {
		t.Error("expected error on non-JSON input")
	}
	if _, err := snapshot.PeekEnvelope(nil); err == nil {
		t.Error("expected error on nil input")
	}
}

func TestPeekEnvelope_TolerantOfMissingBody(t *testing.T) {
	t.Parallel()
	// An envelope with no body field should still decode — PeekEnvelope's
	// whole job is to surface header metadata without decryption. Other
	// fields must round-trip even when Body is absent.
	env := snapshot.SealedEnvelope{
		EnvelopeVersion: snapshot.EnvelopeVersion,
		SnapshotID:      "header-only",
		Codec:           "json",
		Algorithm:       snapshot.EncryptionNone,
		ChecksumSHA256:  strings.Repeat("0", 64),
	}
	raw, _ := json.Marshal(env)

	got, err := snapshot.PeekEnvelope(raw)
	if err != nil {
		t.Fatalf("PeekEnvelope: %v", err)
	}
	if got.SnapshotID != "header-only" || got.Codec != "json" {
		t.Errorf("got %+v", got)
	}
}
