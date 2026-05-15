package snapshot_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/snaplink/sso/snapshot"
	"github.com/snaplink/sso/snapshot/encryption/none"
	"github.com/snaplink/sso/snapshot/encryption/passphrase"
	"github.com/snaplink/sso/snapshot/storage/inline"
)

func TestJSONCodec_Roundtrip(t *testing.T) {
	src := newFixture(t)
	snap, err := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	c := snapshot.NewJSONCodec()
	raw, err := c.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version": "1"`) {
		t.Errorf("missing schema_version in output:\n%s", string(raw))
	}

	got, err := c.Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id mismatch: %q vs %q", got.SnapshotID, snap.SnapshotID)
	}
	if len(got.Resources.Clients) != len(snap.Resources.Clients) {
		t.Errorf("client count drifted: %d vs %d", len(got.Resources.Clients), len(snap.Resources.Clients))
	}
}

func TestJSONCodec_RejectsUnknownSchemaVersion(t *testing.T) {
	bad := []byte(`{"schema_version":"99","snapshot_id":"x","source_namespace":"y"}`)
	_, err := snapshot.NewJSONCodec().Unmarshal(bad)
	if !errors.Is(err, snapshot.ErrUnknownSchemaVersion) {
		t.Errorf("want ErrUnknownSchemaVersion, got %v", err)
	}
}

func TestPipeline_NoEncryption_Roundtrip(t *testing.T) {
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	st := inline.New()
	p := &snapshot.Pipeline{} // defaults: JSON codec + noop sealer
	if err := p.Save(context.Background(), snap, st, "snap-1"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := p.Load(context.Background(), st, "snap-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id drift: %q vs %q", got.SnapshotID, snap.SnapshotID)
	}
}

func TestPipeline_Passphrase_Roundtrip(t *testing.T) {
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	st := inline.New()
	saver := &snapshot.Pipeline{Sealer: passphrase.NewFromString("correct horse battery staple")}
	if err := saver.Save(context.Background(), snap, st, "snap-1"); err != nil {
		t.Fatalf("save: %v", err)
	}

	loader := &snapshot.Pipeline{Sealer: passphrase.NewFromString("correct horse battery staple")}
	got, err := loader.Load(context.Background(), st, "snap-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id drift after roundtrip: %q vs %q", got.SnapshotID, snap.SnapshotID)
	}
}

func TestPipeline_Passphrase_WrongKeyFails(t *testing.T) {
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	st := inline.New()
	saver := &snapshot.Pipeline{Sealer: passphrase.NewFromString("right")}
	if err := saver.Save(context.Background(), snap, st, "snap-1"); err != nil {
		t.Fatalf("save: %v", err)
	}

	loader := &snapshot.Pipeline{Sealer: passphrase.NewFromString("wrong")}
	_, err := loader.Load(context.Background(), st, "snap-1")
	if err == nil {
		t.Errorf("expected open failure with wrong passphrase, got nil")
	}
}

func TestPipeline_AlgorithmMismatch(t *testing.T) {
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	st := inline.New()
	saver := &snapshot.Pipeline{Sealer: passphrase.NewFromString("k")}
	if err := saver.Save(context.Background(), snap, st, "snap-1"); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Loader with no encryption — algorithm mismatch should refuse.
	loader := &snapshot.Pipeline{Sealer: none.New()}
	_, err := loader.Load(context.Background(), st, "snap-1")
	if err == nil || !strings.Contains(err.Error(), "algorithm mismatch") {
		t.Errorf("want algorithm mismatch, got %v", err)
	}
}

func TestPipeline_ChecksumMismatchDetected(t *testing.T) {
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	st := inline.New()
	p := &snapshot.Pipeline{}
	if err := p.Save(context.Background(), snap, st, "snap-1"); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Mutate the stored bytes — flip a byte deep inside the body.
	raw, _ := st.Bytes("snap-1")
	// Find the body field and corrupt one byte after it.
	idx := strings.Index(string(raw), `"body": "`)
	if idx < 0 {
		t.Fatalf("could not locate body field in envelope:\n%s", raw)
	}
	// flip a base64 char inside the body (offset ~ idx+10)
	target := idx + len(`"body": "`) + 5
	if target >= len(raw) {
		t.Fatalf("envelope too short")
	}
	if raw[target] == 'A' {
		raw[target] = 'B'
	} else {
		raw[target] = 'A'
	}
	_ = st.Put(context.Background(), "snap-1", raw)

	_, err := p.Load(context.Background(), st, "snap-1")
	if err == nil {
		t.Errorf("expected error on tampered envelope, got nil")
	}
}

func TestPipeline_LoadMissingReturnsSentinel(t *testing.T) {
	st := inline.New()
	p := &snapshot.Pipeline{}
	_, err := p.Load(context.Background(), st, "absent")
	if !errors.Is(err, snapshot.ErrSnapshotNotFound) {
		t.Errorf("want ErrSnapshotNotFound, got %v", err)
	}
}
