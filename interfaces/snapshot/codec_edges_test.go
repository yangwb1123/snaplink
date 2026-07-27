package snapshot_test

import (
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
)

func TestJSONCodec_Marshal_NilSnapshot(t *testing.T) {
	t.Parallel()
	if _, err := snapshot.NewJSONCodec().Marshal(nil); err == nil {
		t.Error("expected error on nil snapshot")
	}
}

func TestJSONCodec_Marshal_CompactForm(t *testing.T) {
	t.Parallel()
	// Indent=false emits the compact form (no leading two-space lines).
	c := &snapshot.JSONCodec{Indent: false}
	snap := &snapshot.Snapshot{
		SnapshotID: "compact", SchemaVersion: snapshot.SchemaVersion, SourceNamespace: "ns",
	}
	raw, err := c.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), "  ") {
		t.Errorf("compact form should not contain double-space indent; got: %s", raw)
	}
}

func TestJSONCodec_Marshal_IndentedDefault(t *testing.T) {
	t.Parallel()
	c := snapshot.NewJSONCodec()
	snap := &snapshot.Snapshot{
		SnapshotID: "indented", SchemaVersion: snapshot.SchemaVersion, SourceNamespace: "ns",
	}
	raw, err := c.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), "  ") {
		t.Errorf("indented form should contain two-space indent; got: %s", raw)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Errorf("encoded output should end in newline; got: %q", raw)
	}
}

func TestJSONCodec_Marshal_NilReceiverDefaultsToIndented(t *testing.T) {
	t.Parallel()
	// A nil *JSONCodec receiver should still produce indented output —
	// the contract is "passing nil works like the default".
	var c *snapshot.JSONCodec
	snap := &snapshot.Snapshot{
		SnapshotID: "x", SchemaVersion: snapshot.SchemaVersion, SourceNamespace: "ns",
	}
	raw, err := c.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), "  ") {
		t.Errorf("nil receiver should produce indented form; got: %s", raw)
	}
}

func TestJSONCodec_Unmarshal_EmptyInput(t *testing.T) {
	t.Parallel()
	if _, err := snapshot.NewJSONCodec().Unmarshal(nil); err == nil {
		t.Error("expected error on nil input")
	}
	if _, err := snapshot.NewJSONCodec().Unmarshal([]byte{}); err == nil {
		t.Error("expected error on empty input")
	}
}

func TestJSONCodec_Unmarshal_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	// DisallowUnknownFields is on — bogus top-level keys must fail
	// the decode, not be silently dropped.
	bad := []byte(`{"schema_version":"1","snapshot_id":"x","source_namespace":"y","bogus_field":42}`)
	if _, err := snapshot.NewJSONCodec().Unmarshal(bad); err == nil {
		t.Error("expected error on unknown field")
	}
}

func TestJSONCodec_ContentType(t *testing.T) {
	t.Parallel()
	got := snapshot.NewJSONCodec().ContentType()
	if got != string(snapshot.CodecJSON) {
		t.Errorf("ContentType = %q, want %q", got, snapshot.CodecJSON)
	}
}
