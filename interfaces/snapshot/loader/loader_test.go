package loader_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/loader"
	"github.com/snaplink/sso/interfaces/snapshot/storage/inline"
)

// minimalSnapshot returns a Snapshot with the bare minimum fields filled
// in — enough to roundtrip Pipeline.Save / Load.
func minimalSnapshot() *snapshot.Snapshot {
	return &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap_test_loader",
		TakenAtUnix:     1715846400,
		SourceNamespace: "sso-server",
	}
}

func TestFromURI_FileRoundtrip(t *testing.T) {
	snap := minimalSnapshot()
	holder := inline.New()
	p := &snapshot.Pipeline{}
	if err := p.Save(context.Background(), snap, holder, snap.SnapshotID); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, _ := holder.Bytes(snap.SnapshotID)

	dir := t.TempDir()
	target := filepath.Join(dir, snap.SnapshotID+".snap")
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	st, name, err := loader.FromURI("file://" + target)
	if err != nil {
		t.Fatalf("FromURI: %v", err)
	}
	if name != snap.SnapshotID {
		t.Errorf("name=%q want %q", name, snap.SnapshotID)
	}
	got, err := p.Load(context.Background(), st, name)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id drift")
	}
}

func TestFromURI_FileWithExplicitName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alt.snap"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, name, err := loader.FromURI("file://" + dir + "/?name=alt")
	if err != nil {
		t.Fatalf("FromURI: %v", err)
	}
	if name != "alt" {
		t.Errorf("name=%q", name)
	}
	got, err := st.Get(context.Background(), name)
	if err != nil || string(got) != "payload" {
		t.Errorf("get: %v / %q", err, got)
	}
}

func TestFromURI_InlineRoundtrip(t *testing.T) {
	snap := minimalSnapshot()
	holder := inline.New()
	p := &snapshot.Pipeline{}
	if err := p.Save(context.Background(), snap, holder, snap.SnapshotID); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, _ := holder.Bytes(snap.SnapshotID)
	uri := "inline:" + base64.StdEncoding.EncodeToString(raw)

	st, name, err := loader.FromURI(uri)
	if err != nil {
		t.Fatalf("FromURI: %v", err)
	}
	got, err := p.Load(context.Background(), st, name)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id drift")
	}
}

func TestFromURI_Rejects(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want string
	}{
		{"empty", "", "empty URI"},
		{"unknown_scheme", "s3://bucket/snap", "unsupported URI scheme"},
		{"file_no_path", "file://", "requires a path"},
		{"inline_no_body", "inline:", "requires base64 body"},
		{"inline_bad_base64", "inline:!!!not-base64!!!", "not valid base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := loader.FromURI(tc.uri)
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err=%v want substring %q", err, tc.want)
			}
		})
	}
}
