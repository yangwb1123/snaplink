package auditexport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	libexport "github.com/yangwb1123/snaplink/platform/audit/auditexport"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// writeDurableCheckpoint records a real hash chain and persists its signed
// checkpoint through the same SQLite sink used by the read-only CLI opener.
func writeDurableCheckpoint(t *testing.T, dsn string) *audit.SignedCheckpoint {
	t.Helper()
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open writable audit sink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	clock := time.Unix(1700000000, 0).UTC()
	i := 0
	recorder := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return clock.Add(time.Duration(i) * time.Minute)
	}))
	for range 4 {
		recorder.Record(context.Background(), &audit.Event{
			Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "user",
		})
	}

	signer, err := audit.NewEd25519CheckpointSigner()
	if err != nil {
		t.Fatalf("new checkpoint signer: %v", err)
	}
	notary := audit.NewNotary(sink, sink, signer, time.Hour, nil, nil)
	checkpoint, err := notary.CheckpointNow(context.Background())
	if err != nil {
		t.Fatalf("persist checkpoint: %v", err)
	}
	if checkpoint == nil {
		t.Fatal("real notary returned no checkpoint")
	}
	return checkpoint
}

func TestRun_AnchorLatestDurableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	writeDurableCheckpoint(t, dsn)

	if code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", dsn, "--anchor-latest", "--out", out})
	}); code != 0 {
		t.Fatalf("anchor-latest export exit=%d, want 0", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var bundle libexport.ExportBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if bundle.Anchor == nil {
		t.Fatal("anchor-latest bundle must embed a checkpoint")
	}

	store, err := auditsqlite.OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("open read-only store: %v", err)
	}
	latest, err := store.Latest(context.Background())
	_ = store.Close()
	if err != nil {
		t.Fatalf("read latest checkpoint: %v", err)
	}
	if !audit.CheckpointEqual(bundle.Anchor, latest) {
		t.Fatalf("bundle anchor differs from durable Latest: bundle=%+v latest=%+v", bundle.Anchor, latest)
	}
	if err := audit.VerifyCheckpointSignature(bundle.Anchor); err != nil {
		t.Fatalf("embedded checkpoint signature invalid: %v", err)
	}
	if bundle.HeadHash != bundle.Anchor.Checkpoint.HeadHash {
		t.Fatalf("bundle head %q != attested head %q", bundle.HeadHash, bundle.Anchor.Checkpoint.HeadHash)
	}
	if code := captureQuiet(t, func() int { return Run([]string{"--verify", out}) }); code != 0 {
		t.Fatal("offline --verify rejected the durable anchored bundle")
	}
}

func TestRun_AnchorLatestNoCheckpointFailsWithoutOutput(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, dsn, 3)

	var code int
	stdout := captureStdout(t, func() {
		code = Run([]string{"--dsn", dsn, "--anchor-latest", "--out", out})
	})
	if code != 1 {
		t.Fatalf("no-checkpoint export exit=%d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("no-checkpoint failure wrote stdout: %q", stdout)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("no-checkpoint failure left bundle output, stat err=%v", err)
	}
}

func TestRun_AnchorLatestMisuseExitsTwo(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"without-dsn", []string{"--anchor-latest"}, "requires --dsn"},
		{"explicit-anchor", []string{"--dsn", dsn, "--anchor-latest", "--anchor", "checkpoint.json"}, "cannot be combined"},
		{"verify", []string{"--dsn", dsn, "--anchor-latest", "--verify", "bundle.json"}, "cannot be combined"},
		{"from-url", []string{"--from-url", "https://example.test", "--bearer", "token", "--anchor-latest"}, "cannot be combined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = Run(tc.args) })
			if code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr missing %q:\n%s", tc.want, stderr)
			}
		})
	}
}

func TestRun_AnchorLatestHeadMismatchFailsWithoutOutput(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	writeDurableCheckpoint(t, dsn)

	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--anchor-latest", "--until", "1700000060", "--out", out})
	})
	if code != 1 {
		t.Fatalf("partial latest-anchored export exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, "anchor head mismatch") {
		t.Fatalf("stderr missing exact-head failure:\n%s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("head mismatch left bundle output, stat err=%v", err)
	}
}

func TestRun_AnchorLatestTamperedStoredSignatureFails(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	writeDurableCheckpoint(t, dsn)

	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("open writable sink for tamper: %v", err)
	}
	_, err = sink.DB().ExecContext(context.Background(),
		"UPDATE audit_checkpoints SET signature = ? WHERE sequence = (SELECT MAX(sequence) FROM audit_checkpoints)",
		[]byte("tampered"))
	_ = sink.Close()
	if err != nil {
		t.Fatalf("tamper checkpoint signature: %v", err)
	}

	var code int
	stderr := captureStderr(t, func() {
		code = Run([]string{"--dsn", dsn, "--anchor-latest", "--out", out})
	})
	if code != 1 {
		t.Fatalf("tampered checkpoint export exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, "signature check") {
		t.Fatalf("stderr missing signature failure:\n%s", stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("tampered checkpoint failure left bundle output, stat err=%v", err)
	}
}
