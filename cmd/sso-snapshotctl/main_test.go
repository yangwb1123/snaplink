package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
	encryptionnone "github.com/snaplink/sso/interfaces/snapshot/encryption/none"
	encryptionpass "github.com/snaplink/sso/interfaces/snapshot/encryption/passphrase"
	storagefile "github.com/snaplink/sso/interfaces/snapshot/storage/file"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestRunList_EmptyDir — operators verifying an empty backup
// destination get a clear "no snapshots" line, not a silent
// success.
func TestRunList_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	out := captureStdout(t, func() {
		if err := runList([]string{"--dir", dir}); err != nil {
			t.Fatalf("runList: %v", err)
		}
	})
	if !strings.Contains(out, "(no snapshots)") {
		t.Errorf("output = %q; want '(no snapshots)' line", out)
	}
}

// TestRunList_WithSnapshots — after writing one snapshot, list
// should surface the id and basic envelope metadata in a single
// row.
func TestRunList_WithSnapshots(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "")
	out := captureStdout(t, func() {
		if err := runList([]string{"--dir", dir}); err != nil {
			t.Fatalf("runList: %v", err)
		}
	})
	if !strings.Contains(out, id) {
		t.Errorf("output missing snapshot id %q; got:\n%s", id, out)
	}
}

// TestRunInspect_PrintsEnvelopeMetadata — inspect prints JSON
// header projection; verify a representative field round-trips.
func TestRunInspect_PrintsEnvelopeMetadata(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "")
	out := captureStdout(t, func() {
		if err := runInspect([]string{"--dir", dir, "--id", id}); err != nil {
			t.Fatalf("runInspect: %v", err)
		}
	})
	if !strings.Contains(out, `"snapshot_id"`) {
		t.Errorf("output missing snapshot_id field; got:\n%s", out)
	}
	if !strings.Contains(out, `"plaintext_sha256_hex"`) {
		t.Errorf("output missing checksum field; got:\n%s", out)
	}
}

// TestRunVerify_UnencryptedSucceeds — the happy path: a sealed
// snapshot opens cleanly with the no-op sealer, prints a success
// line + summary.
func TestRunVerify_UnencryptedSucceeds(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "")
	out := captureStdout(t, func() {
		if err := runVerify([]string{"--dir", dir, "--id", id}); err != nil {
			t.Fatalf("runVerify: %v", err)
		}
	})
	if !strings.Contains(out, "ok:") {
		t.Errorf("output missing 'ok:' success line; got:\n%s", out)
	}
}

// TestRunVerify_EncryptedRequiresPassphrase — opting into
// passphrase encryption then trying to verify without one should
// fail clearly, not silently no-op.
func TestRunVerify_EncryptedRequiresPassphrase(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "hunter2")
	err := runVerify([]string{"--dir", dir, "--id", id})
	if err == nil {
		t.Fatal("expected error for encrypted snapshot without passphrase")
	}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("err = %v; want encryption-specific message", err)
	}
}

// TestRunVerify_EncryptedWithPassphraseSucceeds — round-trip
// through the argon2id+chacha20poly1305 sealer with the matching
// passphrase.
func TestRunVerify_EncryptedWithPassphraseSucceeds(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "hunter2")
	out := captureStdout(t, func() {
		if err := runVerify([]string{"--dir", dir, "--id", id, "--passphrase", "hunter2"}); err != nil {
			t.Fatalf("runVerify: %v", err)
		}
	})
	if !strings.Contains(out, "ok:") {
		t.Errorf("output missing 'ok:' line; got:\n%s", out)
	}
}

// TestRunVerify_PassphraseFileSurfacesIOError — typo'd
// --passphrase-file path → loud error.
func TestRunVerify_PassphraseFileSurfacesIOError(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "hunter2")
	err := runVerify([]string{"--dir", dir, "--id", id, "--passphrase-file", "/no/such/file"})
	if err == nil {
		t.Fatal("expected error for missing passphrase file")
	}
}

// TestRunVerify_MutuallyExclusivePassphraseFlags — operators who
// supply both inline + file get a clear rejection instead of
// silent precedence behavior they have to discover.
func TestRunVerify_MutuallyExclusivePassphraseFlags(t *testing.T) {
	dir := t.TempDir()
	err := runVerify([]string{"--dir", dir, "--id", "any", "--passphrase", "x", "--passphrase-file", "/tmp/y"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v; want mutually-exclusive rejection", err)
	}
}

// writeSampleSnapshot drops a fully-formed snapshot into a tempdir
// using the same Pipeline + Storage cmd/sso-server would use,
// returning the storage dir + the snapshot id. When passphrase is
// non-empty the snapshot is encrypted with argon2id+chacha20poly1305;
// otherwise the no-op sealer is used.
func writeSampleSnapshot(t *testing.T, passphrase string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := storagefile.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sealer snapshot.Sealer = encryptionnone.New()
	if passphrase != "" {
		sealer = encryptionpass.NewFromString(passphrase)
	}
	pipe := &snapshot.Pipeline{Sealer: sealer}
	const id = "test-snapshot-1"
	snap := &snapshot.Snapshot{
		SchemaVersion: "1",
		SnapshotID:    id,
		Resources: snapshot.Resources{
			Clients: []*sso.Client{{ID: "c-1", Name: "ex"}},
		},
	}
	if err := pipe.Save(context.Background(), snap, store, id); err != nil {
		t.Fatalf("save: %v", err)
	}
	return dir, id
}

// captureStdout runs fn with os.Stdout redirected to a pipe and
// returns whatever fn wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() {
		_ = w.Close()
		os.Stdout = orig
	}()
	fn()
	_ = w.Close()
	out := <-done
	// Restore stdout for the next test that follows in this binary.
	os.Stdout = orig
	return string(bytes.TrimSpace(out))
}

// Silence the file-storage warning Path validation prints to
// stderr on weird inputs in the eager tests. Test stderr stays
// uncaptured by default; only stdout matters for the assertions
// above.
var _ = filepath.Join
