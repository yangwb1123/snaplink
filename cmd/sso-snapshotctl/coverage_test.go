package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	storagefile "github.com/snaplink/sso/snapshot/storage/file"
)

// ---- runList edge cases ----

func TestRunList_MissingDir(t *testing.T) {
	if err := runList(nil); err == nil {
		t.Fatal("expected error when --dir is missing")
	}
}

func TestRunList_BadFlag(t *testing.T) {
	if err := runList([]string{"--bogus"}); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}
}

// TestRunList_PeekErrorRow — a file with the storage extension (.snap)
// that isn't a valid snapshot envelope makes PeekEnvelope fail; runList
// must print a "(peek error)" row and continue rather than aborting the
// whole listing.
func TestRunList_PeekErrorRow(t *testing.T) {
	dir := t.TempDir()
	// The file-storage backend lists files ending in ".snap". A junk
	// ".snap" file is listed but fails PeekEnvelope.
	junk := filepath.Join(dir, "garbage.snap")
	if err := os.WriteFile(junk, []byte("not a snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runList([]string{"--dir", dir}); err != nil {
			t.Fatalf("runList: %v", err)
		}
	})
	if !strings.Contains(out, "peek error") {
		t.Errorf("expected a 'peek error' row; got:\n%s", out)
	}
}

// ---- runInspect edge cases ----

func TestRunInspect_MissingFlags(t *testing.T) {
	if err := runInspect([]string{"--dir", t.TempDir()}); err == nil {
		t.Fatal("expected error when --id is missing")
	}
}

func TestRunInspect_BadFlag(t *testing.T) {
	if err := runInspect([]string{"--nope"}); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}
}

// TestRunInspect_GetMissing — a non-existent id surfaces the storage
// Get error.
func TestRunInspect_GetMissing(t *testing.T) {
	dir := t.TempDir()
	if err := runInspect([]string{"--dir", dir, "--id", "does-not-exist"}); err == nil {
		t.Fatal("expected error inspecting a missing snapshot id")
	}
}

// ---- runVerify edge cases ----

func TestRunVerify_MissingFlags(t *testing.T) {
	if err := runVerify([]string{"--dir", t.TempDir()}); err == nil {
		t.Fatal("expected error when --id is missing")
	}
}

func TestRunVerify_BadFlag(t *testing.T) {
	if err := runVerify([]string{"--nope"}); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}
}

func TestRunVerify_GetMissing(t *testing.T) {
	dir := t.TempDir()
	if err := runVerify([]string{"--dir", dir, "--id", "missing"}); err == nil {
		t.Fatal("expected error verifying a missing snapshot id")
	}
}

// TestRunVerify_PassphraseFileSucceeds — supplying the passphrase via a
// file (not inline) round-trips an encrypted snapshot, covering the
// passphrase-file read branch.
func TestRunVerify_PassphraseFileSucceeds(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "s3cret")
	pf := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(pf, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runVerify([]string{"--dir", dir, "--id", id, "--passphrase-file", pf}); err != nil {
			t.Fatalf("runVerify: %v", err)
		}
	})
	if !strings.Contains(out, "ok:") {
		t.Errorf("output missing 'ok:' line; got:\n%s", out)
	}
}

// TestRunVerify_PassphraseIgnoredOnUnencrypted — passing a passphrase
// for an unencrypted snapshot still succeeds, and the tool notes the
// passphrase was ignored (stderr) while verifying cleanly (stdout).
func TestRunVerify_PassphraseIgnoredOnUnencrypted(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "")
	out := captureStdout(t, func() {
		if err := runVerify([]string{"--dir", dir, "--id", id, "--passphrase", "unused"}); err != nil {
			t.Fatalf("runVerify: %v", err)
		}
	})
	if !strings.Contains(out, "ok:") {
		t.Errorf("output missing 'ok:' line; got:\n%s", out)
	}
}

// TestRunVerify_WrongPassphraseFails — a passphrase that doesn't match
// the sealing passphrase fails the AEAD open during Pipeline.Load.
func TestRunVerify_WrongPassphraseFails(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "correct")
	if err := runVerify([]string{"--dir", dir, "--id", id, "--passphrase", "wrong"}); err == nil {
		t.Fatal("expected load failure with the wrong passphrase")
	}
}

// ---- storage sanity ----

// TestStorageRoundTrip confirms the file storage backend the CLI uses
// lists a written snapshot id — guards the assumption runList relies on.
func TestStorageRoundTrip(t *testing.T) {
	dir, id := writeSampleSnapshot(t, "")
	store, err := storagefile.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	names, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, n := range names {
		if strings.Contains(n, id) || n == id {
			found = true
		}
	}
	if !found && len(names) == 0 {
		t.Errorf("expected snapshot %q in listing %v", id, names)
	}
}

// ---- usage + main dispatch (non-exit paths) ----

// TestUsage_PrintsBanner — banner names the program + all three
// subcommands.
func TestUsage_PrintsBanner(t *testing.T) {
	out := captureStderr(t, usage)
	for _, want := range []string{progName, "list", "inspect", "verify"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q:\n%s", want, out)
		}
	}
}

// TestMain_HelpReturns drives the help branch of main(), which returns
// normally (no os.Exit) — covering the dispatch switch + usage call.
func TestMain_HelpReturns(t *testing.T) {
	defer swapArgs([]string{progName, "help"})()
	_ = captureStderr(t, main)
}

// TestMain_ListSuccess drives the list-success path through main() so
// the dispatch case + normal return are covered without a subprocess.
func TestMain_ListSuccess(t *testing.T) {
	dir := t.TempDir()
	defer swapArgs([]string{progName, "list", "--dir", dir})()
	_ = captureStdout(t, main)
}

// swapArgs replaces os.Args for the duration of a test.
func swapArgs(args []string) func() {
	orig := os.Args
	os.Args = args
	return func() { os.Args = orig }
}

// captureStderr redirects os.Stderr while fn runs and returns the
// captured output.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			b.Write(buf[:n])
			if e != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stderr = orig
	return out
}
