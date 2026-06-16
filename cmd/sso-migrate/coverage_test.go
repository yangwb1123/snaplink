package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/migrate"

	_ "modernc.org/sqlite"
)

// TestRunStatus_JSONOutput drives the --json branch of runStatus against
// a seeded DB so the JSON encoder path (not just the table renderer) is
// exercised end-to-end through the open + Status + render pipeline.
func TestRunStatus_JSONOutput(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runStatus([]string{"--dsn", seedDB(t), "--json"}); err != nil {
			t.Fatalf("runStatus --json: %v", err)
		}
	})
	if !strings.Contains(out, `"Namespace"`) {
		t.Errorf("json output missing Namespace key:\n%s", out)
	}
}

// TestRunStatus_TableOutput drives the table branch of runStatus end to
// end (open + Status + table render), confirming the seeded namespace
// surfaces in the header-prefixed rows.
func TestRunStatus_TableOutput(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runStatus([]string{"--dsn", seedDB(t)}); err != nil {
			t.Fatalf("runStatus table: %v", err)
		}
	})
	if !strings.Contains(out, "NAMESPACE") || !strings.Contains(out, "audit") {
		t.Errorf("table output missing header/namespace:\n%s", out)
	}
}

// TestRunStatus_BadFlag — an unknown flag makes the flag set's Parse
// fail, which runStatus surfaces as an error rather than panicking.
func TestRunStatus_BadFlag(t *testing.T) {
	if err := runStatus([]string{"--not-a-flag"}); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}
}

// TestRunStatus_StatusError — a DSN that opens + pings fine but points
// at a database whose schema_migrations tables are unreadable still
// returns cleanly for an empty DB; here we instead assert the empty-DB
// path renders the "no migrated namespaces" line.
func TestRunStatus_EmptyDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "empty.db")
	out := captureStdout(t, func() {
		if err := runStatus([]string{"--dsn", dsn}); err != nil {
			t.Fatalf("runStatus empty: %v", err)
		}
	})
	if !strings.Contains(out, "no migrated namespaces") {
		t.Errorf("empty DB should report no namespaces:\n%s", out)
	}
}

// TestRunStatus_StatusReadError drives the migrate.Status error path
// (and runStatus's wrap of it). A schema_migrations_* table that lacks
// the expected version/name/applied_at columns makes the per-table
// SELECT fail, so Status returns an error the CLI surfaces.
func TestRunStatus_StatusReadError(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "broken.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Malformed namespace table: present so Status discovers it, but with
	// the wrong columns so the version SELECT errors.
	if _, err := db.ExecContext(context.Background(),
		`CREATE TABLE schema_migrations_broken (wrong_col TEXT); INSERT INTO schema_migrations_broken VALUES ('x')`); err != nil {
		t.Fatalf("seed broken table: %v", err)
	}
	_ = db.Close()

	if err := runStatus([]string{"--dsn", dsn}); err == nil {
		t.Fatal("expected error reading a malformed schema_migrations table")
	}
}

// TestUsage_PrintsBanner — the usage banner names the program + the
// status subcommand so a bare invocation is actionable.
func TestUsage_PrintsBanner(t *testing.T) {
	out := captureStderr(t, usage)
	for _, want := range []string{progName, "status", "--dsn"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q:\n%s", want, out)
		}
	}
}

// TestStatus_OnSeededDB sanity-checks the migrate.Status read the CLI
// relies on: a DB seeded with one namespace reports version 1 for it.
func TestStatus_OnSeededDB(t *testing.T) {
	dsn := seedDB(t)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st, err := migrate.Status(context.Background(), db)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st) == 0 {
		t.Fatal("expected at least one namespace from seeded DB")
	}
}

// TestMain_HelpReturns drives the help branch of main(), which returns
// normally (no os.Exit) — covering the arg-dispatch switch + usage call
// without spawning a subprocess.
func TestMain_HelpReturns(t *testing.T) {
	defer swapArgs([]string{progName, "--help"})()
	_ = captureStderr(t, main) // returns; must not exit the test process
}

// TestMain_StatusSuccess drives the status-success branch of main()
// (dispatch → runStatus → non-error return). Uses a seeded DB so
// runStatus succeeds and main() falls through to its normal return.
func TestMain_StatusSuccess(t *testing.T) {
	dsn := seedDB(t)
	defer swapArgs([]string{progName, "status", "--dsn", dsn})()
	_ = captureStdout(t, main)
}

// swapArgs replaces os.Args for the duration of a test, returning a
// restore func to defer.
func swapArgs(args []string) func() {
	orig := os.Args
	os.Args = args
	return func() { os.Args = orig }
}

// captureStdout redirects os.Stdout while fn runs and returns the
// trimmed captured output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
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
	os.Stdout = orig
	return strings.TrimSpace(out)
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
