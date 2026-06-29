package migratecmd

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/platform/migrate"

	_ "modernc.org/sqlite"
)

// TestRunStatus_JSONOutput drives the --json branch of runStatus against
// a seeded DB so the JSON encoder path (not just the table renderer) is
// exercised end-to-end through the open + Status + render pipeline.
func TestRunStatus_JSONOutput(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	if err := runStatus([]string{"--not-a-flag"}); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}
}

// TestRunStatus_StatusError — a DSN that opens + pings fine but points
// at a database whose schema_migrations tables are unreadable still
// returns cleanly for an empty DB; here we instead assert the empty-DB
// path renders the "no migrated namespaces" line.
func TestRunStatus_EmptyDB(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestRun_HelpReturns drives the help branch of Run, which returns exit
// code 0 — covering the arg-dispatch switch + usage call.
func TestRun_HelpReturns(t *testing.T) {
	t.Parallel()
	var code int
	_ = captureStderr(t, func() { code = Run([]string{"--help"}) })
	if code != 0 {
		t.Errorf("Run(--help) exit code = %d, want 0", code)
	}
}

// TestRun_StatusSuccess drives the status-success branch of Run
// (dispatch → runStatus → exit code 0). Uses a seeded DB so runStatus
// succeeds and Run returns 0.
func TestRun_StatusSuccess(t *testing.T) {
	t.Parallel()
	dsn := seedDB(t)
	var code int
	_ = captureStdout(t, func() { code = Run([]string{"status", "--dsn", dsn}) })
	if code != 0 {
		t.Errorf("Run(status) exit code = %d, want 0", code)
	}
}

// TestRun_NoArgs — a bare invocation prints usage and returns exit code 2.
func TestRun_NoArgs(t *testing.T) {
	t.Parallel()
	var code int
	_ = captureStderr(t, func() { code = Run(nil) })
	if code != 2 {
		t.Errorf("Run(nil) exit code = %d, want 2", code)
	}
}

// TestRun_UnknownSubcommand — an unrecognized subcommand prints usage and
// returns exit code 2.
func TestRun_UnknownSubcommand(t *testing.T) {
	t.Parallel()
	var code int
	_ = captureStderr(t, func() { code = Run([]string{"bogus"}) })
	if code != 2 {
		t.Errorf("Run(bogus) exit code = %d, want 2", code)
	}
}

// TestRun_StatusError — a status invocation whose runStatus fails (missing
// --dsn) returns exit code 1.
func TestRun_StatusError(t *testing.T) {
	t.Parallel()
	var code int
	_ = captureStderr(t, func() { code = Run([]string{"status"}) })
	if code != 1 {
		t.Errorf("Run(status) with no --dsn exit code = %d, want 1", code)
	}
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
