package auditexport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
	libexport "github.com/snaplink/sso/platform/audit/auditexport"
	auditsqlite "github.com/snaplink/sso/platform/audit/sqlite"
)

// seedStore records n hash-chained events into a fresh SQLite audit
// store at dsn and closes it, leaving a durable chain for the CLI to
// export.
func seedStore(t *testing.T, dsn string, n int) {
	t.Helper()
	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer func() { _ = sink.Close() }()
	base := time.Unix(1700000000, 0).UTC()
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return base.Add(time.Duration(i) * time.Hour)
	}))
	for k := 0; k < n; k++ {
		r.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "user"})
	}
}

func TestRun_ExportToFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "evidence.json")
	seedStore(t, dsn, 5)

	code := captureQuiet(t, func() int { return Run([]string{"--dsn", dsn, "--out", out}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if b.EventCount != 5 {
		t.Fatalf("EventCount=%d, want 5", b.EventCount)
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("on-disk bundle failed verify: %v", err)
	}
}

func TestRun_ExportToStdout(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	seedStore(t, dsn, 3)

	var code int
	out := captureStdout(t, func() { code = Run([]string{"--dsn", dsn}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatalf("stdout is not a JSON bundle: %v\n%s", err, out)
	}
	if b.EventCount != 3 {
		t.Fatalf("EventCount=%d, want 3", b.EventCount)
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("stdout bundle failed verify: %v", err)
	}
}

func TestRun_EmptyWindowExitsZero(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "empty.json")
	seedStore(t, dsn, 3)

	code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", dsn, "--since", "2100-01-01T00:00:00Z", "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0 for an empty window", code)
	}
	raw, _ := os.ReadFile(out)
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount != 0 {
		t.Fatalf("EventCount=%d, want 0", b.EventCount)
	}
}

func TestRun_TenantAndTypeFilter(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	out := filepath.Join(dir, "filtered.json")
	seedStore(t, dsn, 4)

	code := captureQuiet(t, func() int {
		return Run([]string{"--dsn", dsn, "--type", string(audit.EventLogout), "--out", out})
	})
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	raw, _ := os.ReadFile(out)
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// No logout events were seeded → empty, and a filtered bundle is
	// marked non-contiguous.
	if b.Contiguous {
		t.Error("type-filtered bundle should be non-contiguous")
	}
	if err := libexport.VerifyExportBundle(&b); err != nil {
		t.Errorf("filtered bundle failed verify: %v", err)
	}
}

func TestRun_OpenErrorExitsOne(t *testing.T) {
	// A read-only DSN pointed at a missing file fails to open.
	dsn := "file:" + filepath.Join(t.TempDir(), "missing.db") + "?mode=ro"
	code, err := run(options{dsn: dsn})
	if code != 1 || err == nil {
		t.Fatalf("run over missing ro db: code=%d err=%v, want (1, err)", code, err)
	}
}

func TestBuildQuery_BadSince(t *testing.T) {
	if _, err := buildQuery(options{since: "not-a-time"}); err == nil {
		t.Error("bad --since should error")
	}
	if _, err := buildQuery(options{until: "not-a-time"}); err == nil {
		t.Error("bad --until should error")
	}
}

func TestBuildQuery_MapsFilters(t *testing.T) {
	q, err := buildQuery(options{
		typ: "login", actorID: "u1", tenantID: "t1", limit: 7,
		since: "1700000000", until: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	if q.Type != audit.EventType("login") || q.ActorID != "u1" || q.TenantID != "t1" || q.Limit != 7 {
		t.Errorf("filters not mapped: %+v", q)
	}
	if q.Since.IsZero() || q.Until.IsZero() {
		t.Errorf("time bounds not parsed: since=%v until=%v", q.Since, q.Until)
	}
}

func TestParseTime(t *testing.T) {
	if _, err := parseTime("2026-01-01T00:00:00Z"); err != nil {
		t.Errorf("RFC3339: %v", err)
	}
	if got, err := parseTime("1700000000"); err != nil || got.Unix() != 1700000000 {
		t.Errorf("unix seconds: got=%v err=%v", got, err)
	}
	if _, err := parseTime("garbage"); err == nil {
		t.Error("garbage should error")
	}
}

func TestUsage_PrintsBanner(t *testing.T) {
	out := captureStderr(t, usage)
	for _, want := range []string{progName, "--dsn"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q:\n%s", want, out)
		}
	}
}

// captureQuiet runs fn with BOTH stdout and stderr redirected to
// discard so a bundle dump / summary doesn't pollute test output, and
// returns fn's exit code.
func captureQuiet(t *testing.T, fn func() int) int {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = devnull, devnull
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
		_ = devnull.Close()
	}()
	return fn()
}

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
	return strings.TrimSpace(out)
}
