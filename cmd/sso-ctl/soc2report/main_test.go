package soc2report

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
	"github.com/snaplink/sso/platform/audit/auditreport"
)

// seedBundle records n hash-chained login events into a fresh
// MemorySink, builds a real ExportBundle, and writes it to path — a
// local stand-in for what `sso-ctl audit-export` would have produced,
// so this test does not need that sibling package to exist to be
// written (it does exist at HEAD, but the coupling stays one-directional:
// this test constructs the fixture directly via the library).
func seedBundle(t *testing.T, path string, n int) {
	t.Helper()
	sink := audit.NewMemorySink(n + 1)
	base := time.Unix(1700000000, 0).UTC()
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return base.Add(time.Duration(i) * time.Hour)
	}))
	for k := 0; k < n; k++ {
		typ := audit.EventLogin
		if k%3 == 0 {
			typ = audit.EventAdminClientCreated
		}
		r.Record(context.Background(), &audit.Event{Type: typ, Outcome: audit.OutcomeSuccess, ActorID: "user"})
	}
	b, err := libexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

func TestRun_SOC2ReportHappyPath(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	out := filepath.Join(dir, "soc2.json")
	seedBundle(t, bundlePath, 5)

	code := captureQuiet(t, func() int { return Run([]string{"--bundle", bundlePath, "--out", out}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report auditreport.SOC2Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !report.Chain.Verified {
		t.Error("Chain.Verified should be true over an untampered bundle")
	}
	if len(report.ControlAreas) == 0 {
		t.Error("ControlAreas should be non-empty")
	}
	if report.MappingDisclaimer == "" {
		t.Error("mapping_disclaimer must be present")
	}
	if report.Chain.EventCount != 5 {
		t.Errorf("Chain.EventCount=%d, want 5", report.Chain.EventCount)
	}
}

func TestRun_SOC2ReportToStdout(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	seedBundle(t, bundlePath, 3)

	var code int
	out := captureStdout(t, func() { code = Run([]string{"--bundle", bundlePath}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0", code)
	}
	var report auditreport.SOC2Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("stdout is not a JSON report: %v\n%s", err, out)
	}
	if report.Chain.EventCount != 3 {
		t.Errorf("Chain.EventCount=%d, want 3", report.Chain.EventCount)
	}
}

// TestRun_TamperedBundleFailsClosed corrupts one field in the exported
// bundle then calls the low-level run() core directly (NOT the Run()
// CLI wrapper, whose errorf path calls os.Exit(1) and would kill the
// test process — mirrors auditexport_test.go's TestRun_OpenErrorExitsOne
// / TestRunVerify_TamperFails convention): exit 1, and --out must NEVER
// be created — refusing to leave a report file that looks valid but was
// built over unverified evidence.
func TestRun_TamperedBundleFailsClosed(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	out := filepath.Join(dir, "soc2.json")
	seedBundle(t, bundlePath, 5)

	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	b.Events[2].ActorID = "tampered"
	tampered, err := json.Marshal(&b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(bundlePath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered bundle: %v", err)
	}

	code, err := run(options{bundle: bundlePath, out: out})
	if code != 1 || err == nil {
		t.Fatalf("run(tampered) = (%d, %v), want (1, err)", code, err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("--out must not be created on verify failure, got err=%v", statErr)
	}
}

// TestValidateOptions_RequiresBundle covers the CLI-misuse path (exit 2
// in Run, via usageErr) without invoking os.Exit directly — usageErr
// itself is a thin, untested-in-isolation wrapper shared with every
// other sso-ctl subcommand's identical convention (auditverify,
// auditexport), so exercising the decision it's gated on is what
// matters here.
func TestValidateOptions_RequiresBundle(t *testing.T) {
	if err := validateOptions(options{}); err == nil {
		t.Error("empty --bundle should be a validation error")
	}
	if err := validateOptions(options{bundle: "evidence.json"}); err != nil {
		t.Errorf("a non-empty --bundle should validate: %v", err)
	}
}

func TestRun_UnreadableBundlePathExitsOne(t *testing.T) {
	code, err := run(options{bundle: filepath.Join(t.TempDir(), "missing.json")})
	if code != 1 || err == nil {
		t.Fatalf("run(missing) = (%d, %v), want (1, err)", code, err)
	}
}

func TestRun_CorruptJSONExitsOne(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, err := run(options{bundle: bundlePath})
	if code != 1 || err == nil {
		t.Fatalf("run(corrupt json) = (%d, %v), want (1, err)", code, err)
	}
}

func TestRun_EmptyBundleExitsZero(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	out := filepath.Join(dir, "soc2.json")
	seedBundle(t, bundlePath, 0)

	code := captureQuiet(t, func() int { return Run([]string{"--bundle", bundlePath, "--out", out}) })
	if code != 0 {
		t.Fatalf("Run exit=%d, want 0 for an empty bundle", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report auditreport.SOC2Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if report.Chain.EventCount != 0 {
		t.Errorf("Chain.EventCount=%d, want 0", report.Chain.EventCount)
	}
}

func TestUsage_PrintsDisclaimerAndBanner(t *testing.T) {
	out := captureStderr(t, usage)
	for _, want := range []string{progName, "--bundle", "NOT a vetted SOC2"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q:\n%s", want, out)
		}
	}
}

// captureQuiet runs fn with BOTH stdout and stderr redirected to
// discard so a report dump / summary doesn't pollute test output, and
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
