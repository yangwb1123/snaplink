package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
)

// readAuditSinkFile reads the file a formatter sink was configured to
// append to. Audit.async is left disabled in every test below, so the
// Recorder drives sinks synchronously and the write is complete by the
// time Record returns — matching the existing webhook wiring tests'
// no-polling convention.
func readAuditSinkFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(b)
}

func TestBuildApp_AuditCEFRequiresOutput(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.CEF.Enabled = true
	// Output omitted on purpose.

	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("expected error when audit.cef.enabled with no output")
	}
}

func TestBuildApp_AuditCEFWritesToFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.cef")

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.CEF.Enabled = true
	cfg.Audit.CEF.Output = path

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-cef"})

	got := readAuditSinkFile(t, path)
	if !strings.HasPrefix(got, "CEF:0|Snaplink|SSO|") {
		t.Fatalf("expected a CEF:0 line, got %q", got)
	}
	if !strings.Contains(got, "suser=user-cef") {
		t.Fatalf("expected suser=user-cef, got %q", got)
	}
}

func TestBuildApp_AuditOCSFWritesToFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf")

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.OCSF.Enabled = true
	cfg.Audit.OCSF.Output = path

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-ocsf"})

	got := readAuditSinkFile(t, path)
	if !strings.Contains(got, `"class_uid":3002`) {
		t.Fatalf("expected an OCSF Authentication class_uid, got %q", got)
	}
	if !strings.Contains(got, `"uid":"user-ocsf"`) {
		t.Fatalf("expected actor.user.uid=user-ocsf, got %q", got)
	}
}

func TestBuildApp_AuditSyslogWritesToFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.syslog")

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Syslog.Enabled = true
	cfg.Audit.Syslog.Output = path
	cfg.Audit.Syslog.AppName = "sso-test"

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-syslog"})

	got := readAuditSinkFile(t, path)
	if !strings.HasPrefix(got, "<86>1 ") {
		// facility default (authpriv=10)*8 + info severity(6) = 86.
		t.Fatalf("expected RFC 5424 PRI <86>, got %q", got)
	}
	if !strings.Contains(got, "sso-test") {
		t.Fatalf("expected configured app-name sso-test, got %q", got)
	}
}

// TestBuildApp_AuditSIEMReceivesRedactedEvents is the required wiring test:
// SIEM sinks are composed AFTER PII redaction inside the Recorder, so the
// raw ActorID/ActorIP must NEVER reach the CEF output when
// audit.pii_redaction.enabled is set — same guarantee the webhook sink
// already gets.
func TestBuildApp_AuditSIEMReceivesRedactedEvents(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.cef")

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.PIIRedaction.Enabled = true
	cfg.Audit.PIIRedaction.Salt = "test-salt"
	cfg.Audit.CEF.Enabled = true
	cfg.Audit.CEF.Output = path

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{
		Type: audit.EventLogin, ActorID: "alice", ActorIP: "203.0.113.42",
	})

	got := readAuditSinkFile(t, path)
	if strings.Contains(got, "suser=alice") {
		t.Fatalf("raw ActorID leaked into CEF output (redaction not applied before sink): %q", got)
	}
	if strings.Contains(got, "src=203.0.113.42") {
		t.Fatalf("raw ActorIP leaked into CEF output (redaction not applied before sink): %q", got)
	}
	if !strings.Contains(got, "suser=h:") {
		t.Fatalf("expected hashed suser=h:... redaction marker, got %q", got)
	}
	if !strings.Contains(got, "src=203.0.113.0/24") {
		t.Fatalf("expected /24-truncated src, got %q", got)
	}
}

// TestBuildApp_AuditSIEMAllThreeIndependentlyEnabled proves the three
// audit.cef/audit.ocsf/audit.syslog blocks are independently pluggable —
// enabling all three at once fans the same event into all three files.
func TestBuildApp_AuditSIEMAllThreeIndependentlyEnabled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cefPath := filepath.Join(dir, "audit.cef")
	ocsfPath := filepath.Join(dir, "audit.ocsf")
	syslogPath := filepath.Join(dir, "audit.syslog")

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.CEF.Enabled, cfg.Audit.CEF.Output = true, cefPath
	cfg.Audit.OCSF.Enabled, cfg.Audit.OCSF.Output = true, ocsfPath
	cfg.Audit.Syslog.Enabled, cfg.Audit.Syslog.Output = true, syslogPath

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "u"})

	for _, p := range []string{cefPath, ocsfPath, syslogPath} {
		if got := readAuditSinkFile(t, p); got == "" {
			t.Errorf("%s: expected non-empty output", p)
		}
	}
}

// TestBuildApp_AuditSIEMComposesWithMemoryQuery proves enabling a SIEM sink
// doesn't disturb the in-process /audit query path (MultiSink keeps the
// primary MemorySink queryable — mirrors the equivalent webhook assertion).
func TestBuildApp_AuditSIEMComposesWithMemoryQuery(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.cef")

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.CEF.Enabled = true
	cfg.Audit.CEF.Output = path

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "u"})

	got, err := a.recorder.Sink().Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Type != audit.EventLogin {
		t.Fatalf("Query returned %+v, want one login event", got)
	}
}
