package soc2report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/auditexport"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditreport"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// TestPipeline_AuditExportThenSOC2Report is the true end-to-end
// composition the brief calls for: it drives the REAL `sso-ctl
// audit-export` entry point (cmd/sso-ctl/auditexport.Run) against a
// SQLite audit store, then feeds the resulting bundle file into this
// package's own Run — proving the two CLI tools compose like a Unix
// pipeline (`sso-ctl audit-export ... | sso-ctl soc2-report ...`)
// without duplicating either tool's internals. A deliberate, test-only
// coupling between two otherwise-independent composition-layer CLI
// packages (lateral import, both cmd/sso-ctl/*) — _test.go files are
// exempt from the per-directory file-count gate regardless.
func TestPipeline_AuditExportThenSOC2Report(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "audit.db")
	bundlePath := filepath.Join(dir, "evidence.json")
	reportPath := filepath.Join(dir, "soc2.json")

	seedSQLiteStore(t, dsn, 6)

	if code := captureQuiet(t, func() int {
		return auditexport.Run([]string{"--dsn", dsn, "--out", bundlePath})
	}); code != 0 {
		t.Fatalf("audit-export Run exit=%d, want 0", code)
	}

	if code := captureQuiet(t, func() int {
		return Run([]string{"--bundle", bundlePath, "--out", reportPath})
	}); code != 0 {
		t.Fatalf("soc2-report Run exit=%d, want 0", code)
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report auditreport.SOC2Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !report.Chain.Verified {
		t.Error("pipeline report should be chain-verified")
	}
	if report.Chain.EventCount != 6 {
		t.Errorf("Chain.EventCount=%d, want 6", report.Chain.EventCount)
	}
}

// seedSQLiteStore records n hash-chained events into a fresh SQLite
// audit store at dsn and closes it — a durable chain for the REAL
// audit-export CLI to read, mirroring
// cmd/sso-ctl/auditexport/main_test.go's own seedStore fixture.
func seedSQLiteStore(t *testing.T, dsn string, n int) {
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
