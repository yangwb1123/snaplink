package main

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/platform/migrate"

	_ "modernc.org/sqlite"
)

func seedDB(t *testing.T) string {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "sso.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := migrate.Run(context.Background(), db, "audit",
		[]migrate.Migration{{Version: 1, Name: "baseline", SQL: `CREATE TABLE IF NOT EXISTS x (a TEXT)`}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return dsn
}

func TestRunStatus_RequiresDSN(t *testing.T) {
	if err := runStatus(nil); err == nil {
		t.Fatal("expected error when --dsn is missing")
	}
}

func TestRunStatus_HappyPath(t *testing.T) {
	if err := runStatus([]string{"--dsn", seedDB(t)}); err != nil {
		t.Fatalf("runStatus: %v", err)
	}
}

func TestRunStatus_BadDSN(t *testing.T) {
	// A path under a nonexistent directory can't be opened/pinged.
	if err := runStatus([]string{"--dsn", "file:/nonexistent-dir-xyz/none.db?mode=ro"}); err == nil {
		t.Fatal("expected error opening a non-existent read-only DB")
	}
}

func TestRenderStatus_Table(t *testing.T) {
	var buf bytes.Buffer
	st := []migrate.NamespaceStatus{{Namespace: "audit", Version: 3, Name: "add_index"}}
	if err := renderStatus(&buf, st, false); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"NAMESPACE", "audit", "3", "add_index"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderStatus_JSON(t *testing.T) {
	var buf bytes.Buffer
	st := []migrate.NamespaceStatus{{Namespace: "tenant", Version: 1, Name: "baseline"}}
	if err := renderStatus(&buf, st, true); err != nil {
		t.Fatalf("render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"Namespace": "tenant"`) {
		t.Errorf("json output unexpected:\n%s", buf.String())
	}
}

func TestRenderStatus_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := renderStatus(&buf, nil, false); err != nil {
		t.Fatalf("render empty: %v", err)
	}
	if !strings.Contains(buf.String(), "no migrated namespaces") {
		t.Errorf("empty output unexpected:\n%s", buf.String())
	}
}
