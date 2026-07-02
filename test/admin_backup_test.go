package ssotest

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
)

// sqliteBackupSource adapts a real modernc SQLite store into a
// core.BackupSource the way an SDK operator would: VACUUM INTO against
// the store's live *sql.DB. No mocks — the destination file is a real
// SQLite database, so the size/duration metadata assertions are honest.
type sqliteBackupSource struct {
	name string
	db   *sql.DB
}

func (b sqliteBackupSource) Name() string { return b.name }
func (b sqliteBackupSource) BackupTo(ctx context.Context, dest string) error {
	_, err := b.db.ExecContext(ctx, "VACUUM INTO ?", dest)
	return err
}

func newBackupHarness(t *testing.T, opts ...sso.Option) *httptest.Server {
	t.Helper()
	store, err := sqlitestores.NewClientStore("file:backup_clients_" + t.Name() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	opts = append(opts, sso.WithBackupSource(sqliteBackupSource{name: "clients", db: store.DB()}))
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func backupPOST(t *testing.T, base string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(base+"/api/v1/admin/backup", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	return resp.StatusCode, out
}

func firstSource(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, ok := body["sources"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("missing sources array: %v", body)
	}
	entry, ok := raw[0].(map[string]any)
	if !ok {
		t.Fatalf("source entry not an object: %v", raw[0])
	}
	return entry
}

func TestAdminBackup_WritesToConfiguredDirWithMetadata(t *testing.T) {
	dir := t.TempDir()
	srv := newBackupHarness(t, sso.WithBackupDir(dir))
	code, body := backupPOST(t, srv.URL)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	entry := firstSource(t, body)
	if entry["status"] != "ok" {
		t.Fatalf("source status = %v, want ok: %v", entry["status"], entry)
	}
	path, _ := entry["path"].(string)
	if filepath.Dir(path) != dir {
		t.Errorf("path %q not under configured dir %q", path, dir)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("backup file missing on disk: %v", err)
	}
	if sz, _ := entry["size_bytes"].(float64); int64(sz) != fi.Size() || fi.Size() == 0 {
		t.Errorf("size_bytes = %v, want on-disk size %d (> 0)", entry["size_bytes"], fi.Size())
	}
	if _, ok := entry["duration_ms"].(float64); !ok {
		t.Errorf("missing duration_ms: %v", entry)
	}
}

func TestAdminBackup_RetentionPrunesOldestKeepingNewestN(t *testing.T) {
	dir := t.TempDir()
	// Stale backups with fixed-width timestamps: lexicographic sort ==
	// chronological, so these three are strictly older than the fresh one.
	stale := []string{
		"sso-backup-clients-20200101T000000.000000000.db",
		"sso-backup-clients-20200102T000000.000000000.db",
		"sso-backup-clients-20200103T000000.000000000.db",
	}
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A foreign file sharing the dir but not the per-source prefix must
	// survive (mirrors snapshot.PruneOldest's prefix-filter guarantee).
	foreign := filepath.Join(dir, "operator-notes.txt")
	if err := os.WriteFile(foreign, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := newBackupHarness(t, sso.WithBackupDir(dir), sso.WithBackupRetention(2))
	code, body := backupPOST(t, srv.URL)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	entry := firstSource(t, body)
	if pruned, _ := entry["pruned"].(float64); int(pruned) != 2 {
		t.Errorf("pruned = %v, want 2 (3 stale + 1 fresh, keep 2)", entry["pruned"])
	}
	if _, err := os.Stat(filepath.Join(dir, stale[0])); !os.IsNotExist(err) {
		t.Errorf("oldest stale backup survived pruning")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign file was wrongly deleted: %v", err)
	}
}
