package sso

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// backupStampLayout is fixed-width + zero-padded so lexicographic order
// of filenames equals chronological order — the pruner relies on it.
const (
	backupStampLayout = "20060102T150405.000000000"
	backupFileExt     = ".db"
)

// handleAdminBackup triggers an online backup of each registered SQLite
// backup source via VACUUM INTO and returns a per-source result summary.
func (s *Server) handleAdminBackup(ctx HandlerContext) {
	dir := s.backupDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.logger.Error("backup dir create failed", "dir", dir, "error", err)
	}
	results := make([]map[string]any, 0, len(s.backupSources))
	for _, src := range s.backupSources {
		results = append(results, s.backupOneSource(ctx, src, dir))
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyStatus: StatusOK, "sources": results})
}

// backupOneSource runs a single VACUUM INTO and reports operator metadata.
// Failures stay per-source (endpoint always 200s a summary — same
// fail-open contract as storage-health); detail goes to the log only.
func (s *Server) backupOneSource(ctx HandlerContext, src core.BackupSource, dir string) map[string]any {
	prefix := core.BackupFilePrefix + filepath.Base(src.Name()) + "-"
	dest := filepath.Join(dir, prefix+time.Now().UTC().Format(backupStampLayout)+backupFileExt)
	start := time.Now()
	if err := src.BackupTo(ctx.Request().Context(), dest); err != nil {
		s.logger.Error("backup failed", "source", src.Name(), "error", err)
		return map[string]any{"name": src.Name(), "status": "failed"}
	}
	out := map[string]any{
		"name":        src.Name(),
		"status":      StatusOK,
		"path":        dest,
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if fi, err := os.Stat(dest); err == nil {
		out["size_bytes"] = fi.Size()
	}
	if s.backupKeep > 0 {
		pruned, err := pruneBackups(dir, prefix, s.backupKeep)
		if err != nil {
			s.logger.Error("backup prune failed", "source", src.Name(), "error", err)
		}
		out["pruned"] = pruned
	}
	return out
}

// pruneBackups mirrors snapshot.PruneOldest: prefix-filter so foreign
// files in the shared dir are never deleted, sort ascending (fixed-width
// stamps make lexicographic == chronological), remove all but the newest
// keep, first error wins but pruning continues.
func pruneBackups(dir, prefix string, keep int) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), backupFileExt) {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return 0, nil
	}
	sort.Strings(names)
	var pruned int
	var firstErr error
	for _, n := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pruned++
	}
	return pruned, firstErr
}
