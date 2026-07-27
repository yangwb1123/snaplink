package sso

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
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

// --- Compliance reporting + automated data retention (protocols/compliance) ---
//
// Path consts + admin-route wiring live here rather than shared/core/consts.go
// / server_routes_admin.go / options_admin.go: all three sit within a few
// lines of the 500-line maintainability budget, while this file has the most
// headroom of any in the package. See server_routes_admin.go's Token
// Portfolio consts for the established precedent of localizing new admin
// route paths to their mounting file when the canonical file has no room.
const (
	PathAdminComplianceSOC2Evidence   = "/admin/compliance/soc2-evidence"
	PathAdminComplianceDataMap        = "/admin/compliance/data-map"
	PathAdminComplianceConsents       = "/admin/compliance/consents"
	PathAdminComplianceRetentionSweep = "/admin/compliance/retention-sweep"
)

// WithDataRetentionSweep opts into the automated data-retention sweep
// (protocols/compliance.RetentionSweeper): session-TTL cleanup, dormant-
// account flagging (or, with cfg.AutoEraseDormant, erasure via the
// self-service Eraser wired by WithSelfServiceAccountErasure), and a
// report-only count of audit events past a configured retention window. OFF
// by default (cfg.Enabled == false is the zero value); even when configured,
// the operator must start Server.RunDataRetentionSweep in a goroutine — the
// same discipline as RunBreakGlassSweeper. A build that never calls this
// option is byte-identical to one without the feature.
func WithDataRetentionSweep(cfg compliance.RetentionConfig) Option {
	return func(s *Server) { s.dataRetention = cfg }
}

// retentionSweeper assembles a compliance.RetentionSweeper from currently-
// wired server state. It reuses the self-service Eraser
// (WithSelfServiceAccountErasure) for the dormant-account auto-erase step
// rather than requiring a second wiring option — Eraser.EraseSubject already
// accepts any subject id, not just the caller's own.
func (s *Server) retentionSweeper() *compliance.RetentionSweeper {
	return &compliance.RetentionSweeper{
		Users:    s.userProvider,
		Sessions: s.sessionMgr,
		Eraser:   s.accountEraser,
		Auditor:  s.auditor,
		Logger:   s.logger,
	}
}

// mountAdminCompliance registers the compliance-reporting admin surface: the
// SOC2 evidence pack + GDPR Art. 30 data map + active-consents report
// (admin:read), and the data-retention-sweep manual trigger (admin:write).
// The data map is static/code-derived, so it needs no backing store and is
// always mounted within the admin surface; the other reports mount only when
// their backing data source is wired, and the retention trigger mounts only
// when WithDataRetentionSweep configured it on — each byte-identical to a
// build without the respective feature.
func (s *Server) mountAdminCompliance(api Router) {
	api.GET(PathAdminComplianceDataMap, s.handleAdminComplianceDataMap)
	if s.auditor != nil {
		api.GET(PathAdminComplianceSOC2Evidence, s.handleAdminSOC2Evidence)
	}
	if s.consentStore != nil && s.userProvider != nil {
		api.GET(PathAdminComplianceConsents, s.handleAdminActiveConsents)
	}
	if s.dataRetention.Enabled {
		api.POST(PathAdminComplianceRetentionSweep, s.handleAdminTriggerRetentionSweep)
	}
}

func (s *Server) handleAdminSOC2Evidence(ctx HandlerContext) {
	r := &compliance.SOC2Reporter{Permissions: s.permissions, Clients: s.clientStore, Audit: s.auditor.Sink()}
	compliance.HandleAdminSOC2Report(r, s.logger, ctx)
}

func (s *Server) handleAdminComplianceDataMap(ctx HandlerContext) {
	opts := compliance.DataMapOptions{ConsentMaxTTL: s.consentMaxTTL}
	compliance.HandleAdminDataMap(opts, s.logger, ctx)
}

func (s *Server) handleAdminActiveConsents(ctx HandlerContext) {
	r := &compliance.ActiveConsentsReporter{Users: s.userProvider, Consent: s.consentStore}
	compliance.HandleAdminActiveConsents(r, s.logger, ctx)
}

func (s *Server) handleAdminTriggerRetentionSweep(ctx HandlerContext) {
	compliance.HandleAdminTriggerRetentionSweep(s.retentionSweeper(), s.dataRetention, s.logger, ctx)
}

// RunDataRetentionSweep wakes every interval and runs one automated
// data-retention sweep (protocols/compliance.RetentionSweeper.Sweep). Same
// shutdown contract as RunBreakGlassSweeper: it exits on ctx cancellation, a
// sweep error is logged but never tears down the loop, and starting it is the
// OPERATOR's responsibility — NewServer/Mount never start it, so embedding
// the SDK never leaks the goroutine.
//
//	go srv.RunDataRetentionSweep(ctx, time.Hour)
//
// No-op when the sweep is disabled (WithDataRetentionSweep not called, or
// cfg.Enabled == false) or interval <= 0 — byte-identical to a build without it.
func (s *Server) RunDataRetentionSweep(ctx context.Context, interval time.Duration) {
	if !s.dataRetention.Enabled || interval <= 0 {
		return
	}
	sweeper := s.retentionSweeper()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := sweeper.Sweep(ctx, s.dataRetention); err != nil {
				s.logger.Error("data retention sweep failed", "error", err)
			}
		}
	}
}
