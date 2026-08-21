package sso

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
)

// PathAdminConfigApply / PathAdminConfigRollback re-export core's paths here
// for the apply/rollback route mounts below — aliases.go is at its frozen
// 500-line budget, and this file hosts the config-audit mount already (the
// same localization precedent as the compliance path consts above).
const (
	PathAdminConfigApply    = core.PathAdminConfigApply
	PathAdminConfigRollback = core.PathAdminConfigRollback
)

// ConfigAuditStore returns nil when runtime configuration history is unwired.
func (s *Server) ConfigAuditStore() configaudit.Store { return s.configAuditStore }

// ConfigCanaryController returns the optional configuration-baseline canary.
func (s *Server) ConfigCanaryController() *configaudit.CanaryController {
	return s.configCanaryController
}

// AppliedConfigSnapshot returns the redacted effective configuration captured
// at startup, OR — after a POST /api/v1/admin/config/apply established a
// declared peer-config baseline — the redacted latest applied baseline from
// the config-audit store (see docs/design/config-apply-mode.md Decision 2).
// The sentinel lets the HTTP layer distinguish unwired snapshots from an
// internal failure and answer 501. The baseline lookup is fail-open: a store
// read error logs and falls back to the startup capture (observability view,
// never a decision input), and before the FIRST apply the store has no
// baseline so every currently-reachable state is byte-identical to today.
func (s *Server) AppliedConfigSnapshot() (map[string]any, error) {
	if s.configAuditStore != nil {
		if v, err := s.configAuditStore.Applied(context.Background()); err == nil && v.Snapshot != nil {
			return v.Snapshot, nil
		} else if err != nil && !errors.Is(err, configaudit.ErrNoAppliedVersion) {
			s.logger.Error("config audit: applied baseline lookup failed, serving startup capture", "error", err)
		}
	}
	if s.configAppliedSnapshot == nil {
		return nil, configaudit.ErrSnapshotUnavailable
	}
	return s.configAppliedSnapshot, nil
}

// RunningConfigSnapshot falls back to the applied snapshot when no live
// source exists, because without a live source there is nothing to drift from.
func (s *Server) RunningConfigSnapshot(ctx context.Context) (map[string]any, error) {
	if s.configRunningSnapshotFn != nil {
		return s.configRunningSnapshotFn(ctx)
	}
	return s.AppliedConfigSnapshot()
}

// applyConfigAuditWiring keeps builds without a config-audit store at zero
// recording cost: the recorder's change hook remains unset.
func (s *Server) applyConfigAuditWiring() {
	if s.auditor != nil && s.configAuditStore != nil {
		s.auditor.SetConfigChangeHook(s.recordConfigHistoryFromAudit)
	}
}

// mountConfigAuditAPI exposes snapshot routes only when a snapshot source
// exists. History is independent so deployments that capture changes without
// snapshots do not mount routes that would fail on every request. The
// apply/rollback write pair (declared peer-config baseline) mounts only when
// BOTH a snapshot source AND a store exist — a build with either missing
// keeps the route set byte-identical.
func (s *Server) mountConfigAuditAPI(api Router) {
	if s.configAppliedSnapshot != nil || s.configRunningSnapshotFn != nil {
		api.GET(PathAdminConfigRunning, s.handleConfigRunning)
		api.GET(PathAdminConfigApplied, s.handleConfigApplied)
		api.GET(PathAdminConfigDiff, s.handleConfigDiff)
		api.POST(PathAdminConfigClusterDiff, s.handleConfigClusterDiff)
	}
	if s.configAuditStore != nil {
		api.GET(PathAdminConfigHistory, s.handleConfigHistory)
	}
	if (s.configAppliedSnapshot != nil || s.configRunningSnapshotFn != nil) && s.configAuditStore != nil {
		api.POST(PathAdminConfigApply, s.handleConfigApply)
		api.POST(PathAdminConfigRollback, s.handleConfigRollback)
	}
}

func (s *Server) handleConfigRunning(ctx HandlerContext)     { configaudit.HandleRunning(s, ctx) }
func (s *Server) handleConfigApplied(ctx HandlerContext)     { configaudit.HandleApplied(s, ctx) }
func (s *Server) handleConfigDiff(ctx HandlerContext)        { configaudit.HandleDiff(s, ctx) }
func (s *Server) handleConfigClusterDiff(ctx HandlerContext) { configaudit.HandleClusterDiff(s, ctx) }
func (s *Server) handleConfigHistory(ctx HandlerContext)     { configaudit.HandleHistory(s, ctx) }

// handleConfigApply / handleConfigRollback stamp the credentialed-response
// no-store headers (the established write-endpoint hygiene, see
// server_extensions.go tokenNoStoreHeaders) BEFORE delegating — the platform
// handler stays transport-independent.
func (s *Server) handleConfigApply(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	configaudit.HandleApply(s, ctx)
}
func (s *Server) handleConfigRollback(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	configaudit.HandleRollback(s, ctx)
}

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
