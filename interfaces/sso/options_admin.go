package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/platform/configaudit"
)

// WithAdminSessionTTL sets an idle timeout for admin bearer tokens. When
// a token has not been used for longer than the TTL, the admin middleware
// rejects the request and the caller must re-authenticate. 0 (default)
// disables idle timeout — tokens remain valid until their exp claim.
//
// The TTL is enforced by the admin middleware, which calls
// AdminTokenStore.Touch() on every successful request and checks
// LastUsedAt against the timeout. Requires WithAdminTokenStore.
//
// Typical value: 30 minutes — aligns with common SOC2/ISO 27001
// session idle-timeout requirements.
//
//	srv := sso.NewServer(
//	    sso.WithAdminTokenStore(store),
//	    sso.WithAdminSessionTTL(30 * time.Minute),
//	)
func WithAdminSessionTTL(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl > 0 {
			s.adminSessionTTL = ttl
		}
	}
}

// WithBackupDir sets the destination directory for POST /api/v1/admin/backup
// (VACUUM INTO snapshots). Empty (default) falls back to the OS temp dir.
func WithBackupDir(dir string) Option {
	return func(s *Server) {
		if dir != "" {
			s.backupDir = dir
		}
	}
}

// WithBackupRetention keeps only the newest keep backup files per source
// after each successful backup. 0 (default) disables pruning.
func WithBackupRetention(keep int) Option {
	return func(s *Server) {
		if keep > 0 {
			s.backupKeep = keep
		}
	}
}

// WithConfigAuditStore wires a platform/configaudit.Store so admin
// mutations (client/tenant/policy changes — see
// Server.recordConfigHistoryFromAudit) are appended to a config_history,
// and mounts GET /api/v1/admin/config/history. Nil (the default) leaves
// both off — byte-identical to a build without the feature.
func WithConfigAuditStore(store configaudit.Store) Option {
	return func(s *Server) { s.configAuditStore = store }
}

// WithConfigSnapshots wires the effective-config snapshots the
// GET /api/v1/admin/config/{running,applied,diff} endpoints serve. applied
// is the redacted config as loaded at startup — capture it ONCE, right
// after config.Load, before any admin mutation could change runtime state.
// runningFn recomputes the CURRENT effective snapshot on demand (called
// per request AND by the drift-detection loop); it may be nil, in which
// case running snapshots fall back to applied (no live source to diff
// against). Both maps/functions should already be redacted by the caller
// OR left raw — the handlers always redact again via
// [configaudit.Redact]/[configaudit.RedactOps] before anything reaches the
// wire, so double-redaction is harmless.
func WithConfigSnapshots(applied map[string]any, runningFn func(context.Context) (map[string]any, error)) Option {
	return func(s *Server) {
		s.configAppliedSnapshot = applied
		s.configRunningSnapshotFn = runningFn
	}
}

// WithConfigDriftDetection opts this replica into the cross-replica
// config-digest broadcast loop (platform/configaudit.DriftDetector),
// started by calling Server.StartConfigDriftDetection with the process run
// context. interval <= 0 (the default via a zero-value Server) keeps the
// feature off. replicaID identifies THIS replica in the broadcast Event's
// Key — reuse the same id WithSharedSigningKeyRegistry's replicaID uses, if
// wired, so operators correlate the two.
func WithConfigDriftDetection(interval time.Duration, replicaID string) Option {
	return func(s *Server) {
		s.configDriftInterval = interval
		s.configReplicaID = replicaID
	}
}
