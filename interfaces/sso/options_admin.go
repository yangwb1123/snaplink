package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/platform/lifecycle/rotation"
	"github.com/snaplink/sso/platform/sse"
	"github.com/snaplink/sso/shared/core"
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

// WithCredentialRotation wires the platform/rotation Registry backing GET
// /api/v1/admin/credentials — a read-only governance inventory (type,
// version, status, created_at, next rotation due) of every credential class
// registered for automatic rotation. NEVER exposes secret material.
//
// The Registry is a passive snapshot source: build it (rotation.NewRegistry,
// then Register each corecredential.CredentialRotator), wrap it in a
// rotation.Scheduler, and Start/Stop the Scheduler from the composition root
// (cmd) — the same lifecycle discipline as the signing-key rotation loop.
// This option only wires the Server's READ access to reg; it does not start
// anything.
//
// Nil (the default) leaves the route unmounted — byte-identical to a build
// without this feature.
func WithCredentialRotation(reg *rotation.Registry) Option {
	return func(s *Server) { s.credentialRegistry = reg }
}

// WithCredentialCompromise mounts POST
// /api/v1/admin/credentials/{type}/compromise (admin:write) — the emergency
// compromise-response path: declaring a credential class leaked force-rotates
// it OFF schedule with NO overlap window, so the leaked version is retired from
// the verify set instantly. The response is the new version's GOVERNANCE
// metadata only — NEVER the secret material.
//
// Pass the SAME rotation.Scheduler wired to drive scheduled rotation (it owns
// the status store + dependent-party notifier the compromise fan-out reuses),
// AND the registry it wraps to WithCredentialRotation so the GET inventory
// reflects a compromise. The Server only INVOKES Compromise on demand; the
// scheduler's own Start/Stop lifecycle is the composition root's (cmd)
// responsibility, same as WithCredentialRotation.
//
// Nil (the default) leaves the route unmounted — byte-identical to a build
// without this feature.
func WithCredentialCompromise(sched *rotation.Scheduler) Option {
	return func(s *Server) { s.credentialScheduler = sched }
}

// WithSSEBroker mounts GET /api/v1/admin/events/stream — the realtime
// admin event source (Server-Sent Events). When an audit recorder is ALSO
// wired, NewServer taps its pipeline (the same AddSink/MultiSink seam
// WithCAEPTransmitter uses) so every recorded event is projected to a
// redacted Summary and published to b; without a recorder the route still
// mounts but never emits (the broker has no source).
//
// The caller owns b's lifecycle: construct it with sse.NewBroker and Close
// it during shutdown, BEFORE the HTTP graceful drain, so idle EventSource
// connections don't pin Shutdown to its full deadline (Server.SSEBroker
// exposes it back for exactly that). Default-off: a nil (unset) broker is
// byte-identical to a build without the feature.
func WithSSEBroker(b *sse.Broker) Option {
	return func(s *Server) { s.sseBroker = b }
}

// SSEBroker returns the wired broker (nil when unset), so cmd can Close it
// during shutdown without retaining its own reference.
func (s *Server) SSEBroker() *sse.Broker { return s.sseBroker }

// WithSSEHeartbeat overrides the admin event stream's keep-alive comment
// interval. <= 0 (the default) leaves the SDK default (sse.DefaultHeartbeat)
// in effect. Has no effect without WithSSEBroker.
func WithSSEHeartbeat(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.sseHeartbeat = d
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

// WithBreakGlassStore wires a store for break-glass (emergency support)
// admin sessions, enabling the POST/GET /api/v1/admin/break-glass,
// DELETE .../{id}, and POST .../{id}/approve lifecycle endpoints. Without
// it, no break-glass surface exists — byte-identical to a build without the
// feature. Pair with a WithSessionManager so impersonate/escalate scope
// grants can mint their marked target-user session; a readonly-only
// deployment works without a SessionManager.
//
// Derived sessions are only ever actually revoked by an active sweep — see
// Server.RunBreakGlassSweeper, which the operator should run in a goroutine
// alongside this option (the same pattern as the audit/CIBA/snapshot
// retention loops in cmd/sso-server).
func WithBreakGlassStore(store core.BreakGlassStore) Option {
	return func(s *Server) { s.breakGlassStore = store }
}
