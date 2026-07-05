package sso

import (
	"context"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/userlifecycle"
	"github.com/snaplink/sso/platform/audit"
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

// configHistoryResourceByEventType classifies an audit.EventType into the
// config_history "resource" column, restricted to the event types that
// ALREADY broadcast a cluster Kind*Change (client/tenant/policy) per
// AGENTS.md's change-capture requirement. Every other admin event type is
// skipped: a resource-scoped config_history pairs with the running/applied
// diff endpoint, it is not a second general admin audit log (that already
// exists at /api/v1/audit/events). Lives beside the config-audit wiring
// options (relocated from server_routes_admin.go to hold that file under the
// 500-line budget).
var configHistoryResourceByEventType = map[audit.EventType]string{
	audit.EventAdminClientCreated:       "client",
	audit.EventAdminClientUpdated:       "client",
	audit.EventAdminClientDeleted:       "client",
	audit.EventAdminClientSecretRotated: "client",
	audit.EventAdminTenantCreated:       "tenant",
	audit.EventAdminTenantUpdated:       "tenant",
	audit.EventAdminTenantDeleted:       "tenant",
	audit.EventAdminTenantStatusChanged: "tenant",
	audit.EventAdminRoleAdded:           "policy",
	audit.EventAdminRoleUpdated:         "policy",
	audit.EventAdminRoleRemoved:         "policy",
	audit.EventAdminRoleAssigned:        "policy",
	audit.EventAdminRoleUnassigned:      "policy",
	audit.EventAdminMenusUpdated:        "policy",
}

// recordConfigHistoryFromAudit is the audit.Recorder ConfigChangeHook wired
// in NewServer when both an auditor and a configAuditStore are present
// (see sso.go). It is the "narrowest existing seam" AGENTS.md's
// change-capture requirement asks for: every admin mutation across gRPC
// (grpcadmin's recordAdmin helper) and REST already funnels through
// Recorder.Record with the actor stamped from the admin auth context
// (sso.AdminActorFromContext / the REST admin middleware), so hooking here
// captures every client/tenant/policy change without touching a single
// admin_*.go call site.
//
// Limitation (documented, not fixed here — see AGENTS.md scope discipline):
// this generic seam only carries the changed entity's ID (via the
// "target="+id Reason convention every admin handler already uses), not its
// before/after field values, so the recorded Patch is empty — a presence-
// only history entry, not a field-level diff. [Server.RecordConfigChange]
// is the field-accurate alternative for a call site that has both states.
func (s *Server) recordConfigHistoryFromAudit(ctx context.Context, e *audit.Event) {
	resource, ok := configHistoryResourceByEventType[e.Type]
	if !ok || s.configAuditStore == nil {
		return
	}
	entry := configaudit.Entry{
		Actor:      e.ActorID,
		Resource:   resource,
		ResourceID: strings.TrimPrefix(e.Reason, "target="),
		Patch:      []configaudit.Op{},
		Reason:     string(e.Type),
	}
	if err := s.configAuditStore.Record(ctx, entry); err != nil {
		s.logger.Error("config history record failed", "resource", resource, "error", err)
	}
}

// RecordConfigChange appends a field-level config_history entry for a
// single resource mutation: before/after are the resource's own JSON-
// shaped representation (NOT the whole server config) — e.g. a client
// struct round-tripped through json.Marshal/Unmarshal into map[string]any.
// actor should come from the caller's admin auth context
// (sso.AdminActorFromContext for gRPC, the REST admin middleware's stashed
// subject for HTTP). No-op when no configAuditStore is wired, so callers
// may invoke it unconditionally.
func (s *Server) RecordConfigChange(ctx context.Context, actor, tenantID, resource, resourceID string, before, after map[string]any, reason string) {
	if s.configAuditStore == nil {
		return
	}
	entry := configaudit.Entry{
		Actor:      actor,
		TenantID:   tenantID,
		Resource:   resource,
		ResourceID: resourceID,
		Patch:      configaudit.RedactOps(configaudit.Diff(before, after)),
		Reason:     reason,
	}
	if err := s.configAuditStore.Record(ctx, entry); err != nil {
		s.logger.Error("config history record failed", "resource", resource, "resource_id", resourceID, "error", err)
	}
}

// WithUserLifecycle wires the user-lifecycle state machine: it mounts the admin
// GET/POST /api/v1/admin/users/:id/lifecycle endpoints (backed by store) so
// operators can inspect and drive an account through INVITED -> ACTIVE ->
// {SUSPENDED, INACTIVE} -> ARCHIVED -> PURGED, each transition validated against
// the legal-transition table and audited (admin_user_lifecycle_changed).
//
// The store is GOVERNANCE metadata: a user with no record reads as ACTIVE, and
// it NEVER gates authentication (core.User.IsActive still owns the login
// decision). Nil (the default) leaves the endpoints unmounted — byte-identical
// to a build without the feature. Pair with WithUserAutoDeprovision to also
// advance dormant accounts on a schedule.
func WithUserLifecycle(store userlifecycle.Store) Option {
	return func(s *Server) { s.userLifecycleStore = store }
}

// WithUserAutoDeprovision arms the OPTIONAL background sweep that advances
// dormant accounts (ACTIVE -> INACTIVE past cfg.DormantAfter; INACTIVE ->
// ARCHIVED past cfg.DormantAfter+cfg.ArchiveAfter), using activity as the "last
// active" signal. It REQUIRES WithUserLifecycle (the sweep persists via that
// store).
//
// OFF by default and OFF unless BOTH configured AND started: cfg.DormantAfter
// <= 0 (the zero value) makes the sweep a no-op, and even when configured the
// operator must start Server.RunUserAutoDeprovision in a goroutine (the same
// discipline as RunBreakGlassSweeper) — NewServer never starts it. A build that
// only wires the store, or omits this option, keeps existing behavior exactly.
func WithUserAutoDeprovision(cfg userlifecycle.DeprovisionConfig, activity userlifecycle.LastActiveSource) Option {
	return func(s *Server) {
		s.userDeprovision = cfg
		s.userLifecycleActivity = activity
	}
}

// LifecycleStore exposes the wired user-lifecycle store to the admin lifecycle
// handlers (admin.Deps); nil when WithUserLifecycle isn't set.
func (s *Server) LifecycleStore() userlifecycle.Store { return s.userLifecycleStore }

// RunUserAutoDeprovision wakes every interval and runs one auto-deprovisioning
// sweep (userlifecycle.SweepOnce): dormant ACTIVE accounts move to INACTIVE and
// (when configured) long-dormant INACTIVE accounts to ARCHIVED. Same shutdown
// contract as RunBreakGlassSweeper: it exits on ctx cancellation, a sweep error
// is logged but never tears down the loop, and it is the OPERATOR's
// responsibility to start it in a goroutine — NewServer/Mount never start it, so
// embedding the SDK never leaks it.
//
//	go srv.RunUserAutoDeprovision(ctx, time.Hour)
//
// No-op when the store/activity source is unwired, the config is disabled
// (DormantAfter <= 0), or interval <= 0 — byte-identical to a build without it.
func (s *Server) RunUserAutoDeprovision(ctx context.Context, interval time.Duration) {
	if s.userLifecycleStore == nil || s.userLifecycleActivity == nil ||
		!s.userDeprovision.Enabled() || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := userlifecycle.SweepOnce(ctx, s.userDeprovisionDeps()); err != nil {
				s.logger.Error("user auto-deprovision sweep failed", "error", err)
			}
		}
	}
}

// userDeprovisionDeps assembles the SweepDeps from the wired server state.
func (s *Server) userDeprovisionDeps() userlifecycle.SweepDeps {
	return userlifecycle.SweepDeps{
		Users:      s.userProvider,
		Lifecycle:  s.userLifecycleStore,
		LastActive: s.userLifecycleActivity,
		Auditor:    s.auditor,
		Logger:     s.logger,
		Config:     s.userDeprovision,
	}
}
