package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/yangwb1123/snaplink/shared/spi"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/admingovernance"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

// buildApp is pure server-assembly wiring: it reads config and constructs the
// Server with every WithXxx option, store, subsystem, and background worker.
// The work is delegated to ordered wireXxx sub-builders on appBuilder (defined
// across build_app*.go), grouped into three phases (foundation -> domains ->
// edge) whose Option-application order is identical to the original monolith
// (option order can decide which security feature wins), as is every
// conditional, error-wrap, defer/cleanup, and background-worker handoff.
func buildApp(cfg *config.Config, logger spi.Logger) (builtApp *app, retErr error) {
	b := &appBuilder{cfg: cfg, logger: logger}
	// The peer-trust checker must exist before any wireXxx phase runs: the
	// region resolver (wireDomains) and the mTLS header extractor (wireEdge)
	// both take it as their trusted-proxies gate.
	if err := b.wirePeerTrust(); err != nil {
		return nil, err
	}
	// The shared Redis client + Postgres pool must exist before any store
	// builder runs, since stores may select backend:redis (hot) or
	// backend:postgres (durable).
	if err := b.wireRedis(); err != nil {
		return nil, err
	}
	if err := b.wirePostgres(); err != nil {
		return nil, err
	}
	// Loud warning if a cluster is declared but core stores still resolve to
	// per-pod memory — the misconfig that boots clean + green /readyz while
	// breaking correctness behind a multi-replica load balancer.
	b.warnHACoherence()
	if err := b.wireFoundation(); err != nil {
		return nil, err
	}
	// If buildApp fails downstream, stop the classifier's watch loop so its
	// goroutine + context don't leak; on success the app owns netCancel and
	// calls it at shutdown. Registered here (after wireFoundation populates
	// netCancel, before the later phases) so the LIFO cleanup fires for any
	// later error, exactly as the original defer did.
	if b.netCancel != nil {
		defer func() {
			if retErr != nil {
				b.netCancel()
			}
		}()
	}
	if err := b.wireDomains(); err != nil {
		return nil, err
	}
	if err := b.wireEdge(); err != nil {
		return nil, err
	}
	return b.finalize()
}

// warnHACoherence emits a LOUD warning when a Redis/Postgres cluster is declared
// but a core security/correctness store still resolves to per-pod memory. Such a
// config boots clean and reports /readyz GREEN (the cluster ping passes) while
// silently serving from state no peer replica can see: behind a round-robin LB
// an auth code minted on one replica is unknown on another (~2/3 of /token
// exchanges fail invalid_grant), and refresh-reuse / replay / session defenses
// become per-pod. It does NOT fail boot (single-replica + hybrid are valid), but
// names exactly which store to move onto the cluster.
func (b *appBuilder) warnHACoherence() {
	redisHA := b.cfg.Redis.Configured()
	pgHA := b.cfg.Postgres.Configured()
	if !redisHA && !pgHA {
		return
	}
	perPod := func(backend string) bool {
		s := strings.ToLower(strings.TrimSpace(backend))
		return s == "" || s == "memory"
	}
	var stuck []string
	// Hot cross-replica stores: needed whenever EITHER cluster is declared (a
	// postgres-only multi-replica deploy still must not run oauth/jti on memory).
	if redisHA || pgHA {
		if perPod(b.cfg.OAuth.Backend) {
			stuck = append(stuck, "oauth.backend (auth_code/refresh/device/par): token exchange FAILS across replicas")
		}
		sess := b.cfg.Identity.SessionBackend
		if sess == "" {
			sess = b.cfg.Identity.Backend
		}
		if perPod(sess) {
			stuck = append(stuck, "identity.session_backend: sessions are per-pod")
		}
		if perPod(b.cfg.Security.JTIReplay.Backend) {
			stuck = append(stuck, "security.jti_replay.backend: replay defense is per-pod")
		}
		if b.cfg.CIBA.Enabled && perPod(b.cfg.CIBA.Backend) {
			stuck = append(stuck, "ciba.backend: CIBA poll/ping FAILS across replicas")
		}
	}
	if pgHA && perPod(b.cfg.Identity.Backend) {
		stuck = append(stuck, "identity.backend (clients/users): durable records are per-pod, lost on restart")
	}
	if len(stuck) == 0 {
		return
	}
	// Error level (not Info) so this is impossible to miss: the Info-level
	// "single-replica only" per-store logs already exist and were demonstrably
	// too quiet. Boot continues — single-replica/hybrid are valid.
	b.logger.Error("HA INCOHERENCE: a redis/postgres cluster is configured but core stores still default to per-pod memory — behind a multi-replica load balancer this breaks correctness; select the per-store backends (see ops/deploy/k8s-prod/config.yaml)",
		"per_pod_stores", stuck)
}

// wirePeerTrust compiles security.trusted_proxies.cidrs ONCE into the
// peertrust.Checker every proxy-header consumer shares. Unset knob leaves
// b.peerTrust nil — every consumer then keeps its legacy first-hop-trust
// behavior byte-identically. A bad CIDR fails boot loudly (same contract
// as sso.WithTrustedProxies, which parses the SAME list later in
// wireMTLSLockoutProxiesCORS).
func (b *appBuilder) wirePeerTrust() error {
	checker, err := peertrust.NewChecker(b.cfg.Security.TrustedProxies.CIDRs)
	if err != nil {
		return fmt.Errorf("trusted proxies: %w", err)
	}
	b.peerTrust = checker
	return nil
}

// wireFoundation runs the kernel sub-builders (identity/signing, audit,
// permissions, network) that the later phases depend on. wireNetwork populates
// b.netCancel, so buildApp registers the on-failure cancel defer immediately
// after this phase returns.
func (b *appBuilder) wireFoundation() error {
	if err := b.wireIdentitySigning(); err != nil {
		return err
	}
	if err := b.wireAudit(); err != nil {
		return err
	}
	if err := b.wirePermissions(); err != nil {
		return err
	}
	return b.wireNetwork()
}

// wireDomains runs the business-domain sub-builders, in the same order the
// original monolith applied their Options. wireAnomaly is NOT here — it moved
// to finalize() (after wireCluster) so it can share the Active ITDR threat
// executor with tokenanomaly.Detector; see wireThreatAction's doc comment.
func (b *appBuilder) wireDomains() error {
	if err := b.wireSelfServicePassword(); err != nil {
		return err
	}
	if err := b.wireIdentityLink(); err != nil {
		return err
	}
	if err := b.wireGeoRegionRisk(); err != nil {
		return err
	}
	if err := b.wireWebAuthnMFA(); err != nil {
		return err
	}
	if err := b.wireTenant(); err != nil {
		return err
	}
	if err := b.wireConnectionsAndCache(); err != nil {
		return err
	}
	if err := b.wireDPoP(); err != nil {
		return err
	}
	return b.wireOAuthGrantStores()
}

// wireEdge runs the delivery-edge sub-builders (response encryption, DCR/
// backchannel, CAEP transmitter, realtime admin event stream, generic
// webhook egress engine, federation, profiles/metadata, metrics,
// body/rate-limit, JTI-replay/SPIFFE, CAEP receiver/mesh,
// mTLS/lockout/proxies/CORS), in the original Option-application order.
// wireCAEPTransmitter, wireSSEEvents, wireWebhookEngine, and
// wireMetricsCollector return no error and keep their original positions.
func (b *appBuilder) wireEdge() error {
	if err := b.wireResponseEncryption(); err != nil {
		return err
	}
	b.wireSessionManagement()
	if err := b.wireDCRBackchannel(); err != nil {
		return err
	}
	b.wireCAEPTransmitter()
	b.wireSSEEvents()
	b.wireWebhookEngine()
	b.wireSCIMProvisioning()
	if err := b.wireFederation(); err != nil {
		return err
	}
	if err := b.wireProfilesAndMetadata(); err != nil {
		return err
	}
	b.wireAPIVersioning()
	b.wireMetricsCollector()
	if err := b.wireBodyAndRateLimit(); err != nil {
		return err
	}
	b.wireInputLimits()
	if err := b.wireJTIReplaySPIFFE(); err != nil {
		return err
	}
	if err := b.wireCAEPReceiverMesh(); err != nil {
		return err
	}
	if err := b.wireMTLSLockoutProxiesCORS(); err != nil {
		return err
	}
	b.wireSecurityHeaders()
	return nil
}

// wireInputLimits wires the RFC 9396 authorization_details shape caps, the
// scope-count cap, and the bearer-token byte-length cap — the remaining
// input-limit-hardening knobs alongside wireBodyAndRateLimit's generic
// whole-request body cap. Each is independently opt-in; an absent or
// all-zero config section leaves the corresponding Option unset, so a
// deployment without this section in its YAML is byte-identical to one
// built before these knobs existed.
func (b *appBuilder) wireInputLimits() {
	cfg, logger := b.cfg, b.logger
	if rl := cfg.Security.RARLimits; rl.MaxBytes > 0 || rl.MaxElements > 0 || rl.MaxDepth > 0 {
		b.opts = append(b.opts, sso.WithAuthorizationDetailsLimits(rl.MaxBytes, rl.MaxElements, rl.MaxDepth))
		logger.Info("security: authorization_details limits enabled",
			"max_bytes", rl.MaxBytes, "max_elements", rl.MaxElements, "max_depth", rl.MaxDepth)
	}
	if n := cfg.Security.ScopeLimit.MaxCount; n > 0 {
		b.opts = append(b.opts, sso.WithMaxScopeCount(n))
		logger.Info("security: scope count cap enabled", "max_count", n)
	}
	if n := cfg.Security.MaxTokenBytes; n > 0 {
		b.opts = append(b.opts, sso.WithMaxTokenBytes(n))
		logger.Info("security: max token bytes enabled", "max_bytes", n)
	}
}

// wireBreakGlass wires the in-memory break-glass store enabling the
// emergency-admin-session endpoints; the expiry sweeper is started later.
// Relocated from build_app_security.go to keep that file within the
// per-file line budget.
func (b *appBuilder) wireBreakGlass() {
	if !b.cfg.BreakGlass.Enabled {
		return
	}
	store := memorystoreidentity.NewMemoryBreakGlassStore()
	b.breakGlassStore = store
	b.opts = append(b.opts, sso.WithBreakGlassStore(store))
}

// wireChangeApproval wires the in-memory ApprovalStore enabling the generic
// change-approval workflow (POST/GET /api/v1/admin/changes + .../approve|
// reject). No Applier is registered here — the shipped binary only exposes
// the propose/approve book-keeping; a forked main wanting a change to take
// automatic effect on approval registers its own admingovernance.Applier
// into a *admingovernance.Registry and passes it to WithChangeApprovalStore
// instead (an operator extension point, same shape as WithCredentialRotation
// requiring the caller's own rotation.Scheduler).
func (b *appBuilder) wireChangeApproval() {
	if !b.cfg.AdminChangeApproval.Enabled {
		return
	}
	store := admingovernance.NewMemoryApprovalStore()
	b.opts = append(b.opts, sso.WithChangeApprovalStore(store, nil, b.cfg.AdminChangeApproval.ActionTypes))
}

// wireUserLifecycle builds the domains/userlifecycle admin state-machine
// surface (user_lifecycle.enabled: GET/POST
// /api/v1/admin/users/:id/lifecycle) and, as a SEPARATE opt-in
// (auto_deprovision.enabled), the background dormancy sweep. Activity is
// derived from the wired SessionManager (userlifecycle.SessionLastActive —
// no other activity backend exists). The sweep's interval is stashed on the
// builder for startUserAutoDeprovisionSweep (build_app_security.go) to start
// post-NewServer, mirroring startBreakGlassSweeper/startTokenAnomalySweep.
// No-op (byte-identical build) when user_lifecycle.enabled is false.
func (b *appBuilder) wireUserLifecycle() error {
	cfg := b.cfg.UserLifecycle
	// Resolve auto_deprovision BEFORE the store-nil early return: an operator
	// who enables auto_deprovision without user_lifecycle.enabled must see the
	// loud boot error BuildUserAutoDeprovision raises, not a silent no-op.
	deprovision, err := serverbuildplatform.BuildUserAutoDeprovision(cfg.AutoDeprovision, cfg.Enabled)
	if err != nil {
		return fmt.Errorf("user_lifecycle: %w", err)
	}
	store := serverbuildplatform.BuildUserLifecycle(cfg)
	if store == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithUserLifecycle(store))
	b.logger.Info("user lifecycle: admin state-machine enabled (/api/v1/admin/users/:id/lifecycle)")
	if !deprovision.Enabled() {
		return nil
	}
	activity := userlifecycle.SessionLastActive{Sessions: b.sessionMgr}
	b.opts = append(b.opts, sso.WithUserAutoDeprovision(deprovision, activity))
	b.userAutoDeprovisionInterval = cfg.AutoDeprovision.SweepInterval
	b.logger.Info("user lifecycle: auto-deprovision sweep enabled",
		"dormant_after", deprovision.DormantAfter, "archive_after", deprovision.ArchiveAfter,
		"sweep_interval", b.userAutoDeprovisionInterval)
	return nil
}

// startUserAutoDeprovisionSweep runs Server.RunUserAutoDeprovision in a
// goroutine under the standard cancel+done pair (mirrors
// startBreakGlassSweeper/startTokenAnomalySweep, build_app_security.go).
// No-op when wireUserLifecycle never armed the sweep (userAutoDeprovisionInterval
// stays 0 unless auto_deprovision was fully enabled).
func (b *appBuilder) startUserAutoDeprovisionSweep(srv *sso.Server) {
	interval := b.userAutoDeprovisionInterval
	if interval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.userAutoDeprovisionCancel, b.userAutoDeprovisionDone = cancel, done
	go func() { defer close(done); srv.RunUserAutoDeprovision(ctx, interval) }()
	b.logger.Info("user lifecycle: auto-deprovision sweep loop started", "interval", interval)
}

// wireIdentityLink builds the domains/identitylink self-service surface
// (self_service.identity_link.enabled: GET/DELETE /me/identities) and its
// optional MergePolicy. No-op (byte-identical build) when disabled; see
// config.IdentityLinkConfig's doc for the merge_policy default-safety
// rationale (unset/"reject" wires NO extra Option — a nil MergePolicy is
// already the package's own safe default).
func (b *appBuilder) wireIdentityLink() error {
	cfg := b.cfg.SelfService.IdentityLink
	store, policy, err := serverbuildplatform.BuildIdentityLink(cfg)
	if err != nil {
		return fmt.Errorf("self_service.identity_link: %w", err)
	}
	if store == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithIdentityLinkStore(store))
	if policy != nil {
		b.opts = append(b.opts, sso.WithIdentityMergePolicy(policy))
	}
	b.logger.Info("self-service identity linking enabled (/me/identities)", "merge_policy", cfg.MergePolicy)
	return nil
}

// --- helpers ---

// slogLogger adapts log/slog to the spi.Logger interface so the SDK can hand
// off to whatever sink the operator wants (stdout, journald, file...).
//
// level is the *slog.LevelVar backing inner's handler — slog.HandlerOptions
// reads it on EVERY log call (it's not baked in at construction), so
// level.Set (see SetLevel in main_logger.go) changes verbosity live. This is
// what makes logging.level the one config field config/reload's Reloader
// can genuinely apply without a restart.
type slogLogger struct {
	inner *slog.Logger
	level *slog.LevelVar
}
