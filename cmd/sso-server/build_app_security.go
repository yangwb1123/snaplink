package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/sso"
)

// wireBodyAndRateLimit wires the request body-size limits + the rate limiter.
func (b *appBuilder) wireBodyAndRateLimit() error {
	cfg, logger := b.cfg, b.logger
	if n := cfg.Security.BodyLimit.MaxBytes; n > 0 {
		b.opts = append(b.opts, sso.WithBodyLimit(n))
		logger.Info("security: body limit", "max_bytes", n)
	}
	for _, ov := range cfg.Security.BodyLimit.Overrides {
		if ov.Prefix == "" {
			continue
		}
		b.opts = append(b.opts, sso.WithBodyLimitForPath(ov.Prefix, ov.MaxBytes))
		logger.Info("security: body limit override", "prefix", ov.Prefix, "max_bytes", ov.MaxBytes)
	}
	if rl := cfg.Security.RateLimit; rl.Enabled {
		policy, err := serverbuildplatform.BuildRateLimitPolicy(rl, b.redis)
		if err != nil {
			return fmt.Errorf("rate limit policy: %w", err)
		}
		b.opts = append(b.opts, sso.WithRateLimit(policy))
		b.opts = serverbuildsign.AppendRateLimitReadyChecks(b.opts, policy)
		backend := rl.Backend
		if backend == "" {
			backend = "memory"
		}
		logger.Info("security: rate limit enabled",
			"backend", backend,
			"default_per_sec", rl.DefaultPerSec,
			"default_burst", rl.DefaultBurst,
			"prefix_rules", len(rl.Prefixes))
	}
	return nil
}

// wireJTIReplaySPIFFE wires the JTI replay-protection store + SPIFFE
// JWT-SVID token-exchange acceptance.
func (b *appBuilder) wireJTIReplaySPIFFE() error {
	cfg, logger := b.cfg, b.logger
	if cfg.Security.JTIReplay.Enabled {
		store, mode, err := serverbuildauthn.BuildJTIReplayStore(cfg.Security.JTIReplay, b.redis)
		if err != nil {
			return fmt.Errorf("jti replay store: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "jti_replay", sqlitestores.JTIReplayMaxVersion()); err != nil {
			return fmt.Errorf("schema check jti_replay: %w", err)
		}
		b.opts = append(b.opts, sso.WithJTIReplayStore(store))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-jti-replay", store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-jti-replay", store)
		if cfg.Security.JTIReplay.FailClosed {
			// Reject when the store can't confirm a jti is unseen, instead of
			// falling through. Closes the replay window during a store outage at
			// the cost of availability.
			b.opts = append(b.opts, sso.WithJTIReplayFailClosed())
		}
		logger.Info("security: jti replay protection enabled", "backend", mode, "fail_closed", cfg.Security.JTIReplay.FailClosed)
	}
	if cfg.SPIFFE.Enabled {
		spiffeOpt, err := serverbuildplatform.BuildSPIFFEOption(cfg.SPIFFE)
		if err != nil {
			return fmt.Errorf("spiffe jwt-svid: %w", err)
		}
		b.opts = append(b.opts, spiffeOpt)
		logger.Info("spiffe: jwt-svid token-exchange acceptance enabled",
			"trust_domain", cfg.SPIFFE.TrustDomain,
			"audience", cfg.SPIFFE.Audience,
			"jwks_file", cfg.SPIFFE.JWKSFile,
		)
	}
	return nil
}

// wireCAEPReceiverMesh wires the CAEP/SSF inbound receiver + the mesh
// ext_authz endpoint.
func (b *appBuilder) wireCAEPReceiverMesh() error {
	cfg, logger := b.cfg, b.logger
	if cfg.CAEP.Receiver.Enabled {
		// OpenID Shared Signals (CAEP/SSF) RECEIVER — the inbound half. Mounts
		// /ssf/receive, consumes SETs from the configured trusted transmitters,
		// and revokes the mapped subject's local access via the SAME seams
		// /token/revoke-all uses. Fail-closed validation; unmapped subject ⇒ ack
		// + no-op (no wrongful revocation).
		rcvOpt, err := serverbuildplatform.BuildCAEPReceiverOption(cfg.CAEP.Receiver, b.sessionMgr, b.refreshTokenStore, b.clientStore, b.userProvider, b.recorder, b.metricsRegistry, b.redis, logger)
		if err != nil {
			return fmt.Errorf("caep receiver: %w", err)
		}
		b.opts = append(b.opts, rcvOpt)
		path := cfg.CAEP.Receiver.Path
		if path == "" {
			path = sso.PathSSFReceive
		}
		logger.Info("caep: OpenID Shared Signals receiver enabled — consumes signed SETs from trusted transmitters and revokes local access",
			"path", path,
			"audience", cfg.CAEP.Receiver.Audience,
			"trusted_transmitters", len(cfg.CAEP.Receiver.Transmitters))
	}
	if cfg.Mesh.ExtAuthz.Enabled {
		// Envoy/Istio ext_authz HTTP-mode endpoint (cluster C1 mesh data-plane).
		// Mesh-internal: only the trusted sidecar may call it, and the mesh MUST
		// strip any client-supplied X-Auth-* at ingress (same edge-strip model as
		// X-Forwarded-* / mtls.backend: header).
		path := cfg.Mesh.ExtAuthz.Path
		if path == "" {
			path = sso.PathMeshExtAuthz
		}
		b.opts = append(b.opts, sso.WithMeshExtAuthz(cfg.Mesh.ExtAuthz.Path))
		logger.Info("mesh: ext_authz HTTP endpoint enabled", "path", path)
	}
	return nil
}

// wireMTLSLockoutProxiesCORS wires mTLS-bound tokens, account lockout, trusted
// proxies (XFF validation), and CORS.
func (b *appBuilder) wireMTLSLockoutProxiesCORS() error {
	cfg, logger := b.cfg, b.logger
	if cfg.Security.MTLS.Enabled {
		extractor, mode, err := serverbuildstore.BuildClientCertExtractor(cfg.Security.MTLS)
		if err != nil {
			return fmt.Errorf("mtls extractor: %w", err)
		}
		b.opts = append(b.opts, sso.WithClientCertExtractor(extractor))
		logger.Info("security: mTLS bound tokens enabled", "extractor", mode)
	}
	if al := cfg.Security.AccountLockout; al.Enabled {
		lockout, mode, err := serverbuildauthn.BuildAccountLockout(al, b.redis)
		if err != nil {
			return fmt.Errorf("account lockout: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, lockout, "account_lockout", sqlitestores.AccountLockoutMaxVersion()); err != nil {
			return fmt.Errorf("schema check account_lockout: %w", err)
		}
		b.opts = append(b.opts, sso.WithAccountLockout(lockout))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-account-lockout", lockout)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-account-lockout", lockout)
		logger.Info("security: account lockout enabled",
			"backend", mode,
			"max_failures", al.MaxFailures,
			"lockout_duration", al.LockoutDuration,
			"failure_window", al.FailureWindow)
	}
	if tp := cfg.Security.TrustedProxies; len(tp.CIDRs) > 0 {
		tpOpt, err := sso.WithTrustedProxies(tp.CIDRs, tp.Hops)
		if err != nil {
			return fmt.Errorf("trusted proxies: %w", err)
		}
		b.opts = append(b.opts, tpOpt)
		logger.Info("security: trusted proxies XFF validation enabled",
			"cidrs", tp.CIDRs,
			"hops", tp.Hops)
	}
	if c := cfg.Security.CORS; c.Enabled && len(c.AllowedOrigins) > 0 {
		b.opts = append(b.opts, sso.WithCORS(cors.Policy{
			AllowedOrigins:   c.AllowedOrigins,
			AllowedMethods:   c.AllowedMethods,
			AllowedHeaders:   c.AllowedHeaders,
			ExposedHeaders:   c.ExposedHeaders,
			AllowCredentials: c.AllowCredentials,
			MaxAge:           c.MaxAge,
		}))
		logger.Info("security: cors enabled", "allowed_origins", c.AllowedOrigins)
	}
	return nil
}

// --- Governance plane: credential rotation, config-audit, break-glass -------
//
// These three wave-1 admin-plane subsystems all follow the same two-phase
// shape: wireGovernance appends their Options BEFORE NewServer (so the routes
// mount + the Server holds its read seams), then startGovernanceWorkers launches
// their background loops AFTER the Server is constructed, each under the standard
// cancel+done shutdown lifecycle (main_shutdown.go stopScheduler).

// wireGovernance appends the credential-rotation, config-audit, and break-glass
// Options and builds their backing registry/store, leaving the loops for
// startGovernanceWorkers. Each sub-wire is a no-op (byte-identical build) when
// its config section is disabled.
func (b *appBuilder) wireGovernance() error {
	if err := b.wireCredentialRotation(); err != nil {
		return err
	}
	if err := b.wireConfigAudit(); err != nil {
		return err
	}
	b.wireBreakGlass()
	if err := b.wireTokenPolicy(); err != nil {
		return err
	}
	if err := b.wireConditionalAccess(); err != nil {
		return err
	}
	return b.wireDegradation()
}

// wireTokenPolicy builds the token-policy governance store (external bundle or
// inline rules) and wires sso.WithTokenPolicy — clamps access-token TTLs down
// and denies dangerous scope combos, plus mounts GET /api/v1/admin/token-policies.
// No-op (byte-identical build) when the token_policies section is absent.
func (b *appBuilder) wireTokenPolicy() error {
	store, err := serverbuildplatform.BuildTokenPolicyStore(b.cfg.TokenPolicies)
	if err != nil {
		return fmt.Errorf("token policies: %w", err)
	}
	if store == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithTokenPolicy(store))
	b.logger.Info("token policy engine enabled — access-token TTL clamp + scope-combo governance")
	return nil
}

// wireConditionalAccess builds the zero-trust conditional-access store + engine
// config and wires sso.WithConditionalAccess (ADVISORY this wave — not in the
// live /auth/login control flow), mounting GET /api/v1/admin/access-policies.
// No-op when the access_policies section is absent.
func (b *appBuilder) wireConditionalAccess() error {
	store, capCfg, err := serverbuildplatform.BuildConditionalAccess(b.cfg.AccessPolicies)
	if err != nil {
		return fmt.Errorf("access policies: %w", err)
	}
	if store == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithConditionalAccess(store, capCfg))
	b.logger.Info("conditional-access engine enabled (advisory)", "default_deny", capCfg.DefaultDeny)
	return nil
}

// wireDegradation builds the degraded-service Manager and wires
// sso.WithDegradationManager, mounting the admin /api/v1/admin/dr/mode read+toggle.
// The manager holds no background loop of its own — the admin endpoint (and any
// external health loop calling SetMode) is the operator's toggle seam. No-op when
// the degradation section is disabled.
func (b *appBuilder) wireDegradation() error {
	mgr, err := serverbuildplatform.BuildDegradationManager(b.cfg.Degradation)
	if err != nil {
		return fmt.Errorf("degradation: %w", err)
	}
	if mgr == nil {
		return nil
	}
	b.degradationMgr = mgr
	b.opts = append(b.opts, sso.WithDegradationManager(mgr))
	if b.cfg.Degradation.AutoReadOnlyOnStoreLoss {
		// No continuous storage-health push loop exists in cmd today (health is
		// pull-based via /readyz + the storage-health admin report), so there is
		// no clean seam to auto-drive SetMode. Surface the intent: an operator or
		// external health loop drives read_only via the mounted dr/mode endpoint.
		b.logger.Info("degradation: auto_read_only_on_store_loss set — no auto-driver seam; drive SetMode(read_only) via POST /api/v1/admin/dr/mode",
			"initial_mode", mgr.Mode())
		return nil
	}
	b.logger.Info("degradation: degraded-service gate enabled", "initial_mode", mgr.Mode())
	return nil
}

// wireCredentialRotation builds the rotation Registry + Scheduler (seeding the
// webhook-HMAC rotator from the audit webhook signing secret) and wires the
// Server's read access to the governance inventory.
func (b *appBuilder) wireCredentialRotation() error {
	reg, sched, err := serverbuildplatform.BuildCredentialRotation(
		b.cfg.Rotation, []byte(b.cfg.Audit.Webhook.SigningSecret), b.logger, b.metricsRegistry)
	if err != nil {
		return fmt.Errorf("credential rotation: %w", err)
	}
	if reg == nil {
		return nil
	}
	// The SAME Scheduler drives both the read-only inventory (WithCredentialRotation)
	// and the emergency compromise-response path (WithCredentialCompromise) — it owns
	// the status store + dependent-party notifier the compromise fan-out reuses — so
	// POST /api/v1/admin/credentials/{type}/compromise mounts whenever rotation is on.
	b.opts = append(b.opts, sso.WithCredentialRotation(reg), sso.WithCredentialCompromise(sched))
	b.credentialScheduler = sched
	return nil
}

// wireConfigAudit builds the config-history store, captures the redacted
// applied-config snapshot once, and appends the snapshot/history/drift Options.
func (b *appBuilder) wireConfigAudit() error {
	cfg := b.cfg.ConfigAudit
	if !cfg.Enabled {
		return nil
	}
	store, err := serverbuildplatform.BuildConfigAuditStore(cfg)
	if err != nil {
		return fmt.Errorf("config audit store: %w", err)
	}
	applied, err := serverbuildplatform.EffectiveConfigSnapshot(b.cfg)
	if err != nil {
		return fmt.Errorf("config audit snapshot: %w", err)
	}
	fullCfg := b.cfg
	running := func(context.Context) (map[string]any, error) {
		return serverbuildplatform.EffectiveConfigSnapshot(fullCfg)
	}
	b.configAuditStore = store
	b.opts = append(b.opts,
		sso.WithConfigAuditStore(store),
		sso.WithConfigSnapshots(applied, running),
	)
	if cfg.Drift.Interval > 0 {
		b.opts = append(b.opts, sso.WithConfigDriftDetection(cfg.Drift.Interval, b.driftReplicaID()))
	}
	b.logger.Info("config audit enabled",
		"backend", configAuditBackend(cfg.Backend), "drift_interval", cfg.Drift.Interval)
	return nil
}

// wireBreakGlass wires the in-memory break-glass store enabling the
// emergency-admin-session endpoints; the expiry sweeper is started later.
func (b *appBuilder) wireBreakGlass() {
	if !b.cfg.BreakGlass.Enabled {
		return
	}
	store := memorystoreidentity.NewMemoryBreakGlassStore()
	b.breakGlassStore = store
	b.opts = append(b.opts, sso.WithBreakGlassStore(store))
}

// startGovernanceWorkers launches the governance background loops after the
// Server is constructed: the rotation scheduler, the config-drift broadcast
// loop, and the break-glass expiry sweeper. Each records a cancel+done pair for
// graceful shutdown.
func (b *appBuilder) startGovernanceWorkers(srv *sso.Server) error {
	if b.credentialScheduler != nil {
		ctx, cancel := context.WithCancel(context.Background())
		b.credentialSchedCancel = cancel
		b.credentialSchedDone = b.credentialScheduler.Start(ctx)
	}
	if b.cfg.ConfigAudit.Enabled && b.cfg.ConfigAudit.Drift.Interval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		done, err := srv.StartConfigDriftDetection(ctx)
		if err != nil {
			cancel()
			return fmt.Errorf("config drift detection: %w", err)
		}
		b.configDriftCancel, b.configDriftDone = cancel, done
	}
	b.startBreakGlassSweeper(srv)
	return nil
}

// startBreakGlassSweeper runs Server.RunBreakGlassSweeper in a goroutine wrapped
// in the standard cancel+done pair. No-op when no break-glass store is wired.
func (b *appBuilder) startBreakGlassSweeper(srv *sso.Server) {
	if b.breakGlassStore == nil {
		return
	}
	interval := b.cfg.BreakGlass.SweeperInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.breakGlassCancel, b.breakGlassDone = cancel, done
	go func() { defer close(done); srv.RunBreakGlassSweeper(ctx, interval) }()
	b.logger.Info("break-glass sweeper enabled", "interval", interval)
}

// driftReplicaID resolves the id the config-drift broadcast tags its digest
// with, reusing the signing-key registry's replica id (or the derived service
// id) so operators can correlate the two cross-replica loops.
func (b *appBuilder) driftReplicaID() string {
	if id := strings.TrimSpace(b.cfg.Keys.SigningKeyRegistry.ReplicaID); id != "" {
		return id
	}
	return serverbuildplatform.ResolveServiceID(b.cfg.Registry.ServiceID, b.cfg.Server.Issuer)
}

// configAuditBackend maps an empty backend to its "memory" default for logging.
func configAuditBackend(backend string) string {
	if strings.TrimSpace(backend) == "" {
		return "memory"
	}
	return backend
}
