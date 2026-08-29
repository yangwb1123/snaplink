package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/domains/threataction"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
)

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

// wireJTIReplaySPIFFE wires JTI replay protection + SPIFFE JWT-SVID.
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

// wireCAEPReceiverMesh wires the CAEP/SSF inbound receiver + mesh ext_authz.
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

// wireMTLSLockoutProxiesCORS wires mTLS tokens, lockout, trusted proxies, CORS.
func (b *appBuilder) wireMTLSLockoutProxiesCORS() error {
	cfg, logger := b.cfg, b.logger
	if cfg.Security.MTLS.Enabled {
		extractor, mode, err := serverbuildstore.BuildClientCertExtractor(cfg.Security.MTLS, b.peerTrust)
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
	if c := cfg.Security.CORS; c.Enabled && (len(c.AllowedOrigins) > 0 || len(c.PathOverrides) > 0) {
		b.opts = append(b.opts, sso.WithCORS(c.ToPolicy()))
		logger.Info("security: cors enabled", "allowed_origins", c.AllowedOrigins, "path_overrides", len(c.PathOverrides))
	}
	return nil
}

// wireSecurityHeaders wires the opt-in security-headers framework: CSP
// (with a per-request script-src nonce) + Permissions-Policy +
// Clear-Site-Data on logout/erase, plus the always-emitted
// X-Content-Type-Options / X-Frame-Options / Referrer-Policy / HSTS.
// Off by default; bare enabled:true uses the SDK's default policy.
func (b *appBuilder) wireSecurityHeaders() {
	sh := b.cfg.Security.SecurityHeaders
	if !sh.Enabled {
		return
	}
	b.opts = append(b.opts, sso.WithSecurityHeadersPolicy(handler.SecurityHeadersPolicy{
		CSPDirectives:     sh.CSPDirectives,
		PermissionsPolicy: sh.PermissionsPolicy,
	}))
	b.logger.Info("security: security headers enabled (CSP + Permissions-Policy + nonce)",
		"csp_directives_overridden", len(sh.CSPDirectives) > 0)
}

// Governance wiring appends options before NewServer and starts loops after it.

// wireGovernance builds governance options and defers loops until after server construction.
func (b *appBuilder) wireGovernance(threatExec threataction.ThreatExecutor) error {
	if err := b.wireCredentialRotation(); err != nil {
		return err
	}
	if err := b.wireConfigAudit(); err != nil {
		return err
	}
	b.wireBreakGlass()
	b.wireChangeApproval()
	if err := b.wireTokenPolicy(); err != nil {
		return err
	}
	if err := b.wireConditionalAccess(); err != nil {
		return err
	}
	if err := b.wireTrustScoring(); err != nil {
		return err
	}
	b.wireSessionTrustDecay()
	if err := b.wireTokenAnomaly(threatExec); err != nil {
		return err
	}
	if err := b.wireUserLifecycle(); err != nil {
		return err
	}
	return b.wireDegradation()
}

// wireTokenAnomaly builds the off-path detector, recorder, and sweep.
func (b *appBuilder) wireTokenAnomaly(threatExec threataction.ThreatExecutor) error {
	rec, detector, err := serverbuildplatform.BuildTokenAnomaly(b.cfg.TokenAnomaly, b.logger, threatExec)
	if err != nil {
		return fmt.Errorf("token anomaly: %w", err)
	}
	if detector == nil {
		return nil
	}
	// Start the drainer before the Server can Offer the first usage event.
	rec.Start()
	b.tokenUsageRecorder = rec
	b.tokenAnomalyDetector = detector
	b.opts = append(b.opts,
		sso.WithTokenUsageRecorder(rec),
		sso.WithTokenAnomalyDetector(detector),
	)
	b.logger.Info("token anomaly detector enabled — off-path geo/velocity/rate-spike findings + token-usage telemetry",
		"sweep_interval", b.cfg.TokenAnomaly.SweepInterval)
	return nil
}

// wireTokenPolicy builds the token-policy store and admin read surface.
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

// wireConditionalAccess builds the conditional-access store and admin surface.
func (b *appBuilder) wireConditionalAccess() error {
	store, capCfg, err := serverbuildplatform.BuildConditionalAccess(b.cfg.AccessPolicies)
	if err != nil {
		return fmt.Errorf("access policies: %w", err)
	}
	if store == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithConditionalAccess(store, capCfg))
	b.logger.Info("conditional-access engine enabled", "enforce", capCfg.Enforce, "default_deny", capCfg.DefaultDeny)
	return nil
}

// wireSessionTrustDecay wires the decay curve and continuous-verification gate.
func (b *appBuilder) wireSessionTrustDecay() {
	cfg := b.cfg.SessionTrustDecay
	if cfg.Interval <= 0 || cfg.Factor <= 0 || cfg.Factor >= 1 {
		return
	}
	b.opts = append(b.opts, sso.WithSessionTrustDecay(sso.SessionTrustDecayConfig{
		Interval:        cfg.Interval,
		Factor:          cfg.Factor,
		Floor:           cfg.Floor,
		MinScore:        cfg.MinScore,
		SweepInterval:   cfg.SweepInterval,
		StepUpACRValues: cfg.StepUpACRValues,
		StepUpMaxAge:    cfg.StepUpMaxAge,
		InitialScore:    cfg.InitialScore,
	}))
	b.sessionTrustDecayOn = true
	b.logger.Info("session trust decay enabled — continuous-verification agent + min-trust gate",
		"interval", cfg.Interval, "factor", cfg.Factor, "floor", cfg.Floor)
}

// wireDegradation builds the degraded-service manager and optional auto driver.
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
		// Auto driver: polls the storage-health sources, drives SetMode(read_only)
		// after the grace window — see serverbuildplatform.BuildDegradationAutoDriver.
		if drv := serverbuildplatform.BuildDegradationAutoDriver(b.cfg.Degradation, mgr, b.storageHealthSources, b.logger); drv != nil {
			ctx, cancel := context.WithCancel(context.Background())
			b.autoReadOnlyCancel, b.autoReadOnlyDone = cancel, drv.Run(ctx)
			b.logger.Info("degradation: auto read_only driver armed", "interval", drv.Interval(), "grace", drv.Grace(), "stores", drv.StoreCount())
		}
		return nil
	}
	b.logger.Info("degradation: degraded-service gate enabled", "initial_mode", mgr.Mode())
	return nil
}

// wireCredentialRotation builds the rotation registry/scheduler and inventory.
func (b *appBuilder) wireCredentialRotation() error {
	reg, sched, err := serverbuildplatform.BuildCredentialRotation(
		b.cfg.Rotation, b.cfg.ClientSecretRotation, []byte(b.cfg.Audit.Webhook.SigningSecret),
		b.clientStore, b.logger, b.metricsRegistry)
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

// wireConfigAudit builds the store, snapshots, canary, and drift options.
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
	b.configCanaryController = b.buildConfigCanaryController(store)
	b.opts = append(b.opts,
		sso.WithConfigAuditStore(store),
		sso.WithConfigSnapshots(applied, running),
	)
	if b.configCanaryController != nil {
		b.opts = append(b.opts, sso.WithConfigCanaryController(b.configCanaryController))
	}
	if cfg.Drift.Interval > 0 {
		b.opts = append(b.opts, sso.WithConfigDriftDetection(cfg.Drift.Interval, b.driftReplicaID()))
	}
	b.logger.Info("config audit enabled",
		"backend", configAuditBackend(cfg.Backend), "drift_interval", cfg.Drift.Interval)
	return nil
}

func (b *appBuilder) buildConfigCanaryController(store configaudit.Store) *configaudit.CanaryController {
	canaryStore, ok := store.(configaudit.CanaryStore)
	if !ok {
		return nil
	}
	probes := make([]configaudit.CanaryProbe, 0, len(b.storageHealthSources))
	for _, src := range b.storageHealthSources {
		if src.Name == "" || strings.HasPrefix(src.Name, "audit-") || src.Ping == nil {
			continue
		}
		source := src
		probes = append(probes, configaudit.CanaryProbe{Name: source.Name, Check: func(ctx context.Context) configaudit.CanaryHealth {
			err := source.Ping(ctx)
			if err == nil {
				return configaudit.CanaryHealthy
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return configaudit.CanaryUnknown
			}
			return configaudit.CanaryUnhealthy
		}})
	}
	return configaudit.NewCanaryController(canaryStore, probes, b.logger, b.recorder)
}

// startGovernanceWorkers launches the governance background loops after the
// Server is constructed: the rotation scheduler, the config-drift broadcast
// loop, and the break-glass expiry sweeper. Each records a cancel+done pair for
// graceful shutdown.
func (b *appBuilder) startGovernanceWorkers(srv *sso.Server) error {
	if b.clientStore != nil {
		ctx, cancel := context.WithCancel(context.Background())
		b.clientSecretScanCancel = cancel
		var scanOpts []rotation.ClientSecretExpiryScannerOption
		if b.redis != nil {
			scanOpts = append(scanOpts, rotation.WithClientSecretWarningClaimStore(
				redisbackend.NewClientSecretWarningClaimStore(b.redis)))
		}
		b.clientSecretScanDone = rotation.StartClientSecretScan(
			ctx, b.clientStore, b.recorder, b.metricsRegistry, b.logger, scanOpts...)
		b.logger.Info("client secret expiry scan enabled", "interval", rotation.ClientSecretScanInterval)
	}
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
	if b.configCanaryController != nil {
		ctx, cancel := context.WithCancel(context.Background())
		b.configCanaryCancel = cancel
		b.configCanaryDone = b.configCanaryController.Run(ctx)
	}
	if b.sessionTrustDecayOn {
		ctx, cancel := context.WithCancel(context.Background())
		b.continuousVerifyCancel = cancel
		b.continuousVerifyDone = srv.StartContinuousVerification(ctx)
	}
	b.startCAPConvergence(srv)
	b.startTokenAnomalySweep(srv)
	b.startBreakGlassSweeper(srv)
	b.startUserAutoDeprovisionSweep(srv)
	return nil
}

// startTokenAnomalySweep runs Server.RunTokenAnomalyDetection in a goroutine
// wrapped in the standard cancel+done pair. No-op when no detector is wired
// (token_anomaly disabled). The recorder that feeds the detector is drained
// separately at shutdown (main_shutdown.go).
func (b *appBuilder) startTokenAnomalySweep(srv *sso.Server) {
	if b.tokenAnomalyDetector == nil {
		return
	}
	interval := b.cfg.TokenAnomaly.SweepInterval
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.tokenAnomalySweepCancel, b.tokenAnomalySweepDone = cancel, done
	go func() { defer close(done); srv.RunTokenAnomalyDetection(ctx, interval) }()
	b.logger.Info("token anomaly sweep enabled", "interval", interval)
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
