package main

import (
	"context"
	"crypto"
	"database/sql"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	postgresbackend "github.com/snaplink/sso/infrastructure/postgres"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/domains/tokenanomaly"
	"github.com/snaplink/sso/domains/tokenusage"
	"github.com/snaplink/sso/infrastructure/defaultimpl/emailsmtp"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/storageinline"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/platform/lifecycle/admingovernance"
	"github.com/snaplink/sso/platform/lifecycle/dr"
	"github.com/snaplink/sso/platform/lifecycle/rotation"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// appBuilder threads the shared mutable wiring state through buildApp's
// cohesive sub-builders. buildApp is pure server-assembly: each wireXxx
// method appends Options to b.opts (order-significant — option order can
// change which security feature wins) and accumulates the storage-health
// sources + background-worker lifecycle handles that the final *app needs.
// The struct exists ONLY to keep that ordered accumulation explicit while
// the body is split below the 50-line / cyclo-15 budget; it changes no
// behavior. Field names mirror the original buildApp locals 1:1.
type appBuilder struct {
	cfg    *config.Config
	logger spi.Logger

	// redis is the one shared Redis client (single/sentinel/cluster) fanned
	// out to every store whose backend is "redis". Built first by wireRedis so
	// all later wireXxx can consume it, and Closed once at shutdown. Nil when
	// no redis block is configured (memory/sqlite deployments are unaffected).
	redis goredis.UniversalClient

	// pgDB is the one shared Postgres-wire *sql.DB pool fanned out to every
	// DURABLE store whose backend is "postgres"; pgDialect picks the
	// postgres/cockroach behavior. Built by wirePostgres, Closed at shutdown.
	// Nil when no postgres block is configured.
	pgDB      *sql.DB
	pgDialect postgresbackend.Dialect

	metricsRegistry *metrics.Metrics

	opts                 []sso.Option
	storageHealthSources []sso.StorageHealthSource

	// Schema-check context, reused for every SQLite boot gate.
	schemaCtx context.Context

	// Core identity + signing wiring.
	clientStore    sso.ClientStore
	userProvider   sso.UserProvider
	sessionMgr     sso.SessionManager
	jwtIssuer      serverbuildsign.SigningIssuer
	signingAlg     string
	externalSigner crypto.Signer
	tokenIssuers   map[string]sso.TokenIssuer

	// Audit subsystem.
	recorder             *audit.Recorder
	asyncSink            *audit.AsyncSink
	auditRetentionCancel context.CancelFunc
	auditRetentionDone   <-chan struct{}
	// auditKafkaSink is the RAW (pre-RetryingSink) Kafka audit sink, non-nil
	// only when audit.kafka.enabled — retained so shutdownSubsystems can
	// Close it (flush + disconnect the producer). audit.Sink (an interface)
	// rather than a concrete type: the concrete implementation lives in the
	// infrastructure/kafka nested module, which this (the core) module never
	// imports.
	auditKafkaSink audit.Sink

	// Permissions.
	provider permissions.Provider

	// Network policy.
	classifier *netpolicy.Classifier
	netStore   netpolicy.Store
	netStop    <-chan struct{}
	netCancel  context.CancelFunc

	// Self-service password store (shared by login verifier + change EP).
	passwordStore sso.PasswordCredentialStore

	// emailSender is the built-in SMTP sender backing the four shared/spi
	// token-delivery options (nil when smtp.enabled=false or no host is
	// configured). serverbuildauthn builds its OWN Sender instance for the
	// email-OTP transport (see appendEmailAuthenticator) — kept independent
	// so authenticator wiring doesn't depend on self-service build order;
	// both share the same config.SMTPConfig -> emailsmtp.Config translation.
	emailSender *emailsmtp.Sender

	// Authenticators.
	tempStore       authenticators.TempTokenStore
	totpAuth        *authenticators.TOTPAuthenticator
	totpEnrollStore sso.MFAEnrollmentStore

	// Erasure-relevant stores, retained so the GDPR eraser can clear the
	// inheritable state a re-registered account would otherwise pick up.
	consentStore   sso.ConsentStore
	mfaEnrollStore sso.MFAEnrollmentStore
	// accountEraser is the self-service /me/account/erase eraser, retained so
	// finalize can late-bind Consent + MFAEnrollments AFTER their stores wire
	// (it's constructed in wireDomains, before those stores exist).
	accountEraser *compliance.Eraser
	// dataExporter is the self-service /me/data-export exporter, retained so
	// finalize can late-bind Extra (consent + MFA enrollments) AFTER their
	// stores wire (it's constructed in wireDomains, before those stores exist)
	// — same ordering problem as accountEraser above, same fix.
	dataExporter *compliance.Exporter

	// Region.
	regionResolver region.Resolver

	// WebAuthn.
	webauthnHelper *webauthn.Helper
	webauthnUsers  webauthn.UserStore

	// MFA push lifecycle.
	pushApprovalStore *sqlitestores.PushApprovalStore
	pushNotify        func(string)
	pushPruneCancel   context.CancelFunc
	pushPruneDone     <-chan struct{}

	// Anomaly subsystem.
	anomalyRT *anomalyRuntime

	// Tenant + connections.
	tenantStore     tenant.Store
	connectionStore connections.Store

	// OAuth refresh-token store (consumed by self-service erase + CAEP recv).
	refreshTokenStore oauth.RefreshTokenStore
	refreshTokenTTL   time.Duration

	// CIBA prune lifecycle.
	cibaPruneCancel context.CancelFunc
	cibaPruneDone   <-chan struct{}

	// Refresh grace prune lifecycle (SQLite backend only; cleanup goroutine
	// for expired refresh_grace_cache rows).
	refreshGracePruneCancel context.CancelFunc
	refreshGracePruneDone   <-chan struct{}

	// Governance subsystems (wave-2 cmd wiring). credentialScheduler is built
	// by wireCredentialRotation (pre-NewServer) and Started by
	// startGovernanceWorkers (post-NewServer); the cancel/done pairs mirror the
	// audit/snapshot retention lifecycle. configAuditStore is retained so
	// assemble folds it into the *app for Close at shutdown. All nil when the
	// owning config section is disabled.
	credentialScheduler   *rotation.Scheduler
	credentialSchedCancel context.CancelFunc
	credentialSchedDone   <-chan struct{}
	configAuditStore      configaudit.Store
	configDriftCancel     context.CancelFunc
	configDriftDone       <-chan struct{}
	breakGlassStore       core.BreakGlassStore
	breakGlassCancel      context.CancelFunc
	breakGlassDone        <-chan struct{}

	// sessionTrustDecayOn is set by wireSessionTrustDecay when the zero-trust
	// session-trust-decay feature is enabled; startGovernanceWorkers then launches
	// the ContinuousVerificationAgent under the continuousVerify cancel/done pair.
	sessionTrustDecayOn    bool
	continuousVerifyCancel context.CancelFunc
	continuousVerifyDone   <-chan struct{}

	// Token-anomaly subsystem (wave-4 cmd wiring, token_anomaly.enabled).
	// tokenUsageRecorder is the bounded-buffer telemetry substrate whose drain
	// feeds tokenAnomalyDetector (the tokenusage.Store decorator it wraps); both
	// are built pre-NewServer by wireTokenAnomaly and the RunTokenAnomalyDetection
	// sweep is Started post-NewServer under the tokenAnomalySweep cancel/done pair.
	// The recorder is Closed at shutdown to drain its queue. All nil when off.
	tokenUsageRecorder      *tokenusage.Recorder
	tokenAnomalyDetector    *tokenanomaly.Detector
	tokenAnomalySweepCancel context.CancelFunc
	tokenAnomalySweepDone   <-chan struct{}

	// degradationMgr is the disaster-recovery degraded-service Manager
	// (degradation.enabled). It has no background loop — the admin
	// /api/v1/admin/dr/mode endpoints wired by WithDegradationManager drive it —
	// so it carries no cancel/done pair; retained only so the *app can expose the
	// current posture (and a future health loop can call SetMode). Nil when off.
	degradationMgr *sso.DegradationManager
}

// finalize wires the cluster subsystems + the last Options, constructs the
// Server, starts the background workers, builds the admin middleware + the
// snapshot/release subsystems, self-registers in the registry, and assembles
// the *app. The forward-declared srv lets the readiness checks registered in
// wireCluster close over the not-yet-constructed Server.
func (b *appBuilder) finalize() (*app, error) {
	var srv *sso.Server
	cw, err := b.wireCluster(&srv)
	if err != nil {
		return nil, err
	}
	if err := b.wireFinalOptions(); err != nil {
		return nil, err
	}
	if err := b.wireGovernance(); err != nil {
		return nil, err
	}
	// Late-bind the self-service eraser + exporter's consent + MFA stores: they
	// wire in wireFinalOptions, AFTER wireDomains constructed the eraser/exporter
	// (build order), so both captured them nil. See lateBindComplianceStores.
	b.lateBindComplianceStores()
	srv = sso.NewServer(b.opts...)
	rt := serverRuntime{server: srv, cluster: cw}
	rt.busStop, rt.signingKeyStop, rt.keyRotationStop, rt.keyRotationCancel, err = b.startBackgroundWorkers(srv, cw)
	if err != nil {
		return nil, err
	}
	if err := b.startGovernanceWorkers(srv); err != nil {
		return nil, err
	}
	// On-demand signing-key rotation admin service (needs srv for the hook).
	rt.keyAdmin = b.buildKeyAdminService(srv)
	rt.adminMW = b.wireAdminMW(srv)
	rt.snapshots, err = b.wireSnapshotReleases()
	if err != nil {
		return nil, err
	}
	// DR replication reuses the just-built snapshot pipeline's export, so it
	// wires AFTER wireSnapshotReleases — before that call srw.pipeline is
	// always nil.
	rt.dr, err = b.wireDR(rt.snapshots)
	if err != nil {
		return nil, err
	}
	if err := b.registerService(cw); err != nil {
		return nil, err
	}
	return b.assemble(rt), nil
}

// wireAdminMW builds the admin middleware (rate limit + token store + idle
// timeout) when admin is enabled; nil otherwise (admin disabled — matches
// the original inline assembly byte-identically). Split out of finalize to
// keep it under the function-length budget.
func (b *appBuilder) wireAdminMW(srv *sso.Server) *sso.AdminMiddleware {
	if !b.cfg.Admin.Enabled {
		return nil
	}
	mw := sso.NewAdminMiddleware(srv, b.provider)
	// The wasmauthz admin debug route is a read-only decision probe (POST,
	// for its JSON body, but no state mutation) — override the default
	// GET=read/mutation=write HTTP rule for just this one path so it needs
	// admin:read rather than admin:write. See interfaces/admin/governance.go's
	// methodScopeForPath for the (longest-prefix) override lookup.
	mw.SetMethodScope(sso.PathAPIPrefix+sso.PathAdminWASMAuthzCheck, sso.AdminScopeRead)
	// Same override for the cross-cluster config-diff probe: POST for its
	// JSON body, but it only reads + diffs, never mutates.
	mw.SetMethodScope(sso.PathAPIPrefix+sso.PathAdminConfigClusterDiff, sso.AdminScopeRead)
	if rate, burst := srv.AdminRateLimit(); rate > 0 && burst > 0 {
		mw.SetRateLimit(rate, burst)
	}
	if store := srv.AdminTokenStore(); store != nil {
		mw.SetAdminTokenStore(store)
		if ttl := srv.AdminSessionTTL(); ttl > 0 {
			mw.SetAdminSessionTTL(ttl)
		}
	}
	b.wireAdminGovernanceMW(mw, srv)
	return mw
}

// wireAdminGovernanceMW wires the admin governance framework's
// transport-level checks onto mw: the per-tenant/admin write quota, the
// destructive-action confirmation guard, and the IP-allowlist/geo-lock.
// Each is independently opt-in (its own config section); an unconfigured
// section calls no setter, leaving mw byte-identical on that axis. Split
// out of wireAdminMW to keep it under the function-length budget. The
// IP-allowlist's country dimension reuses srv.GeoProvider() (the SAME
// provider WithGeoProvider wired for the enrichment middleware) rather than
// building a second one.
func (b *appBuilder) wireAdminGovernanceMW(mw *sso.AdminMiddleware, srv *sso.Server) {
	cfg := b.cfg
	if q := cfg.AdminWriteQuota; q.Enabled {
		mw.SetWriteQuota(admingovernance.NewMemoryWriteQuotaStore(), q.Limit, q.Window, q.KeyBy)
		b.logger.Info("admin governance: write quota enabled", "limit", q.Limit, "window", q.Window, "key_by", q.KeyBy)
	}
	if d := cfg.AdminDestructive; d.Enabled {
		rules := make([]admingovernance.DestructiveRule, 0, len(d.Rules))
		for _, r := range d.Rules {
			rules = append(rules, admingovernance.DestructiveRule{Method: r.Method, PathPrefix: r.PathPrefix, Action: r.Action})
		}
		mw.SetDestructiveActions(admingovernance.NewDestructiveSet(rules))
		b.logger.Info("admin governance: destructive-action confirmation guard enabled", "rules", len(rules))
	}
	if ip := cfg.AdminIPAllowlist; ip.Enabled {
		allow, err := admingovernance.ParseIPAllowlistConfig(ip.CIDRs, ip.Countries)
		if err != nil {
			b.logger.Error("admin governance: invalid ip allowlist config, gate NOT installed", "error", err)
			return
		}
		mw.SetIPAllowlist(allow, srv.GeoProvider())
		b.logger.Info("admin governance: ip allowlist/geo-lock enabled", "cidrs", len(ip.CIDRs), "countries", len(ip.Countries))
	}
}

// lateBindComplianceStores sets Consent + MFAEnrollments on the self-service
// eraser and exporter AFTER wireFinalOptions has wired those stores. Both
// compliance.Eraser/Exporter pointers are constructed early in wireDomains
// (before consentStore/mfaEnrollStore exist), so a one-shot assignment at
// construction time would silently capture nil — the SDK holds each by
// pointer and reads these fields at request time, so setting them here (once,
// right before NewServer) makes self-erasure AND self-export agree with the
// admin compliance routes on what "the subject's consent + MFA data" is.
func (b *appBuilder) lateBindComplianceStores() {
	if b.accountEraser != nil {
		b.accountEraser.Consent = b.consentStore
		b.accountEraser.MFAEnrollments = b.mfaEnrollStore
	}
	if b.dataExporter != nil {
		b.dataExporter.Extra = compliance.SubjectExporters(b.consentStore, b.mfaEnrollStore)
	}
}

// serverRuntime carries the post-NewServer handles assemble folds into the
// *app alongside the appBuilder's pre-NewServer state.
type serverRuntime struct {
	server            *sso.Server
	cluster           *clusterWiring
	snapshots         *snapshotReleaseWiring
	dr                *drWiring
	adminMW           *sso.AdminMiddleware
	keyAdmin          *grpcserver.KeyAdminService
	busStop           <-chan struct{}
	signingKeyStop    <-chan struct{}
	keyRotationStop   <-chan struct{}
	keyRotationCancel context.CancelFunc
}

// assemble folds the accumulated builder state + runtime handles into the
// final *app. Pure field mapping — no behavior.
func (b *appBuilder) assemble(rt serverRuntime) *app {
	cw, srw := rt.cluster, rt.snapshots
	a := &app{
		server: rt.server, recorder: b.recorder, provider: b.provider, registry: cw.reg,
		netStore:          b.netStore,
		classifier:        b.classifier,
		clientStore:       b.clientStore,
		userProvider:      b.userProvider,
		sessionMgr:        b.sessionMgr,
		tempStore:         b.tempStore,
		tokenIssuers:      b.tokenIssuers,
		idTokenIssuer:     b.jwtIssuer,
		refreshTokenStore: b.refreshTokenStore,
		refreshTokenTTL:   b.refreshTokenTTL,
		adminMW:           rt.adminMW,
		snapshotPipeline:  srw.pipeline,
		snapshotStorage:   srw.storage,
		snapshotter:       srw.snapshotter,
		snapshotRestorer:  srw.restorer,
		keyAdmin:          rt.keyAdmin,
		releaseRegistry:   srw.releaseRegistry, releaseStore: srw.releaseStore,
		tenantStore:             b.tenantStore,
		connectionStore:         b.connectionStore,
		regionResolver:          b.regionResolver,
		webauthnHelper:          b.webauthnHelper,
		auditAsyncSink:          b.asyncSink,
		auditRetentionCancel:    b.auditRetentionCancel,
		auditRetentionDone:      b.auditRetentionDone,
		snapshotRetentionCancel: srw.retentionCancel,
		snapshotRetentionDone:   srw.retentionDone,
		anomalyRT:               b.anomalyRT,
		pushApprovalStore:       serverbuildsign.PushApprovalStoreIface(b.pushApprovalStore),
		pushNotify:              b.pushNotify,
		metrics:                 b.metricsRegistry,
		invalidationBus:         cw.invalidationBus,
		busStop:                 rt.busStop,
		signingKeyRegistry:      cw.signingKeyRegistry,
		signingKeyStop:          rt.signingKeyStop,
		keyRotationCancel:       rt.keyRotationCancel,
		keyRotationStop:         rt.keyRotationStop,
		redisClient:             b.redis,
		pgDB:                    b.pgDB,
	}
	b.assembleExtras(a, rt)
	return a
}

// assembleExtras lives in build_app_core.go (relocated to keep this file
// under the 500-line maintainability budget).

// drFields extracts the DR handles from dw; a nil dw (dr.enabled=false)
// returns all-zero values, matching the "nil means off" convention every
// other optional subsystem here follows.
func drFields(dw *drWiring) (*dr.DRReadiness, context.CancelFunc, <-chan struct{}) {
	if dw == nil {
		return nil, nil, nil
	}
	return dw.readiness, dw.cancel, dw.done
}

// drWiring carries the DR subsystem's post-construction handles: the
// SnapshotReplicator background loop's Cancel+Done lifecycle pair (same
// shape as snapshot/audit retention, see main_shutdown.go) and the
// DRReadiness aggregate the admin status endpoint + optional /readyz gate
// both read from.
type drWiring struct {
	readiness *dr.DRReadiness
	cancel    context.CancelFunc
	done      <-chan struct{}
}

// wireDR starts the background snapshot-replication loop when dr.enabled.
// Requires the snapshot subsystem (srw.pipeline + srw.snapshotter) to
// already be wired — DR replicates the SAME sealed export the manual/
// retention snapshot pipeline produces; it does not stand up a second
// export path. Returns (nil, nil) when dr.enabled is false, matching the
// nil-means-off convention every other optional subsystem here follows.
func (b *appBuilder) wireDR(srw *snapshotReleaseWiring) (*drWiring, error) {
	cfg := b.cfg.DR
	if !cfg.Enabled {
		return nil, nil
	}
	if srw.pipeline == nil || srw.snapshotter == nil {
		return nil, fmt.Errorf("dr.enabled requires snapshot.enabled=true (DR replicates the configured snapshot pipeline's export)")
	}
	replicator, err := dr.NewSnapshotReplicator(
		buildDRExportFunc(srw.pipeline, srw.snapshotter),
		cfg.TargetDir, cfg.Interval, cfg.Keep, b.logger,
	)
	if err != nil {
		return nil, err
	}
	tracker := dr.NewRecoveryTimeTracker(cfg.RTOHistory)
	readiness := dr.NewDRReadiness(replicator, tracker, cfg.RPOTarget, cfg.RTOTarget)
	if b.metricsRegistry != nil {
		b.metricsRegistry.Registry.MustRegister(metrics.NewDRCollector(readiness))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := replicator.Run(ctx)
	b.logger.Info("dr: snapshot replication scheduler enabled",
		"target_dir", replicator.TargetDir, "interval", replicator.Interval, "keep", replicator.Keep,
		"rpo_target", cfg.RPOTarget, "gate_readiness", cfg.GateReadiness)
	return &drWiring{readiness: readiness, cancel: cancel, done: done}, nil
}

// buildDRExportFunc adapts the snapshot Export + Pipeline.Save pair to
// dr.ExportFunc. Pipeline.Save writes through a snapshot.Storage, so an
// in-memory storageinline.Storage captures the sealed envelope bytes for
// this one call without a second persistent write — exactly the "dummy
// backend" use case documented on that package (the caller only wants the
// SealedEnvelope bytes back, the replicator owns the actual DR-mount copy).
func buildDRExportFunc(pipeline *snapshot.Pipeline, snapshotter *snapshot.Snapshotter) dr.ExportFunc {
	return func(ctx context.Context) (string, []byte, error) {
		snap, err := snapshotter.Export(ctx, snapshot.ExportOptions{})
		if err != nil {
			return "", nil, fmt.Errorf("dr: snapshot export: %w", err)
		}
		buf := inline.New()
		if err := pipeline.Save(ctx, snap, buf, snap.SnapshotID); err != nil {
			return "", nil, fmt.Errorf("dr: seal: %w", err)
		}
		data, ok := buf.Bytes(snap.SnapshotID)
		if !ok {
			return "", nil, fmt.Errorf("dr: sealed envelope missing after save")
		}
		return snap.SnapshotID, data, nil
	}
}
