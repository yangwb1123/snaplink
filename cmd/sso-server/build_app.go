package main

import (
	"context"
	"crypto"
	"database/sql"
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
	"github.com/snaplink/sso/infrastructure/defaultimpl/emailsmtp"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/oauth"
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
	b.lateBindComplianceStores()
	srv = sso.NewServer(b.opts...)
	rt := serverRuntime{server: srv, cluster: cw}
	rt.busStop, rt.signingKeyStop, rt.keyRotationStop, rt.keyRotationCancel, err = b.startBackgroundWorkers(srv, cw)
	if err != nil {
		return nil, err
	}
	// On-demand signing-key rotation admin service (needs srv for the hook).
	rt.keyAdmin = b.buildKeyAdminService(srv)
	if b.cfg.Admin.Enabled {
		rt.adminMW = sso.NewAdminMiddleware(srv, b.provider)
		// Apply admin rate limit when configured.
		if rate, burst := srv.AdminRateLimit(); rate > 0 && burst > 0 {
			rt.adminMW.SetRateLimit(rate, burst)
		}
		// Wire admin token store and idle timeout when both configured.
		if store := srv.AdminTokenStore(); store != nil {
			rt.adminMW.SetAdminTokenStore(store)
			if ttl := srv.AdminSessionTTL(); ttl > 0 {
				rt.adminMW.SetAdminSessionTTL(ttl)
			}
		}
	}
	rt.snapshots, err = b.wireSnapshotReleases()
	if err != nil {
		return nil, err
	}
	if err := b.registerService(cw); err != nil {
		return nil, err
	}
	return b.assemble(rt), nil
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
	// Pairs moved out of the literal to keep assemble within the length budget.
	a.consentStore, a.mfaEnrollStore = b.consentStore, b.mfaEnrollStore
	a.pushPruneCancel, a.pushPruneDone = b.pushPruneCancel, b.pushPruneDone
	a.cibaPruneCancel, a.cibaPruneDone = b.cibaPruneCancel, b.cibaPruneDone
	a.netStop, a.netCancel = b.netStop, b.netCancel
	return a
}
