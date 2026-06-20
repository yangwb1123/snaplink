package main

import (
	"context"
	"crypto"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/netpolicy"
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

	metricsRegistry *metrics.Metrics

	opts                 []sso.Option
	storageHealthSources []sso.StorageHealthSource

	// Schema-check context, reused for every SQLite boot gate.
	schemaCtx context.Context

	// Core identity + signing wiring.
	clientStore    sso.ClientStore
	userProvider   sso.UserProvider
	sessionMgr     sso.SessionManager
	jwtIssuer      signingIssuer
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

	// Authenticators.
	tempStore       authenticators.TempTokenStore
	totpAuth        *authenticators.TOTPAuthenticator
	totpEnrollStore sso.MFAEnrollmentStore

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
	srv = sso.NewServer(b.opts...)

	rt := serverRuntime{server: srv, cluster: cw}
	rt.busStop, rt.signingKeyStop, rt.keyRotationStop, rt.keyRotationCancel, err = b.startBackgroundWorkers(srv, cw)
	if err != nil {
		return nil, err
	}
	if b.cfg.Admin.Enabled {
		rt.adminMW = sso.NewAdminMiddleware(srv, b.provider)
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

// serverRuntime carries the post-NewServer handles assemble folds into the
// *app alongside the appBuilder's pre-NewServer state.
type serverRuntime struct {
	server            *sso.Server
	cluster           *clusterWiring
	snapshots         *snapshotReleaseWiring
	adminMW           *sso.AdminMiddleware
	busStop           <-chan struct{}
	signingKeyStop    <-chan struct{}
	keyRotationStop   <-chan struct{}
	keyRotationCancel context.CancelFunc
}

// assemble folds the accumulated builder state + runtime handles into the
// final *app. Pure field mapping — no behavior.
func (b *appBuilder) assemble(rt serverRuntime) *app {
	cw, srw := rt.cluster, rt.snapshots
	return &app{
		server: rt.server, recorder: b.recorder, provider: b.provider, registry: cw.reg,
		netStore:                b.netStore,
		classifier:              b.classifier,
		clientStore:             b.clientStore,
		userProvider:            b.userProvider,
		sessionMgr:              b.sessionMgr,
		tempStore:               b.tempStore,
		tokenIssuers:            b.tokenIssuers,
		idTokenIssuer:           b.jwtIssuer,
		refreshTokenStore:       b.refreshTokenStore,
		refreshTokenTTL:         b.refreshTokenTTL,
		adminMW:                 rt.adminMW,
		snapshotPipeline:        srw.pipeline,
		snapshotStorage:         srw.storage,
		snapshotter:             srw.snapshotter,
		snapshotRestorer:        srw.restorer,
		releaseRegistry:         srw.releaseRegistry,
		releaseStore:            srw.releaseStore,
		tenantStore:             b.tenantStore,
		connectionStore:         b.connectionStore,
		regionResolver:          b.regionResolver,
		webauthnHelper:          b.webauthnHelper,
		auditAsyncSink:          b.asyncSink,
		auditRetentionCancel:    b.auditRetentionCancel,
		auditRetentionDone:      b.auditRetentionDone,
		snapshotRetentionCancel: srw.retentionCancel,
		snapshotRetentionDone:   srw.retentionDone,
		pushPruneCancel:         b.pushPruneCancel,
		anomalyRT:               b.anomalyRT,
		pushPruneDone:           b.pushPruneDone,
		cibaPruneCancel:         b.cibaPruneCancel,
		cibaPruneDone:           b.cibaPruneDone,
		pushApprovalStore:       pushApprovalStoreIface(b.pushApprovalStore),
		pushNotify:              b.pushNotify,
		metrics:                 b.metricsRegistry,
		netStop:                 b.netStop,
		netCancel:               b.netCancel,
		invalidationBus:         cw.invalidationBus,
		busStop:                 rt.busStop,
		signingKeyRegistry:      cw.signingKeyRegistry,
		signingKeyStop:          rt.signingKeyStop,
		keyRotationCancel:       rt.keyRotationCancel,
		keyRotationStop:         rt.keyRotationStop,
	}
}
