package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
	"github.com/yangwb1123/snaplink/platform/registry"
	"github.com/yangwb1123/snaplink/platform/releases"
	"github.com/yangwb1123/snaplink/platform/signingkeys"
)

// rotatableIssuer is the scheduled-rotation seam cmd needs from the signing
// issuer. All four built-in algs satisfy it; a custom WithTokenIssuer that
// only implements manual RotateKey/RetireKey will not, and degrades gracefully.
type rotatableIssuer interface {
	StartRotation(context.Context, defaultimpl.RotationConfig) <-chan struct{}
}

// defaultRuntimeRotateGrace is the fallback overlap window for an on-demand
// admin rotation when keys.rotation.grace_period is unset (the scheduled loop
// may be disabled entirely). It MUST be >= the max access-token TTL so tokens
// minted just before the rotation stay verifiable; 24h dwarfs any sane
// access-token lifetime. Operators running shorter windows set grace_period.
const defaultRuntimeRotateGrace = 24 * time.Hour

// runtimeKeyRotator is the on-demand rotation seam cmd needs from the primary
// JWT signing issuer. All three built-in software algs satisfy it; a custom
// WithTokenIssuer without RotateNow does not (→ Unimplemented), and an external
// signer is refused before this even matters (→ FailedPrecondition).
type runtimeKeyRotator interface {
	RotateNow() (string, error)
	ScheduleRetire(kid string, after time.Duration)
	KeyID() string
}

// buildKeyAdminService wires the admin runtime signing-key rotation RPC. The
// rotate closure REUSES makeRotateHook so an on-demand rotation produces the
// SAME side effects as the scheduled loop (audit + discovery bust + metrics +
// PublishSigningKeys + coordinated broadcast), then arranges the grace-delayed
// local retire. An external signer owns its lifecycle in the KMS/HSM (the RPC
// refuses with FailedPrecondition); a non-rotatable issuer leaves rotate nil
// (→ Unimplemented). List works regardless (public JWKS metadata only).
func (b *appBuilder) buildKeyAdminService(srv *sso.Server) *grpcserver.KeyAdminService {
	external := strings.TrimSpace(b.cfg.Keys.Signing.External) != ""
	grace := b.cfg.Keys.Rotation.GracePeriod
	if grace <= 0 {
		grace = defaultRuntimeRotateGrace
	}
	cfg := grpcserver.KeyAdminConfig{
		ExternalManaged: external,
		DefaultGrace:    grace,
		Issuers:         b.tokenIssuers,
		Recorder:        b.recorder,
	}
	if rotator, ok := b.jwtIssuer.(runtimeKeyRotator); ok && !external {
		cfg.Rotate = b.makeRuntimeRotate(srv, rotator)
	}
	return grpcserver.NewKeyAdminService(cfg)
}

// makeRuntimeRotate is the injected rotate closure: promote a fresh key, fire
// the shared side-effect hook with the request's grace, then schedule the
// demoted key's grace-delayed retire.
func (b *appBuilder) makeRuntimeRotate(srv *sso.Server, rotator runtimeKeyRotator) func(context.Context, time.Duration) (string, string, error) {
	return func(_ context.Context, grace time.Duration) (string, string, error) {
		old := rotator.KeyID()
		nw, err := rotator.RotateNow()
		if err != nil {
			return old, "", err
		}
		b.makeRotateHook(srv, grace)(old, nw)
		rotator.ScheduleRetire(old, grace)
		return old, nw, nil
	}
}

// snapshotReleaseWiring bundles the snapshot + release subsystem handles the
// final *app needs, plus the snapshot-retention lifecycle pair.
type snapshotReleaseWiring struct {
	pipeline        *snapshot.Pipeline
	storage         snapshot.Storage
	snapshotter     *snapshot.Snapshotter
	restorer        *snapshot.Restorer
	releaseRegistry *releases.Registry
	releaseStore    releases.ReleaseStore
	operationStore  operations.Store
	retentionCancel context.CancelFunc
	retentionDone   <-chan struct{}
}

// clusterWiring holds the cross-replica + finalize-stage handles that span the
// pre- and post-NewServer steps (the readiness checks close over srv, which is
// only assigned by sso.NewServer).
type clusterWiring struct {
	reg                registry.Registry
	regKind            string
	invalidationBus    cluster.Bus
	signingKeyRegistry signingkeys.Registry
}

// wireCluster builds the service registry, the cross-replica invalidation bus,
// and the shared signing-key registry, plus their readiness checks that close
// over the forward-declared *sso.Server.
func (b *appBuilder) wireCluster(srv **sso.Server) (*clusterWiring, error) {
	cfg, logger := b.cfg, b.logger
	cw := &clusterWiring{}

	if err := b.wireServiceRegistry(cw); err != nil {
		return nil, err
	}

	// Cross-replica invalidation bus built before NewServer so the option is in
	// place; the subscriber is started just after (needs the Server).
	invalidationBus, _, err := serverbuildplatform.BuildInvalidationBus(&cfg.Cluster.Bus, logger)
	if err != nil {
		return nil, fmt.Errorf("invalidation bus: %w", err)
	}
	cw.invalidationBus = invalidationBus
	if err := b.wireInvalidationBusOpts(invalidationBus); err != nil {
		return nil, err
	}

	// Shared signing-key registry (opt-in leaderless multi-replica JWKS
	// aggregation). Built before NewServer so the option is in place; the
	// publish/subscribe loop starts just after (needs the Server).
	signingKeyRegistry, _, err := serverbuildplatform.BuildSigningKeyRegistry(&cfg.Keys.SigningKeyRegistry, logger)
	if err != nil {
		return nil, fmt.Errorf("signing key registry: %w", err)
	}
	cw.signingKeyRegistry = signingKeyRegistry
	// srv is forward-declared so the readiness checks registered below can close
	// over it: each runs at /readyz probe time, long after sso.NewServer.
	if invalidationBus != nil {
		// Trip /readyz when the invalidation-bus subscriber goes degraded (its
		// bus stream closed under a live context and it's resubscribing) — the
		// replica is no longer applying cross-replica invalidations.
		b.opts = append(b.opts,
			sso.WithReadyCheck("invalidation-bus", func(context.Context) error {
				return (*srv).InvalidationBusReady()
			}),
		)
	}
	b.wireSigningKeyRegistryOpts(signingKeyRegistry, srv)
	return cw, nil
}

// wireServiceRegistry builds the service registry before NewServer so its etcd
// Ping can participate in /readyz alongside the SQLite peers. Self-registration
// happens later (needs cfg.Server.Listen resolved).
func (b *appBuilder) wireServiceRegistry(cw *clusterWiring) error {
	reg, regKind, err := serverbuildplatform.BuildRegistry(&b.cfg.Registry, b.logger)
	if err != nil {
		return fmt.Errorf("service registry: %w", err)
	}
	cw.reg = reg
	cw.regKind = regKind
	if regKind == "etcd" {
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "etcd-registry", reg)
	}
	return nil
}

// wireInvalidationBusOpts wires the bus Option + the coordinated-rotation and
// cross-replica-revocation riders. These two are SECURITY features whose only
// purpose is cross-replica propagation, so arming them without a live Bus is a
// misconfiguration that would silently leak revoked tokens / skip coordinated
// cutover. Fail CLOSED at boot (clear, actionable) instead of the old
// log-and-continue, which left a multi-replica fleet exposed with only a warning.
func (b *appBuilder) wireInvalidationBusOpts(invalidationBus cluster.Bus) error {
	cfg, logger := b.cfg, b.logger
	if invalidationBus == nil {
		if cfg.Keys.Rotation.CoordinatedCutover {
			return errors.New("keys.rotation.coordinated_cutover requires a live cluster.bus (set cluster.bus.backend=etcd) — refusing to boot with it INERT")
		}
		if cfg.Cluster.CrossReplicaRevocation {
			return errors.New("cluster.cross_replica_revocation requires a live cluster.bus (set cluster.bus.backend=etcd) — refusing to boot with revocation propagation INERT")
		}
		return nil
	}
	b.opts = append(b.opts, sso.WithInvalidationBus(invalidationBus))
	// Deadline-coordinated same-kid rotation cutover rides the same bus.
	if cfg.Keys.Rotation.CoordinatedCutover {
		b.opts = append(b.opts, sso.WithCoordinatedKeyRotation())
		logger.Info("signing-key rotation: deadline-coordinated cutover armed")
	}
	// Cross-replica access-token revocation propagation rides the same bus.
	if cfg.Cluster.CrossReplicaRevocation {
		b.opts = append(b.opts, sso.WithCrossReplicaRevocation())
		logger.Info("revocation: cross-replica access-token propagation armed")
	}
	return nil
}

// wireSigningKeyRegistryOpts wires the shared signing-key registry + replica
// id + lease TTL + the aggregation readiness check (closing over srv).
func (b *appBuilder) wireSigningKeyRegistryOpts(signingKeyRegistry signingkeys.Registry, srv **sso.Server) {
	cfg, logger := b.cfg, b.logger
	if signingKeyRegistry == nil {
		return
	}
	// Default the replica id to the same hostname-derived id the service
	// registry uses, so two replicas of one issuer announce distinct ids.
	replicaID := strings.TrimSpace(cfg.Keys.SigningKeyRegistry.ReplicaID)
	if replicaID == "" {
		replicaID = serverbuildplatform.ResolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer)
	}
	b.opts = append(b.opts,
		sso.WithSharedSigningKeyRegistry(signingKeyRegistry),
		sso.WithSigningKeyReplicaID(replicaID),
		sso.WithSigningKeyLeaseTTL(cfg.Keys.SigningKeyRegistry.LeaseTTL),
		// Trip /readyz when the aggregation subscriber goes degraded (its
		// registry stream closed and it's resubscribing) — the replica is no
		// longer adopting peers' keys, so it may reject valid peer tokens.
		sso.WithReadyCheck("signing-key-aggregation", func(context.Context) error {
			return (*srv).SigningKeyAggregationReady()
		}),
	)
	// Distinct from the aggregation check above: only the etcd backend exposes
	// ReadyzCheck, tripping when THIS replica's publish-lease KeepAlive is
	// degraded — its keys are absent from peers' JWKS, so tokens it signs fail
	// verification fleet-wide and the LB must pull it while the lease
	// re-grants. The memory registry is process-local with no such failure
	// mode; the type-assertion gate silently no-ops for it, mirroring
	// serverbuildsign.AppendReadyCheck's memory-backend cadence.
	if rc, ok := signingKeyRegistry.(interface{ ReadyzCheck() error }); ok {
		b.opts = append(b.opts, sso.WithReadyCheck("etcd-signing-key-registry",
			func(context.Context) error { return rc.ReadyzCheck() }))
	}
	logger.Info("signing key aggregation enabled", "replica_id", replicaID)
}

// wireFinalOptions mounts storage-health, the setup-wizard API gate, the
// consent store, the native-SSO device-secret store, and the
// protected-resource metadata — the last Options before NewServer.
func (b *appBuilder) wireFinalOptions() error {
	cfg, logger := b.cfg, b.logger
	// Mount the per-store storage-health admin report only when the admin
	// middleware is enabled. The route is under /api/v1/admin/ which the
	// middleware guards with a bearer scope check; without admin enabled the
	// route would be served unauthenticated, leaking internal store names,
	// connectivity status, and on Ping errors raw driver strings with host/path
	// details to any caller on the same network.
	if len(b.storageHealthSources) > 0 && cfg.Admin.Enabled {
		b.opts = append(b.opts, sso.WithStorageHealth(b.storageHealthSources...))
		logger.Info("storage-health report enabled", "stores", len(b.storageHealthSources))
	} else if len(b.storageHealthSources) > 0 && !cfg.Admin.Enabled {
		logger.Info("storage-health report disabled: admin must be enabled to serve authenticated store diagnostics")
	}

	// sso-server serves no frontend of its own (admin console, hosted login,
	// self-service portal, developer portal, setup wizard all live in a
	// separate project, reverse-proxied alongside this server). The setup
	// wizard's public API pair (POST /api/v1/setup, GET /api/v1/setup/status)
	// still needs its own enable gate, independent of any UI.
	if cfg.SetupWizard.Enabled {
		b.opts = append(b.opts, sso.WithSetupWizardEnabled(true))
		logger.Info("setup wizard API enabled", "paths", "/api/v1/setup, /api/v1/setup/status")
	}

	return b.wireConsentNativeSSOPRM()
}

// startBackgroundWorkers boots the invalidation-bus subscriber, the
// signing-key aggregation loop, and the scheduled key-rotation loop. On
// subscribe failure it closes the registries (LIFO) and surfaces the error.
func (b *appBuilder) startBackgroundWorkers(srv *sso.Server, cw *clusterWiring) (busStop, signingKeyStop <-chan struct{}, keyRotationStop <-chan struct{}, keyRotationCancel context.CancelFunc, err error) {
	// Background ctx + Close-at-shutdown mirrors the netpolicy Classifier:
	// closing the bus ends the subscriber Watch, which closes busStop.
	busStop, err = srv.StartInvalidationBus(context.Background())
	if err != nil {
		if cw.invalidationBus != nil {
			_ = cw.invalidationBus.Close()
		}
		return nil, nil, nil, nil, fmt.Errorf("invalidation bus subscribe: %w", err)
	}

	// Signing-key aggregation: publish our public keys + adopt peers'. Same
	// background-ctx + Close-at-shutdown shape as the invalidation bus — closing
	// the registry ends the subscriber stream, closing signingKeyStop.
	signingKeyStop, err = srv.StartSigningKeyAggregation(context.Background())
	if err != nil {
		if cw.signingKeyRegistry != nil {
			_ = cw.signingKeyRegistry.Close()
		}
		if cw.invalidationBus != nil {
			_ = cw.invalidationBus.Close()
		}
		return nil, nil, nil, nil, fmt.Errorf("signing key aggregation start: %w", err)
	}

	keyRotationStop, keyRotationCancel = b.startKeyRotation(srv)
	return busStop, signingKeyStop, keyRotationStop, keyRotationCancel, nil
}

// startKeyRotation arms the scheduled signing-key rotation loop. External
// signers own their key lifecycle in the KMS/HSM, so in-process rotation is
// skipped for them. Returns nil handles when rotation is disabled or the issuer
// has no scheduled-rotation support.
func (b *appBuilder) startKeyRotation(srv *sso.Server) (<-chan struct{}, context.CancelFunc) {
	cfg, logger := b.cfg, b.logger
	rc, ok := serverbuildplatform.SigningKeyRotationConfig(cfg.Keys.Rotation)
	if ok && strings.TrimSpace(cfg.Keys.Signing.External) != "" {
		// An external signer owns its key lifecycle in the KMS/HSM; in-process
		// RotateKey would mint a key the backend never sees.
		logger.Info("keys.rotation enabled but ignored: an external signer (keys.signing.external) manages its own key lifecycle; in-process scheduled rotation disabled")
		return nil, nil
	}
	if !ok {
		return nil, nil
	}
	rc.OnRotate = b.makeRotateHook(srv, rc.GracePeriod)
	// All four built-in signing algs (EdDSA/ES256/RS256/PS256) ship a
	// StartRotation scheduler. The type assertion still guards the loop so a
	// custom WithTokenIssuer that implements only manual RotateKey/RetireKey
	// degrades gracefully (warn + skip) rather than failing boot.
	rotator, ok := b.jwtIssuer.(rotatableIssuer)
	if !ok {
		logger.Info("keys.rotation enabled but the configured signing issuer has no scheduled-rotation support; skipping the rotation loop (manual rotation still available)",
			"alg", b.signingAlg)
		return nil, nil
	}
	rotCtx, cancel := context.WithCancel(context.Background())
	stop := rotator.StartRotation(rotCtx, rc)
	logger.Info("signing key rotation enabled",
		"alg", b.signingAlg, "interval", rc.Interval, "grace_period", rc.GracePeriod)
	return stop, cancel
}

// makeRotateHook builds the OnRotate callback: it records an audit event, busts
// the discovery cache, re-publishes our keys, and broadcasts the coordinated
// retire deadline. Best-effort throughout; no-ops when the relevant subsystem
// (recorder / signing-key registry / invalidation bus) is not wired.
func (b *appBuilder) makeRotateHook(srv *sso.Server, grace time.Duration) func(string, string) {
	rec, logger := b.recorder, b.logger
	return func(oldKID, newKID string) {
		if rec != nil {
			rec.Record(context.Background(), &audit.Event{
				Type:      audit.EventSigningKeyRotated,
				Outcome:   audit.OutcomeSuccess,
				Timestamp: time.Now().UTC(),
				Reason:    "from=" + oldKID + " to=" + newKID,
			})
		}
		srv.InvalidateDiscoveryCache()
		if b.metricsRegistry != nil {
			b.metricsRegistry.SigningKeyRotationsTotal.Inc()
		}
		// Re-publish our keys so peers adopt the rotated kid (the announcement
		// replaces our prior one wholesale, dropping the retired kid from peers'
		// verify-sets after its grace window). No-op when no registry is wired.
		if err := srv.PublishSigningKeys(context.Background()); err != nil {
			logger.Error("signingkeys: re-publish after rotation failed", "error", err)
		}
		// Deadline-coordinated cutover: broadcast the demoted+new kids and a
		// now+grace retire deadline so every armed peer defers the demoted kid's
		// retirement to the SAME instant. Best-effort + no-op unless
		// WithCoordinatedKeyRotation + an invalidation bus are wired.
		srv.PublishSigningKeyRotation(context.Background(), oldKID, newKID, grace)
		logger.Info("signing key rotated", "from", oldKID, "to", newKID)
	}
}

// wireSnapshotReleases builds the snapshot + release subsystems, the snapshot
// retention loop, and wires snapshot-aware release rollback.
func (b *appBuilder) wireSnapshotReleases(srv *sso.Server) (*snapshotReleaseWiring, error) {
	cfg, logger := b.cfg, b.logger
	srw := &snapshotReleaseWiring{}

	pipeline, snapStorage, err := serverbuildstore.BuildSnapshotSubsystem(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("snapshot subsystem: %w", err)
	}
	srw.pipeline = pipeline
	srw.storage = snapStorage
	if pipeline != nil {
		b.buildSnapshotterRestorer(srw, srv)
	}

	releaseRegistry, releaseStore, err := serverbuildplatform.BuildReleaseSubsystem(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("release subsystem: %w", err)
	}
	srw.releaseRegistry = releaseRegistry
	srw.releaseStore = releaseStore
	srw.operationStore, err = serverbuildplatform.BuildOperationStore(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("operation store: %w", err)
	}
	if err := b.startSnapshotRetention(srw); err != nil {
		return nil, err
	}

	// Wire ConfigSnapshot-aware Rollback when both subsystems are enabled and
	// the operator opted in. Done here (after both factories) so the Registry
	// receives a fully-formed adapter with the runtime restorer/pipeline in
	// scope.
	if releaseRegistry != nil && pipeline != nil && cfg.Releases.SnapshotIntegration {
		releaseRegistry.SnapshotRestorer = &serverbuildstore.SnapshotRestorerAdapter{
			Pipeline: pipeline,
			Storage:  snapStorage,
			Restorer: srw.restorer,
		}
		logger.Info("release rollback wired with snapshot restore")
	}
	return srw, nil
}

// startSnapshotRetention boots the snapshot-retention prune loop when enabled,
// validating that the snapshot subsystem is present and keep > 0.
func (b *appBuilder) startSnapshotRetention(srw *snapshotReleaseWiring) error {
	rc := b.cfg.Snapshot.Retention
	if !rc.Enabled {
		return nil
	}
	if srw.pipeline == nil || srw.storage == nil {
		return errors.New("snapshot.retention.enabled requires snapshot.enabled=true")
	}
	if rc.Keep <= 0 {
		return errors.New("snapshot.retention.keep must be > 0 (set 0 disables; use enabled=false to skip the loop)")
	}
	interval := rc.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	retentionCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	srw.retentionCancel = cancel
	srw.retentionDone = done
	go serverbuildstore.RunSnapshotRetention(retentionCtx, done, srw.storage, interval, rc.Keep, b.logger, b.metricsRegistry)
	b.logger.Info("snapshot: retention scheduler enabled",
		"keep", rc.Keep, "interval", interval)
	return nil
}

// registerService self-registers this replica in the service registry. The
// address/tags/TTL defaults mirror the original inline resolution.
func (b *appBuilder) registerService(cw *clusterWiring) error {
	cfg := b.cfg
	addr := strings.TrimSpace(cfg.Registry.ServiceAddress)
	if addr == "" {
		addr = cfg.Server.Listen
		if addr == "" || addr[0] == ':' {
			addr = "127.0.0.1" + addr
		}
	}
	tags := cfg.Registry.ServiceTags
	if len(tags) == 0 {
		tags = []string{"sso"}
	}
	// ServiceTTL only matters under etcd (lease lifetime + KeepAlive cadence).
	// Memory ignores it; the registration's lifetime IS the process lifetime.
	// Default to 30s so dead etcd-backed replicas fall off the discovery list
	// within one TTL window.
	ttl := cfg.Registry.ServiceTTL
	if cw.regKind == "etcd" && ttl <= 0 {
		ttl = 30 * time.Second
	}
	if err := cw.reg.Register(context.Background(), &registry.Service{
		ID:      serverbuildplatform.ResolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer),
		Name:    "sso",
		Address: addr,
		Tags:    tags,
		TTL:     ttl,
	}); err != nil {
		return fmt.Errorf("registry register: %w", err)
	}
	return nil
}
