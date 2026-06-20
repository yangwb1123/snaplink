package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverassets"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/registry"
	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/signingkeys"
)

// rotatableIssuer is the scheduled-rotation seam cmd needs from the signing
// issuer. All four built-in algs satisfy it; a custom WithTokenIssuer that
// only implements manual RotateKey/RetireKey will not, and degrades gracefully.
type rotatableIssuer interface {
	StartRotation(context.Context, defaultimpl.RotationConfig) <-chan struct{}
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

	// Service registry built before NewServer so its etcd Ping can participate
	// in /readyz alongside the SQLite peers. Self-registration happens later
	// (needs cfg.Server.Listen resolved).
	reg, regKind, err := buildRegistry(&cfg.Registry, logger)
	if err != nil {
		return nil, fmt.Errorf("service registry: %w", err)
	}
	cw.reg = reg
	cw.regKind = regKind
	if regKind == "etcd" {
		b.opts = appendReadyCheck(b.opts, "etcd-registry", reg)
	}

	// Cross-replica invalidation bus built before NewServer so the option is in
	// place; the subscriber is started just after (needs the Server).
	invalidationBus, _, err := buildInvalidationBus(&cfg.Cluster.Bus, logger)
	if err != nil {
		return nil, fmt.Errorf("invalidation bus: %w", err)
	}
	cw.invalidationBus = invalidationBus
	b.wireInvalidationBusOpts(invalidationBus)

	// Shared signing-key registry (opt-in leaderless multi-replica JWKS
	// aggregation). Built before NewServer so the option is in place; the
	// publish/subscribe loop starts just after (needs the Server).
	signingKeyRegistry, _, err := buildSigningKeyRegistry(&cfg.Keys.SigningKeyRegistry, logger)
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

// wireInvalidationBusOpts wires the bus Option + the coordinated-rotation and
// cross-replica-revocation riders gated on a live bus, warning when those
// features are armed but no bus is wired (they would be inert).
func (b *appBuilder) wireInvalidationBusOpts(invalidationBus cluster.Bus) {
	cfg, logger := b.cfg, b.logger
	if invalidationBus == nil {
		if cfg.Keys.Rotation.CoordinatedCutover {
			logger.Error("keys.rotation.coordinated_cutover set but no cluster.bus wired — coordinated cutover is INERT")
		}
		if cfg.Cluster.CrossReplicaRevocation {
			logger.Error("cluster.cross_replica_revocation set but no cluster.bus wired — cross-replica revocation is INERT")
		}
		return
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
		replicaID = resolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer)
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
	logger.Info("signing key aggregation enabled", "replica_id", replicaID)
}

// wireFinalOptions mounts storage-health, the admin console SPA, hosted login +
// portal SPAs, the consent store, the native-SSO device-secret store, and the
// protected-resource metadata — the last Options before NewServer.
func (b *appBuilder) wireFinalOptions() error {
	cfg, logger := b.cfg, b.logger
	// Mount the per-store storage-health admin report from the sources gathered
	// alongside the /readyz checks. Empty (all-memory backends) ⇒ WithStorageHealth
	// doesn't mount the route — byte-identical to a build without it.
	if len(b.storageHealthSources) > 0 {
		b.opts = append(b.opts, sso.WithStorageHealth(b.storageHealthSources...))
		logger.Info("storage-health report enabled", "stores", len(b.storageHealthSources))
	}

	// Serve the hosted admin console SPA at /admin/. The filesystem is embedded
	// in the binary at compile time via go:embed in admin_assets.go.
	b.opts = append(b.opts, sso.WithAdminConsoleFS(serverassets.AdminSubFS()))

	// Serve the hosted-login SPA at /login/ when opted in via config.
	if cfg.HostedLogin.Enabled {
		b.opts = append(b.opts, sso.WithHostedLoginFS(serverassets.LoginSubFS()))
		logger.Info("hosted login UI enabled", "path", "/login/")
		// The end-user self-service portal SPA pairs with the hosted login UI:
		// once a user signs in they manage sessions/consents/password/MFA at
		// /portal/ against the same /me* endpoints. Gated by the same flag.
		b.opts = append(b.opts, sso.WithSelfServicePortalFS(serverassets.PortalSubFS()))
		logger.Info("self-service portal UI enabled", "path", "/portal/")
	}

	return b.wireConsentNativeSSOPRM()
}

// wireConsentNativeSSOPRM wires the self-service consent store, the Native SSO
// device-secret store, and RFC 9728 protected-resource metadata.
func (b *appBuilder) wireConsentNativeSSOPRM() error {
	cfg, logger := b.cfg, b.logger
	// Self-service consent store. Opt-in: enabling it turns ON the consent gate
	// at /auth/login and mounts /consents/me.
	consentStore, err := buildConsentStore(cfg.SelfService.Consent)
	if err != nil {
		return fmt.Errorf("self_service consent store: %w", err)
	}
	if consentStore != nil {
		b.opts = append(b.opts, sso.WithConsentStore(consentStore))
		logger.Info("self-service consent enabled", "backend", cfg.SelfService.Consent.Backend)
	}

	// OpenID Connect Native SSO 1.0 device_secret store. Opt-in.
	deviceSecretStore, err := buildDeviceSecretStore(cfg.NativeSSO)
	if err != nil {
		return fmt.Errorf("native_sso device secret store: %w", err)
	}
	if deviceSecretStore != nil {
		b.opts = append(b.opts, sso.WithDeviceSecretStore(deviceSecretStore, cfg.NativeSSO.TTL))
		logger.Info("native sso enabled", "backend", cfg.NativeSSO.Backend)
	}

	// RFC 9728 OAuth 2.0 Protected Resource Metadata (opt-in).
	if prm := cfg.ProtectedResource; prm.Enabled {
		b.opts = append(b.opts, sso.WithProtectedResourceMetadata(sso.ProtectedResourceMetadata{
			Resource:              prm.Resource,
			AuthorizationServers:  prm.AuthorizationServers,
			ResourceName:          prm.ResourceName,
			ResourceDocumentation: prm.ResourceDocumentation,
		}))
		logger.Info("protected resource metadata enabled", "path", "/.well-known/oauth-protected-resource")
	}
	return nil
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
	rc, ok := signingKeyRotationConfig(cfg.Keys.Rotation)
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
func (b *appBuilder) wireSnapshotReleases() (*snapshotReleaseWiring, error) {
	cfg, logger := b.cfg, b.logger
	srw := &snapshotReleaseWiring{}

	pipeline, snapStorage, err := buildSnapshotSubsystem(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("snapshot subsystem: %w", err)
	}
	srw.pipeline = pipeline
	srw.storage = snapStorage
	if pipeline != nil {
		b.buildSnapshotterRestorer(srw)
	}

	releaseRegistry, releaseStore, err := buildReleaseSubsystem(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("release subsystem: %w", err)
	}
	srw.releaseRegistry = releaseRegistry
	srw.releaseStore = releaseStore
	if err := b.startSnapshotRetention(srw); err != nil {
		return nil, err
	}

	// Wire ConfigSnapshot-aware Rollback when both subsystems are enabled and
	// the operator opted in. Done here (after both factories) so the Registry
	// receives a fully-formed adapter with the runtime restorer/pipeline in
	// scope.
	if releaseRegistry != nil && pipeline != nil && cfg.Releases.SnapshotIntegration {
		releaseRegistry.SnapshotRestorer = &snapshotRestorerAdapter{
			pipeline: pipeline,
			storage:  snapStorage,
			restorer: srw.restorer,
		}
		logger.Info("release rollback wired with snapshot restore")
	}
	return srw, nil
}

// buildSnapshotterRestorer constructs the Snapshotter + Restorer over the live
// stores (called only when the snapshot pipeline is enabled).
func (b *appBuilder) buildSnapshotterRestorer(srw *snapshotReleaseWiring) {
	srw.snapshotter = &snapshot.Snapshotter{
		Clients:     b.clientStore,
		Users:       b.userProvider,
		Permissions: b.provider,
		NetPolicy:   b.netStore,
		Namespace:   bootstrapNamespace,
	}
	// Opt-in defense-in-depth: when set, EVERY export strips client credentials
	// so a plaintext export is safe to share/inspect. NOT a restore path —
	// encryption stays the route for restorable backups.
	if b.cfg.Snapshot.RedactSecrets {
		srw.snapshotter.DefaultExportRedactor = snapshot.SnapshotRedactSecrets()
	}
	srw.restorer = &snapshot.Restorer{
		Clients:     b.clientStore,
		Users:       b.userProvider,
		Permissions: b.provider,
		NetPolicy:   b.netStore,
		Namespace:   bootstrapNamespace,
	}
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
	go runSnapshotRetention(retentionCtx, done, srw.storage, interval, rc.Keep, b.logger, b.metricsRegistry)
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
		ID:      resolveServiceID(cfg.Registry.ServiceID, cfg.Server.Issuer),
		Name:    "sso",
		Address: addr,
		Tags:    tags,
		TTL:     ttl,
	}); err != nil {
		return fmt.Errorf("registry register: %w", err)
	}
	return nil
}
