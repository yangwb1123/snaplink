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
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/permissions"
	permsqlite "github.com/yangwb1123/snaplink/domains/permissions/sqlite"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/protocols/caep"
)

// wireIdentitySigning constructs metrics, the seeded client store, the user
// provider + session manager, the signing issuer, and the base Option set.
func (b *appBuilder) wireIdentitySigning() error {
	cfg := b.cfg
	if cfg.Metrics.Enabled {
		b.metricsRegistry = metrics.New()
	}

	clientStore, err := serverbuildstore.BuildClientStore(cfg.Identity, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("identity client_store: %w", err)
	}
	if err := b.seedClients(clientStore); err != nil {
		return err
	}
	b.clientStore = clientStore

	userProvider, err := serverbuildstore.BuildUserProvider(cfg.Identity, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("identity user_provider: %w", err)
	}
	sessionMgr, err := serverbuildstore.BuildSessionManager(cfg.Identity, cfg.Server.SessionTTL, b.redis, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("identity session_manager: %w", err)
	}
	b.userProvider = userProvider
	b.sessionMgr = sessionMgr
	// Schema-version boot gate: refuse to start when any SQLite store's
	// live schema is ahead of what this binary knows. A memory backend
	// silently no-ops (no DB() method). This must run before traffic is
	// accepted so an operator doing a canary rollback sees a clear error
	// instead of silent data corruption. The check is SQLite-dialect-specific
	// (it probes sqlite_master), so skip it for postgres-backed stores — their
	// own migrate runs at construction; a postgres canary gate is a follow-up.
	b.schemaCtx = context.Background()
	identityIsPG := strings.EqualFold(strings.TrimSpace(cfg.Identity.Backend), "postgres")
	if !identityIsPG {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, clientStore, "clients", sqlitestores.ClientsMaxVersion()); err != nil {
			return fmt.Errorf("schema check clients: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, userProvider, "users", sqlitestores.UsersMaxVersion()); err != nil {
			return fmt.Errorf("schema check users: %w", err)
		}
	}
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, sessionMgr, "sessions", sqlitestores.SessionsMaxVersion()); err != nil {
		return fmt.Errorf("schema check sessions: %w", err)
	}
	return b.wireSigningIssuer()
}

// seedClients loads the configured clients into the freshly-built store,
// validating each CAEP receiver endpoint at boot.
func (b *appBuilder) seedClients(clientStore sso.ClientStore) error {
	for _, c := range b.cfg.Clients {
		seeded := &sso.Client{
			ID:                               c.ID,
			Secret:                           c.Secret,
			Name:                             c.Name,
			RedirectURIs:                     c.RedirectURIs,
			AllowedScopes:                    c.AllowedScopes,
			AllowedAuthenticators:            c.AllowedAuthenticators,
			LoginPageURI:                     c.LoginPageURI,
			TokenStrategy:                    c.TokenStrategy,
			Active:                           c.Active,
			TenantID:                         c.TenantID,
			RequirePKCE:                      c.RequirePKCE,
			AllowedResources:                 c.AllowedResources,
			PostLogoutRedirectURIs:           c.PostLogoutRedirectURIs,
			AllowedAuthorizationDetailsTypes: c.AllowedAuthorizationDetailsTypes,
			RefreshTokenTTL:                  c.RefreshTokenTTL,
			AccessTokenTTL:                   c.AccessTokenTTL,
			AllowedPKCEMethods:               c.AllowedPKCEMethods,
			RequireSignedRequestObject:       c.RequireSignedRequestObject,
			RequirePAR:                       c.RequirePAR,
			AllowPasswordlessOnly:            c.AllowPasswordlessOnly,
			AllowedRequestURIs:               c.AllowedRequestURIs,
			DeviceCodeTTL:                    c.DeviceCodeTTL,
			DeviceCodePollInterval:           c.DeviceCodePollInterval,
			UserinfoSignedResponseAlg:        c.UserinfoSignedResponseAlg,
			IDTokenSignedResponseAlg:         c.IDTokenSignedResponseAlg,
			BackchannelLogoutURI:             c.BackchannelLogoutURI,
			SubjectType:                      c.SubjectType,
			SectorIdentifierURI:              c.SectorIdentifierURI,
			FrontchannelLogoutURI:            c.FrontchannelLogoutURI,
			JWKS:                             serverbuildstore.ConvertClientJWKs(c.JWKS),
			Attributes:                       c.Attributes,
			SkipConsent:                      c.SkipConsent,
			ConsentRefreshInterval:           c.ConsentRefreshInterval,
		}
		// Validate the CAEP receiver endpoint (https) at boot; plaintext would
		// exfiltrate revocation SETs (same anti-exfil rule as the admin gRPC path).
		if ep := c.Attributes[caep.AttrReceiverEndpoint]; ep != "" {
			if err := caep.ValidateReceiverEndpoint(ep); err != nil {
				return fmt.Errorf("client %q caep_receiver_endpoint: %w", c.ID, err)
			}
		}
		if err := clientStore.Add(context.Background(), seeded); err != nil && !errors.Is(err, sso.ErrClientExists) {
			return fmt.Errorf("seed client %q: %w", c.ID, err)
		}
	}
	return nil
}

// wireSigningIssuer builds the signing issuer + base Option set (router,
// logger, tracing, token issuers, OIDC id-token issuer, supported algs) and
// registers the identity-store readiness checks + storage-health sources.
func (b *appBuilder) wireSigningIssuer() error {
	cfg, logger := b.cfg, b.logger
	// Signing issuer: EdDSA (default) / ES256 / RS256|PS256, optionally
	// backed by an external KMS/HSM signer. Both concrete types satisfy
	// the same interface set; only the scheduled rotation loop below is
	// EdDSA-specific (type-asserted there).
	jwtIssuer, signingAlg, externalSigner, err := serverbuildsign.BuildSigningIssuer(cfg.Keys.Signing, cfg.Server, b.redis, b.metricsRegistry, logger)
	if err != nil {
		return err
	}
	sessionIssuer := defaultimpl.NewSessionTokenIssuer(
		defaultimpl.WithSessionTokenTTL(cfg.Server.SessionTTL),
	)
	b.jwtIssuer = jwtIssuer
	b.signingAlg = signingAlg
	b.externalSigner = externalSigner
	b.tokenIssuers = map[string]sso.TokenIssuer{
		sso.TokenStrategyJWT:     jwtIssuer,
		sso.TokenStrategySession: sessionIssuer,
	}

	b.opts = append(cfg.ServerOptions(),
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithLogger(logger),
		sso.WithTracing("sso-server"), // single correlation switch: span tree + X-Trace-Id/X-Request-Id + audit trace_id; no-op until tracing.Init activates
		sso.WithTokenIssuer(sso.TokenStrategyJWT, jwtIssuer),
		sso.WithTokenIssuer(sso.TokenStrategySession, sessionIssuer),
		sso.WithUserProvider(b.userProvider),
		sso.WithClientStore(b.clientStore),
		sso.WithSessionManager(b.sessionMgr),
		// Ed25519JWTIssuer satisfies oidc.IDTokenIssuer — sharing one
		// signing key keeps JWKS single-entry. Without this option the
		// id_token field is omitted from every /token + /auth/login
		// response and OIDC is silently disabled, which is the wrong
		// default for a binary called "sso-server".
		sso.WithIDTokenIssuer(jwtIssuer),
		// Pin the Server-level Validate alg gate to the wired signing
		// alg so an RP can never select the verification algorithm
		// (anti alg-confusion); discovery also reflects this set.
		sso.WithSupportedSigningAlgs(signingAlg),
	)
	// Additional per-client id_token signing keys (keys.id_token_algs).
	if b.opts, err = serverbuildsign.BuildIDTokenAlgOptions(b.opts, cfg, b.redis, b.metricsRegistry, logger); err != nil {
		return err
	}
	logger.Info("signing issuer configured", "alg", signingAlg)
	b.registerIdentityHealth()
	return nil
}

// wireAudit builds the audit recorder + sink stack (primary, webhook fan-out,
// async wrap), the retention scheduler, and the audit API + readiness wiring.
func (b *appBuilder) wireAudit() error {
	cfg, logger := b.cfg, b.logger
	if !cfg.Audit.Enabled {
		return nil
	}
	primary, primaryName, err := serverbuildauthn.BuildPrimaryAuditSink(cfg.Audit, logger, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("audit: build primary sink: %w", err)
	}
	if err := b.checkAuditSchema(primary); err != nil {
		return err
	}
	if err := b.startAuditRetention(primary, primaryName); err != nil {
		return err
	}
	sink, err := b.composeAuditSinks(primary)
	if err != nil {
		return err
	}
	recorder, err := b.buildRecorder(sink)
	if err != nil {
		return err
	}
	b.recorder = recorder
	b.opts = append(b.opts, sso.WithAuditRecorder(recorder))
	if cfg.Audit.APIEnabled {
		b.opts = append(b.opts, sso.WithAuditAPI())
	}
	// Register a readycheck for the primary sink if it satisfies
	// the Ping interface — the SQLite sink does; MemorySink
	// silently no-ops.
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "audit-"+primaryName, primary)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "audit-"+primaryName, primary)
	return nil
}

// composeAuditSinks layers the optional fan-outs and the async wrap around
// the primary sink, in the fixed order webhook -> SIEM -> kafka -> async so
// the buffered hot path always sits outermost.
func (b *appBuilder) composeAuditSinks(primary audit.Sink) (audit.Sink, error) {
	cfg := b.cfg
	sink := primary
	var err error
	if w := cfg.Audit.Webhook; w.Enabled {
		if sink, err = b.wireAuditWebhook(primary, w); err != nil {
			return nil, err
		}
	}
	if sink, err = b.wireAuditSIEM(sink); err != nil {
		return nil, err
	}
	if sink, err = b.wireAuditKafka(sink); err != nil {
		return nil, err
	}
	// Async wrap when configured. The buffered hot path keeps slow
	// (e.g. webhook) sinks from blocking request latency. Memory
	// sink benefits little — the wrap is opt-in per operator.
	if cfg.Audit.Async.Enabled {
		if sink, err = b.wireAuditAsync(sink); err != nil {
			return nil, err
		}
	}
	return sink, nil
}

// checkAuditSchema refuses to start when the SQLite audit sink's live
// schema is ahead of what this binary knows; postgres's migrate already ran
// at construction so it is skipped.
func (b *appBuilder) checkAuditSchema(primary audit.Sink) error {
	if strings.EqualFold(strings.TrimSpace(b.cfg.Audit.Backend), "postgres") {
		return nil
	}
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, primary, "audit", auditsqlite.AuditMaxVersion()); err != nil {
		return fmt.Errorf("schema check audit: %w", err)
	}
	return nil
}

// wireAuditSIEM fans sink out to every enabled CEF/OCSF/syslog formatter —
// three independent config blocks, so any subset may be active
// simultaneously. Formatter sinks are local/stdout/file targets (no
// RetryingSink): network delivery of these same formatters is
// wireAuditKafka below.
func (b *appBuilder) wireAuditSIEM(sink audit.Sink) (audit.Sink, error) {
	siemSinks, err := serverbuildauthn.BuildAuditSIEMSinks(b.cfg.Audit, b.logger)
	if err != nil {
		return nil, fmt.Errorf("audit: build siem sinks: %w", err)
	}
	if len(siemSinks) == 0 {
		return sink, nil
	}
	return audit.NewMultiSink(append([]audit.Sink{sink}, siemSinks...)...), nil
}

// wireAuditKafka fans sink out to the configured Kafka topic when
// audit.kafka.enabled. Unlike the CEF/OCSF/syslog formatter sinks (a
// local/stdout/file target), this is a network delivery — wrapped in
// RetryingSink to mask transient broker hiccups, the same posture as
// wireAuditWebhook. The RAW (unwrapped) sink is retained on b.auditKafkaSink
// so shutdownSubsystems can Close it (flush + disconnect the producer) at
// graceful shutdown; RetryingSink does not forward Close.
func (b *appBuilder) wireAuditKafka(sink audit.Sink) (audit.Sink, error) {
	kafkaSink, err := serverbuildauthn.BuildAuditKafkaSink(b.cfg.Audit.Kafka, b.logger)
	if err != nil {
		return nil, fmt.Errorf("audit: build kafka sink: %w", err)
	}
	if kafkaSink == nil {
		return sink, nil
	}
	b.auditKafkaSink = kafkaSink
	return audit.NewMultiSink(sink, audit.NewRetryingSink(kafkaSink)), nil
}

// startAuditRetention boots the retention prune loop against the SQLite primary
// sink. The in-memory ring buffer self-prunes by capacity; cmd type-asserts the
// concrete *auditsqlite.Sink so the memory path silently skips, letting an
// operator flip retention.enabled without coordinating with the backend choice.
func (b *appBuilder) startAuditRetention(primary audit.Sink, primaryName string) error {
	rc := b.cfg.Audit.Retention
	if !rc.Enabled || primaryName != "sqlite" {
		return nil
	}
	sqliteSink, ok := primary.(*auditsqlite.Sink)
	if !ok {
		return errors.New("audit.retention.enabled requires audit.backend=sqlite (assert failed — internal bug)")
	}
	if rc.MaxAge <= 0 {
		return errors.New("audit.retention.max_age required when retention.enabled")
	}
	interval := rc.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	retentionCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.auditRetentionCancel = cancel
	b.auditRetentionDone = done
	go serverbuildstore.RunAuditRetention(retentionCtx, done, sqliteSink, interval, rc.MaxAge, b.logger, b.metricsRegistry)
	b.logger.Info("audit: retention scheduler enabled",
		"max_age", rc.MaxAge, "interval", interval)
	return nil
}

// wireAuditWebhook fans the primary sink out to every configured webhook
// subscription. Compose order: MultiSink(Primary, sub1, sub2, ...) where each
// sub is RetryingSink(FilteringSink(WebhookSink)) — so in-process /audit query
// reads still see every event while each subscription receives only its
// selected event types. The legacy scalar url stays supported (implicit
// unfiltered "default" subscription); per-subscription compilation lives in
// serverbuildauthn to keep this a thin wire step.
func (b *appBuilder) wireAuditWebhook(primary audit.Sink, w config.AuditWebhookConfig) (audit.Sink, error) {
	subSinks, err := serverbuildauthn.BuildAuditWebhookSinks(w, b.logger)
	if err != nil {
		return nil, err
	}
	return audit.NewMultiSink(append([]audit.Sink{primary}, subSinks...)...), nil
}

// wireAuditAsync wraps the sink in a buffered AsyncSink and starts it.
// batch_size selects per-event vs batch draining; the builder validates the
// knob against the composed sink, so a dead combination fails boot here.
func (b *appBuilder) wireAuditAsync(sink audit.Sink) (audit.Sink, error) {
	async, err := serverbuildauthn.BuildAuditAsyncSink(b.cfg.Audit.Async, sink, b.logger)
	if err != nil {
		return nil, err
	}
	b.asyncSink = async
	async.Start()
	return async, nil
}

// buildRecorder assembles the audit Recorder with PII redaction + hash chain
// options as configured.
func (b *appBuilder) buildRecorder(sink audit.Sink) (*audit.Recorder, error) {
	logger := b.logger
	recorderOpts := []audit.Option{
		audit.WithErrorHandler(func(err error) { logger.Error("audit sink", "error", err) }),
	}
	if pii := b.cfg.Audit.PIIRedaction; pii.Enabled {
		salt, err := serverbuildstore.ResolvePIISalt(pii)
		if err != nil {
			return nil, fmt.Errorf("audit pii_redaction salt: %w", err)
		}
		recorderOpts = append(recorderOpts, audit.WithRedactor(audit.DefaultPIIRedactor(salt)))
		logger.Info("audit: pii redaction enabled (actor hashed, ip truncated, user-agent stripped)")
	}
	if b.cfg.Audit.HashChain {
		recorderOpts = append(recorderOpts, audit.WithHashChain())
		logger.Info("audit: hash chain enabled — Events carry PrevHash + Hash for tamper-evidence")
	}
	return audit.New(sink, recorderOpts...), nil
}

// wirePermissions builds + wires the permissions provider, minting a memory
// provider when admin needs one for scope checks but none is configured.
func (b *appBuilder) wirePermissions() error {
	cfg, logger := b.cfg, b.logger
	provider, err := serverbuildplatform.BuildPermissionsProvider(cfg, logger, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("permissions: %w", err)
	}
	if provider != nil {
		// Schema-version boot gate: refuse to start when the SQLite
		// permissions store's live schema is ahead of what this binary
		// knows. Skip for postgres (its migrate ran at construction).
		if !strings.EqualFold(strings.TrimSpace(cfg.Permissions.Backend), "postgres") {
			if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, provider, "permissions", permsqlite.PermissionsMaxVersion()); err != nil {
				return fmt.Errorf("schema check permissions: %w", err)
			}
		}
		b.opts = append(b.opts, sso.WithPermissionProvider(provider))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-permissions", provider)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-permissions", provider)
		if cfg.Permissions.EmbedInLogin {
			b.opts = append(b.opts, sso.WithEmbedPermissionsInLogin())
		}
	}
	// Admin needs a non-nil permission provider for scope checks. Mint a
	// memory provider so first-boot bootstrap can seed into something.
	if cfg.Admin.Enabled && provider == nil {
		mp := permissions.NewMemoryProvider()
		provider = mp
		b.opts = append(b.opts, sso.WithPermissionProvider(provider))
	}
	b.provider = provider
	return nil
}

// wireNetwork builds the network-policy store + classifier, starts the
// self-healing Watch loop, and wires the policy + API + readiness options.
// The caller (buildApp) owns the on-failure netCancel cleanup defer since a
// defer here would fire at method return, not at buildApp's scope.
func (b *appBuilder) wireNetwork() error {
	cfg, logger := b.cfg, b.logger
	netStore, netStoreKind, err := serverbuildstore.BuildNetworkStore(&cfg.Network, logger)
	if err != nil {
		return fmt.Errorf("network policy store: %w", err)
	}
	b.netStore = netStore
	if netStore == nil {
		return nil
	}
	classifier := netpolicy.NewClassifier(
		netpolicy.WithClassifierMetrics(b.metricsRegistry),
		netpolicy.WithClassifierLogger(logger),
	)
	b.classifier = classifier
	// Cancellable run ctx so shutdown stops the self-healing Watch loop
	// cleanly (it exits on ctx cancel). Without it the loop would treat the
	// shutdown store-Close as a Watch failure and flip degraded on the way
	// out, emitting a spurious degraded signal + reconnect churn.
	netCtx, netCancel := context.WithCancel(context.Background())
	b.netCancel = netCancel
	done, err := classifier.Start(netCtx, netStore)
	if err != nil {
		netCancel()
		_ = netStore.Close()
		return fmt.Errorf("network classifier: %w", err)
	}
	b.netStop = done
	b.opts = append(b.opts, sso.WithNetworkPolicy(netStore, classifier))
	if cfg.Network.APIEnabled {
		b.opts = append(b.opts, sso.WithNetworkPolicyAPI())
	}
	if netStoreKind == "etcd" {
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "etcd-netpolicy", netStore)
		// The Classifier's self-healing Watch loop flips degraded when the
		// etcd watch closes under a live context (compaction/leader change):
		// it keeps serving its frozen snapshot but stops applying policy
		// edits. Surface that on /readyz so a stuck-stale replica is visible
		// (Ready ignores ctx — it reads an atomic flag, no I/O).
		cls := classifier
		b.opts = append(b.opts, sso.WithReadyCheck("netpolicy-classifier", func(context.Context) error { return cls.Ready() }))
	}
	return nil
}

// assembleExtras sets the *app fields left out of assemble()'s (build_app.go)
// composite literal to keep that function within the function-length
// budget — pure field mapping, no behavior.
func (b *appBuilder) assembleExtras(a *app, rt serverRuntime) {
	a.auditKafkaSink, a.consentStore, a.mfaEnrollStore = b.auditKafkaSink, b.consentStore, b.mfaEnrollStore
	a.passwordResetRevoker = b.passwordResetRevoker
	a.pushPruneCancel, a.pushPruneDone = b.pushPruneCancel, b.pushPruneDone
	a.cibaPruneCancel, a.cibaPruneDone = b.cibaPruneCancel, b.cibaPruneDone
	a.netStop, a.netCancel = b.netStop, b.netCancel
	a.drReadiness, a.drReplicationCancel, a.drReplicationDone = drFields(rt.dr)
	a.configAuditStore = b.configAuditStore
	a.credentialSchedCancel, a.credentialSchedDone = b.credentialSchedCancel, b.credentialSchedDone
	a.configDriftCancel, a.configDriftDone = b.configDriftCancel, b.configDriftDone
	a.breakGlassCancel, a.breakGlassDone = b.breakGlassCancel, b.breakGlassDone
	a.continuousVerifyCancel, a.continuousVerifyDone = b.continuousVerifyCancel, b.continuousVerifyDone
	a.capConvergenceCancel, a.capConvergenceDone = b.capConvergenceCancel, b.capConvergenceDone
	a.tokenUsageRecorder = b.tokenUsageRecorder
	a.tokenAnomalySweepCancel, a.tokenAnomalySweepDone = b.tokenAnomalySweepCancel, b.tokenAnomalySweepDone
	a.degradationMgr = b.degradationMgr
	a.autoReadOnlyCancel, a.autoReadOnlyDone = b.autoReadOnlyCancel, b.autoReadOnlyDone
	a.userAutoDeprovisionCancel, a.userAutoDeprovisionDone = b.userAutoDeprovisionCancel, b.userAutoDeprovisionDone
	a.clientSecretScanCancel, a.clientSecretScanDone = b.clientSecretScanCancel, b.clientSecretScanDone
	if b.tenantQuotaRuntime != nil {
		a.tenantQuotaStop = b.tenantQuotaRuntime.Stop
	}
}
