package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/federation"
	federationhealth "github.com/yangwb1123/snaplink/domains/federation/health"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/protocols/oidc/bcl"
)

// wireResponseEncryption wires the OIDC JWE response encrypter per the
// configured backend (rsa / ecdh / multi).
func (b *appBuilder) wireResponseEncryption() error {
	re := b.cfg.OIDC.ResponseEncryption
	if !re.Enabled {
		return nil
	}
	backend := strings.ToLower(strings.TrimSpace(re.Backend))
	if backend == "" {
		backend = "rsa"
	}
	switch backend {
	case "rsa":
		b.opts = append(b.opts, sso.WithJWEResponseEncrypter(defaultimpl.NewRSAJWEResponseEncrypter()))
		b.logger.Info("oidc response encryption: enabled (RSA-OAEP-256 + A256GCM); per-client via id_token/userinfo_encrypted_response_alg")
	case "ecdh":
		b.opts = append(b.opts, sso.WithJWEResponseEncrypter(defaultimpl.NewECDHJWEResponseEncrypter()))
		b.logger.Info("oidc response encryption: enabled (ECDH-ES[+A256KW] + A256GCM); per-client via id_token/userinfo_encrypted_response_alg")
	case "multi":
		b.opts = append(b.opts, sso.WithJWEResponseEncrypter(defaultimpl.NewMultiJWEResponseEncrypter(
			defaultimpl.NewRSAJWEResponseEncrypter(),
			defaultimpl.NewECDHJWEResponseEncrypter(),
		)))
		b.logger.Info("oidc response encryption: enabled (RSA-OAEP-256 + ECDH-ES, A256GCM); routed per-client by registered key type")
	default:
		return fmt.Errorf("oidc.response_encryption.backend %q unsupported (supported: rsa, ecdh, multi)", backend)
	}
	return nil
}

// wireSessionManagement wires OpenID Connect Session Management 1.0 when
// oidc.session_management.enabled is set — see sso.WithOIDCSessionManagement.
func (b *appBuilder) wireSessionManagement() {
	if !b.cfg.OIDC.SessionManagement.Enabled {
		return
	}
	b.opts = append(b.opts, sso.WithOIDCSessionManagement())
	b.logger.Info("oidc session management: enabled — /auth/login stamps session_state, GET /check_session_iframe mounted, discovery advertises check_session_iframe")
}

// wireDCRBackchannel wires dynamic client registration and backchannel logout.
func (b *appBuilder) wireDCRBackchannel() error {
	cfg, logger := b.cfg, b.logger
	if cr := cfg.ClientRegistration; cr.Enabled {
		b.opts = append(b.opts, sso.WithDynamicClientRegistration(oauth.DCRPolicy{
			InitialAccessToken:             cr.InitialAccessToken,
			AllowOpenRegistration:          cr.AllowOpenRegistration,
			DefaultActive:                  cr.DefaultActive,
			DefaultTokenStrategy:           cr.DefaultTokenStrategy,
			AllowedAuthenticators:          cr.AllowedAuthenticators,
			RotateRegistrationAccessToken:  cr.RotateAccessToken,
			RegistrationAccessTokenOverlap: cr.RotateAccessTokenOverlap,
		}))
		if cr.AllowOpenRegistration && cr.InitialAccessToken == "" {
			logger.Info("client_registration: OPEN — no initial_access_token; production deployments SHOULD restrict")
		}
	}
	if cfg.BackchannelLogout.Enabled {
		if err := b.wireBackchannelLogout(); err != nil {
			return err
		}
	}
	return nil
}

func (b *appBuilder) wireBackchannelLogout() error {
	cfg := b.cfg.BackchannelLogout
	idx, indexMode, err := serverbuildauthn.BuildSubjectClientIndex(cfg.Index, b.redis)
	if err != nil {
		return fmt.Errorf("subject_client_index: %w", err)
	}
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, idx, "subject_client_index", sqlitestores.SubjectClientIndexMaxVersion()); err != nil {
		return fmt.Errorf("schema check subject_client_index: %w", err)
	}
	queue, queueMode, err := serverbuildauthn.BuildBackchannelFailureStore(cfg.FailureQueue, b.redis)
	if err != nil {
		return fmt.Errorf("backchannel failure queue: %w", err)
	}
	notifier := sso.LogoutNotifier(sso.NewHTTPLogoutNotifier())
	if queue != nil {
		notifier = bcl.NewManager(b.jwtIssuer, notifier, queue,
			bcl.WithRetryInterval(cfg.FailureQueue.RetryInterval), bcl.WithBatchSize(cfg.FailureQueue.BatchSize),
			bcl.WithLeaseDuration(cfg.FailureQueue.LeaseDuration), bcl.WithLogger(b.logger), bcl.WithAuditor(b.recorder),
			bcl.WithDelivered(func(ctx context.Context, f bcl.Failure) error { return idx.Forget(ctx, f.Subject, f.ClientID) }))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "redis-bcl-failure-queue", queue)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "redis-bcl-failure-queue", queue)
	}
	b.opts = append(b.opts, sso.WithBackchannelLogout(b.jwtIssuer, notifier), sso.WithSubjectClientIndex(idx))
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-bcl-subject-client-index", idx)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-bcl-subject-client-index", idx)
	if cfg.MaxConcurrent > 0 {
		b.opts = append(b.opts, sso.WithBackchannelLogoutMaxConcurrent(cfg.MaxConcurrent))
	}
	b.logger.Info("backchannel logout: enabled", "subject_client_index", indexMode, "failure_queue", queueMode)
	return nil
}

// wireCAEPTransmitter wires the OpenID Shared Signals (CAEP/RISC) transmitter.
func (b *appBuilder) wireCAEPTransmitter() {
	cfg, logger := b.cfg, b.logger
	if !cfg.CAEP.Enabled {
		return
	}
	// OpenID Shared Signals (CAEP/RISC) transmitter: real-time cross-RP
	// revocation. Reuses the same signing issuer (SET via its generic SignJWT
	// path) + the ClientStore (receivers resolved fresh per event) + the audit
	// pipeline. Best-effort, fail-open, opt-in.
	caepOpts := []caep.Option{
		caep.WithIssuer(cfg.Server.Issuer),
		caep.WithLogger(logger),
		caep.WithFailureRecorder(b.recorder),
	}
	if b.metricsRegistry != nil {
		caepOpts = append(caepOpts, caep.WithMetric(func(outcome string) {
			b.metricsRegistry.CAEPSetsTotal.WithLabelValues(outcome).Inc()
		}))
	}
	if d := cfg.CAEP.ReceiverTimeout; d > 0 {
		caepOpts = append(caepOpts, caep.WithReceiverTimeout(d))
	}
	if d := cfg.CAEP.SETTTL; d > 0 {
		caepOpts = append(caepOpts, caep.WithSETTTL(d))
	}
	if n := cfg.CAEP.DeliveryRetryMaxAttempts; n > 1 {
		caepOpts = append(caepOpts, caep.WithDeliveryRetry(n))
	}
	if cfg.CAEP.DeliveryRetryInitialBackoff > 0 || cfg.CAEP.DeliveryRetryMaxBackoff > 0 {
		caepOpts = append(caepOpts, caep.WithDeliveryRetryBackoff(cfg.CAEP.DeliveryRetryInitialBackoff, cfg.CAEP.DeliveryRetryMaxBackoff))
	}
	caepTx := caep.NewTransmitter(b.jwtIssuer, b.clientStore, caepOpts...)
	b.opts = append(b.opts, sso.WithCAEPTransmitter(caepTx))
	logger.Info("caep: OpenID Shared Signals transmitter enabled — signed SETs pushed to affected clients' registered receivers on revocation/suspension/family-reuse events")
}

// wireSSEEvents wires the realtime admin event stream (GET
// /api/v1/admin/events/stream). Default-off: skipping this leaves b.opts
// untouched, so a build without events.enabled is byte-identical. The
// broker is retrievable back off the built Server (Server.SSEBroker) so
// shutdown can Close it without appBuilder/app retaining a second reference.
func (b *appBuilder) wireSSEEvents() {
	ec := b.cfg.Events
	if !ec.Enabled {
		return
	}
	broker := sse.NewBroker(sse.Options{
		SubscriberBuffer: ec.SubscriberBuffer,
		ReplayBuffer:     ec.ReplayBuffer,
		MaxSubscribers:   ec.MaxSubscribers,
	})
	b.opts = append(b.opts, sso.WithSSEBroker(broker))
	if ec.HeartbeatInterval > 0 {
		b.opts = append(b.opts, sso.WithSSEHeartbeat(ec.HeartbeatInterval))
	}
	if !b.cfg.Audit.Enabled {
		// Fail-open, not fail-loud: the broker is still a valid mount (an SDK
		// consumer could publish to it directly), it just has no source until
		// audit is also enabled.
		b.logger.Info("events.enabled but audit.enabled is false — the event stream route is mounted but will never emit (no audit recorder to tap)")
	}
	b.logger.Info("events: realtime admin event stream enabled",
		"max_subscribers", ec.MaxSubscribers, "replay_buffer", ec.ReplayBuffer)
}

// wireWebhookEngine wires the generic event/webhook egress engine
// (platform/lifecycle/webhook): a MultiSink sibling to the primary audit sink that
// fans matching events out to runtime-registered EventSubscriptions
// (managed via the admin API, not YAML — see WebhooksConfig). Default-off:
// skipping this leaves b.opts untouched, so a build without
// webhooks.enabled is byte-identical. Subscriptions and dead-letters are
// process-local (MemorySubscriptionStore / MemoryDeadLetterStore); a
// restart loses them, matching MemorySink's discipline for the primary
// audit ring buffer.
func (b *appBuilder) wireWebhookEngine() error {
	wc := b.cfg.Webhooks
	if !wc.Enabled {
		return b.wireExternalAuditWorker()
	}
	runtime, err := serverbuildauthn.BuildManagedWebhookRuntime(wc, b.recorder, b.logger)
	if err != nil {
		return err
	}
	b.opts = append(b.opts,
		sso.WithWebhookEngine(runtime.CurrentEngine()),
		sso.WithWebhookRuntime(runtime),
		sso.WithReadyCheck("webhook-exporter", runtime.Ready),
	)
	b.logger.Info("webhooks: generic event/webhook egress engine enabled — manage subscriptions via POST /api/v1/admin/webhooks/subscriptions")
	return b.wireExternalAuditWorker()
}

func (b *appBuilder) wireExternalAuditWorker() error {
	cfg := b.cfg.Audit.ExternalWorker
	if !cfg.Enabled {
		return nil
	}
	runtime, err := serverbuildauthn.BuildExternalAuditRuntime(cfg, b.recorder, b.logger)
	if err != nil {
		return fmt.Errorf("audit.external_worker: %w", err)
	}
	b.recorder.AddSink(runtime)
	b.opts = append(b.opts, sso.WithReadyCheck("external-audit-worker", runtime.Ready))
	b.externalAuditClose = runtime.Close
	return nil
}

func (b *appBuilder) closeBuildFailure() {
	if b.netCancel != nil {
		b.netCancel()
	}
	if b.externalAuditClose != nil {
		_ = b.externalAuditClose(context.Background())
	}
}

// wireFederation wires OpenID Federation 1.0 entity config, trust-chain
// resolution, the §8 fetch endpoint, and auto-registration.
func (b *appBuilder) wireFederation() error {
	cfg, logger := b.cfg, b.logger
	if !cfg.Federation.Enabled {
		return nil
	}
	fedCfg, err := serverbuildplatform.BuildFederationConfig(cfg.Federation)
	if err != nil {
		return fmt.Errorf("federation: %w", err)
	}
	resolverOpts := b.wireFederationConnectionHealth(cfg.Federation.ConnectionHealth)
	b.opts = append(b.opts, sso.WithFederationEntity(fedCfg, b.jwtIssuer, resolverOpts...))
	logger.Info("federation: OpenID Federation 1.0 entity configuration enabled — self-signed Entity Statement served at /.well-known/openid-federation",
		"authority_hints", len(fedCfg.AuthorityHints),
		"trust_anchors", len(fedCfg.TrustAnchors),
		"subordinates", len(fedCfg.Subordinates),
	)
	if len(fedCfg.Subordinates) > 0 {
		// §8 SUPERIOR / INTERMEDIATE role: this server issues SIGNED Subordinate
		// Statements about its configured subordinates so a resolver can climb
		// THROUGH it. The /fetch route is mounted + the entity config advertises
		// federation_fetch_endpoint (gated on subordinates).
		logger.Info("federation: §8 Federation Fetch endpoint enabled — this server acts as a federation SUPERIOR/INTERMEDIATE, issuing signed Subordinate Statements about configured subordinates at /fetch (iss=this server, sub=looked-up subordinate, jwks=operator-configured vouched keys)",
			"subordinates", len(fedCfg.Subordinates),
		)
	}
	if len(fedCfg.TrustAnchors) > 0 {
		// Slice 2: the trust-chain resolver is now LIVE (anchors loaded). It
		// resolves + validates a remote entity's chain up to a configured anchor.
		logger.Info("federation: trust-chain resolution enabled — remote entities validated up to a configured trust anchor",
			"trust_anchors", len(fedCfg.TrustAnchors),
			"max_chain_depth", fedCfg.MaxTrustChainDepth,
		)
	}
	if cfg.Federation.AutoRegister {
		// Slice 3: automatic client registration. A validated federation RP
		// becomes a usable OAuth client with no manual registration. REQUIRES
		// trust anchors (no root of trust ⇒ nothing to admit anyone), so fail
		// loud rather than silently no-op.
		if len(fedCfg.TrustAnchors) == 0 {
			return fmt.Errorf("federation: auto_register requires at least one trust_anchor (no root of trust to admit a federation client)")
		}
		b.opts = append(b.opts, sso.WithFederationAutoRegistration())
		logger.Info("federation: AUTOMATIC client registration enabled — a validated federation RP becomes a usable OAuth client with no manual registration (chain-vouched keys, no shared secret; policy-constrained metadata)",
			"trust_anchors", len(fedCfg.TrustAnchors),
		)
	}
	return nil
}

// wireFederationConnectionHealth opts into the federation metadata-health
// lifecycle (PURE OBSERVABILITY — see config.FederationHealthConfig): when
// enabled, it builds a MemoryConnectionHealth store, wraps the SAME hardened
// default fetcher (federation.NewDefaultFetcher) with a recording decorator,
// wires the store into the SDK (mounting the admin listing), and returns the
// WithTrustChainFetcher option so the trust-chain resolver's fetches flow
// through the SAME wrapped fetcher the admin listing reads from. Disabled
// (default) ⇒ returns nil, so WithFederationEntity gets no extra resolver
// options and behavior is byte-identical to a build without this package.
func (b *appBuilder) wireFederationConnectionHealth(cfg config.FederationHealthConfig) []federation.TrustChainResolverOption {
	if !cfg.Enabled {
		return nil
	}
	store := federationhealth.NewMemoryConnectionHealth()
	observed := federationhealth.NewObservingFetcher(federation.NewDefaultFetcher(), store)
	b.opts = append(b.opts, sso.WithFederationConnectionHealth(store, cfg.CertExpiryWarning))
	b.logger.Info("federation: connection-health tracking enabled — GET /api/v1/admin/federation/health lists per-peer fetch health + TLS certificate expiry",
		"cert_expiry_warning", cfg.CertExpiryWarning,
	)
	return []federation.TrustChainResolverOption{federation.WithTrustChainFetcher(observed)}
}

// wireProfilesAndMetadata wires OAuth2.1 strict mode, the FAPI compliance
// profile, pairwise subjects, supported ACR values, operator metadata, and
// the signed-metadata signer.
func (b *appBuilder) wireProfilesAndMetadata() error {
	cfg, logger := b.cfg, b.logger
	if cfg.Server.OAuth21StrictMode {
		b.opts = append(b.opts, sso.WithOAuth21StrictMode(true))
		logger.Info("oauth2.1 strict mode: implicit grant disabled, S256-only PKCE, PKCE required for every login")
	}
	if prof := strings.ToLower(strings.TrimSpace(cfg.OAuth.Compliance.Profile)); prof != "" {
		switch prof {
		case "fapi_2", "fapi2", "fapi-2":
			mode := sso.FAPIModeEnforce
			if cfg.OAuth.Compliance.InspectionOnly {
				mode = sso.FAPIModeInspection
			}
			b.opts = append(b.opts, sso.WithFAPIProfile(mode))
			logger.Info("oauth compliance profile: fapi_2", "mode", mode.String(),
				"note", "PAR/JAR/DPoP-or-mTLS must be wired for clients to pass enforcement")
		default:
			return fmt.Errorf("oauth.compliance.profile %q unsupported (supported: fapi_2)", prof)
		}
	}
	if cfg.Server.PairwiseSubjects.Enabled {
		if err := b.wirePairwiseSubjects(); err != nil {
			return err
		}
	}
	if len(cfg.Server.SupportedACRValues) > 0 {
		b.opts = append(b.opts, sso.WithSupportedACRValues(cfg.Server.SupportedACRValues...))
	}
	if om := cfg.Server.OperatorMetadata; om.PolicyURI != "" || om.TosURI != "" || om.ServiceDocumentation != "" {
		b.opts = append(b.opts, sso.WithOperatorMetadata(om.PolicyURI, om.TosURI, om.ServiceDocumentation))
	}
	if cfg.Server.SignedMetadata {
		// jwtIssuer satisfies oidc.MetadataSigner — reuse the same signing key as
		// access + id + userinfo so JWKS continues to cover everything with one
		// entry.
		if signer, ok := any(b.jwtIssuer).(oidc.MetadataSigner); ok {
			b.opts = append(b.opts, sso.WithMetadataSigner(signer))
		} else {
			logger.Info("signed_metadata enabled but the configured JWT issuer does not implement oidc.MetadataSigner — discovery doc will not be signed")
		}
	}
	return nil
}

// wireAPIVersioning wires ADR-0008's opt-in HTTP API versioning mechanism:
// Accept-Version request-header negotiation, Sunset/Deprecation response
// headers (whole-API and/or per-route), and the v2alpha proof-of-mechanism
// route. Every sub-mechanism's own zero value keeps it off — a deployment
// that never sets server.api_versioning: behaves byte-identically to today.
func (b *appBuilder) wireAPIVersioning() {
	av := b.cfg.Server.APIVersioning
	if len(av.SupportedVersions) > 0 {
		b.opts = append(b.opts, sso.WithAPIVersioning(av.SupportedVersions...))
		b.logger.Info("api_versioning: Accept-Version negotiation enabled", "supported", av.SupportedVersions)
	}
	if dep := av.Deprecation; !dep.Since.IsZero() || !dep.Sunset.IsZero() || dep.Link != "" {
		b.opts = append(b.opts, sso.WithAPIDeprecation(middleware.DeprecationPolicy{
			Since: dep.Since, Sunset: dep.Sunset, Link: dep.Link,
		}))
		b.logger.Info("api_versioning: whole-API Deprecation/Sunset headers enabled")
	}
	for path, dep := range av.RouteDeprecations {
		b.opts = append(b.opts, sso.WithRouteDeprecation(path, middleware.DeprecationPolicy{
			Since: dep.Since, Sunset: dep.Sunset, Link: dep.Link,
		}))
	}
	if len(av.RouteDeprecations) > 0 {
		b.logger.Info("api_versioning: per-route Deprecation/Sunset headers enabled", "routes", len(av.RouteDeprecations))
	}
	if av.V2AlphaPreview {
		b.opts = append(b.opts, sso.WithAPIVersionPreview())
		b.logger.Info("api_versioning: v2alpha proof-of-mechanism route enabled at GET /api/v2alpha/version")
	}
}

// wirePairwiseSubjects wires the OIDC pairwise subject store + salt.
func (b *appBuilder) wirePairwiseSubjects() error {
	cfg := b.cfg
	salt, err := serverbuildstore.ResolvePairwiseSalt(cfg.Server.PairwiseSubjects)
	if err != nil {
		return fmt.Errorf("pairwise_subjects salt: %w", err)
	}
	store, mode, err := serverbuildauthn.BuildPairwiseSubjectStore(cfg.Server.PairwiseSubjects, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("pairwise_subjects store: %w", err)
	}
	// SQLite-dialect schema gate; skip for postgres (its migrate ran at
	// construction — a postgres canary gate is a follow-up).
	if !strings.EqualFold(strings.TrimSpace(cfg.Server.PairwiseSubjects.Backend), "postgres") {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "pairwise", sqlitestores.PairwiseMaxVersion()); err != nil {
			return fmt.Errorf("schema check pairwise: %w", err)
		}
	}
	b.opts = append(b.opts,
		sso.WithPairwiseSubjectStore(store),
		sso.WithPairwiseSalt(salt),
	)
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-pairwise-subjects", store)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-pairwise-subjects", store)
	b.logger.Info("oidc pairwise subjects: enabled", "store", mode)
	return nil
}

// wireMetricsCollector attaches the AsyncSinkCollector + WithMetrics option.
// metricsRegistry was constructed at the top of buildApp so retention
// schedulers could emit during their loops; here we wire it into the server.
func (b *appBuilder) wireMetricsCollector() {
	cfg, logger := b.cfg, b.logger
	if !cfg.Metrics.Enabled {
		return
	}
	if b.asyncSink != nil {
		b.metricsRegistry.Registry.MustRegister(metrics.NewAsyncSinkCollector(b.asyncSink))
	}
	b.opts = append(b.opts, sso.WithMetrics(b.metricsRegistry))
	logger.Info("metrics: prometheus /metrics enabled")
	// Opt-in per-tenant login/issue metrics. Cardinality-gated by the operator
	// allowlist (§5): empty = OFF (vectors never registered).
	if len(cfg.Metrics.TenantLabelAllowlist) > 0 {
		b.opts = append(b.opts, sso.WithTenantMetricsAllowlist(cfg.Metrics.TenantLabelAllowlist))
		logger.Info("metrics: per-tenant breakdown enabled", "tenants", len(cfg.Metrics.TenantLabelAllowlist))
	}
}

// wireJARM wires JWT-secured authorization response mode (response_mode=jwt).
func (b *appBuilder) wireJARM() error {
	cfg := b.cfg
	if !cfg.OAuth.JARM.Enabled {
		return nil
	}
	js, ok := any(b.jwtIssuer).(oidc.JARMSigner)
	if !ok {
		return fmt.Errorf("oauth.jarm.enabled but the %s signing issuer does not implement JARM signing", b.signingAlg)
	}
	b.opts = append(b.opts, sso.WithJARM(js))
	b.logger.Info("jarm: enabled (response_mode=jwt)", "signing_alg", b.signingAlg)
	return nil
}

// wireIntrospection wires the /token/introspect response-caching, signed-JWT
// response (reusing the primary signing issuer), and batch tuning knobs.
func (b *appBuilder) wireIntrospection() error {
	cfg := b.cfg.OAuth.Introspection
	if cfg.CacheTTL > 0 {
		b.opts = append(b.opts, sso.WithIntrospectionCache(handler.NewMemoryIntrospectionCache(), cfg.CacheTTL))
		b.logger.Info("introspection response cache enabled", "ttl", cfg.CacheTTL)
	}
	if cfg.SignedResponseEnabled {
		is, ok := any(b.jwtIssuer).(oauth.IntrospectionSigner)
		if !ok {
			return fmt.Errorf("oauth.introspection.signed_response_enabled but the %s signing issuer does not implement introspection signing", b.signingAlg)
		}
		b.opts = append(b.opts, sso.WithIntrospectionSigner(is))
		b.logger.Info("introspection: signed JWT responses enabled (opt-in via Accept header)", "signing_alg", b.signingAlg)
	}
	if cfg.BatchEnabled {
		b.opts = append(b.opts, sso.WithIntrospectionBatch(cfg.MaxBatchSize))
		b.logger.Info("introspection: batch requests enabled", "max_batch_size", cfg.MaxBatchSize)
	}
	return nil
}

// wireIntrospectionSigning wires RFC 9701 JWT-formatted /token/introspect
// responses with the optional dedicated signing issuer.
func (b *appBuilder) wireIntrospectionSigning() error {
	cfg := b.cfg.Keys.IntrospectionSigning
	if !cfg.Enabled {
		return nil
	}
	issuer, alg, extSigner, err := serverbuildsign.BuildSigningIssuer(cfg.SigningConfig, b.cfg.Server, b.redis, b.metricsRegistry, b.logger)
	if err != nil {
		return fmt.Errorf("keys.introspection_signing: %w", err)
	}
	signer, ok := any(issuer).(oauth.IntrospectionSigner)
	if !ok {
		return fmt.Errorf("keys.introspection_signing.alg %q does not implement introspection-response signing", alg)
	}
	b.opts = append(b.opts, sso.WithIntrospectionSigning(signer))
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "introspection-external-signer", extSigner)
	b.logger.Info("introspection signing: enabled (RFC 9701 JWT introspection responses)", "signing_alg", alg)
	return nil
}
