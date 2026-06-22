package main

import (
	"fmt"
	"strings"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
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

// wireDCRBackchannel wires dynamic client registration and backchannel logout.
func (b *appBuilder) wireDCRBackchannel() error {
	cfg, logger := b.cfg, b.logger
	if cr := cfg.ClientRegistration; cr.Enabled {
		b.opts = append(b.opts, sso.WithDynamicClientRegistration(oauth.DCRPolicy{
			InitialAccessToken:            cr.InitialAccessToken,
			AllowOpenRegistration:         cr.AllowOpenRegistration,
			DefaultActive:                 cr.DefaultActive,
			DefaultTokenStrategy:          cr.DefaultTokenStrategy,
			AllowedAuthenticators:         cr.AllowedAuthenticators,
			RotateRegistrationAccessToken: cr.RotateAccessToken,
		}))
		if cr.AllowOpenRegistration && cr.InitialAccessToken == "" {
			logger.Info("client_registration: OPEN — no initial_access_token; production deployments SHOULD restrict")
		}
	}
	if cfg.BackchannelLogout.Enabled {
		idx, mode, err := serverbuildauthn.BuildSubjectClientIndex(cfg.BackchannelLogout.Index)
		if err != nil {
			return fmt.Errorf("subject_client_index: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, idx, "subject_client_index", sqlitestores.SubjectClientIndexMaxVersion()); err != nil {
			return fmt.Errorf("schema check subject_client_index: %w", err)
		}
		b.opts = append(b.opts,
			sso.WithBackchannelLogout(b.jwtIssuer, sso.NewHTTPLogoutNotifier()),
			sso.WithSubjectClientIndex(idx),
		)
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-bcl-subject-client-index", idx)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-bcl-subject-client-index", idx)
		if n := cfg.BackchannelLogout.MaxConcurrent; n > 0 {
			b.opts = append(b.opts, sso.WithBackchannelLogoutMaxConcurrent(n))
		}
		logger.Info("backchannel logout: enabled", "subject_client_index", mode)
	}
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
	caepTx := caep.NewTransmitter(b.jwtIssuer, b.clientStore, caepOpts...)
	b.opts = append(b.opts, sso.WithCAEPTransmitter(caepTx))
	logger.Info("caep: OpenID Shared Signals transmitter enabled — signed SETs pushed to affected clients' registered receivers on revocation/suspension/family-reuse events")
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
	b.opts = append(b.opts, sso.WithFederationEntity(fedCfg, b.jwtIssuer))
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
