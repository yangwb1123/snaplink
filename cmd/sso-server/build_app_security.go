package main

import (
	"fmt"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
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
