package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	connectionssqlite "github.com/snaplink/sso/domains/connections/sqlite"
	tenantsqlite "github.com/snaplink/sso/domains/tenant/sqlite"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	redisbackend "github.com/snaplink/sso/infrastructure/redis"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
)

// wireTenant builds the tenant store, its middleware/suspension options, the
// per-tenant token-strategy bindings, and the usage-metering aggregator.
func (b *appBuilder) wireTenant() error {
	cfg, logger := b.cfg, b.logger
	tenantStore, err := serverbuildstore.BuildTenantStore(cfg, logger, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("tenant store: %w", err)
	}
	b.tenantStore = tenantStore
	if tenantStore == nil {
		return nil
	}
	// Schema-version boot gate: refuse to start when the SQLite tenant
	// store's live schema is ahead of what this binary knows. Skip for
	// postgres (its migrate ran at construction — a postgres canary gate
	// is a follow-up).
	if !strings.EqualFold(strings.TrimSpace(cfg.Tenant.Backend), "postgres") {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, tenantStore, "tenant", tenantsqlite.TenantMaxVersion()); err != nil {
			return fmt.Errorf("schema check tenant: %w", err)
		}
	}
	b.opts = append(b.opts, sso.WithTenantStore(tenantStore))
	// SQLite-backed tenant store implements Ping → /readyz. Memory-backed
	// silently no-ops (Ping isn't on the interface; serverbuildsign.AppendReadyCheck only
	// registers when the concrete type satisfies it).
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-tenant", tenantStore)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-tenant", tenantStore)
	if cfg.Tenant.LookupTimeout > 0 || cfg.Tenant.IncludeSuspended {
		b.opts = append(b.opts, sso.WithTenantMiddlewareOptions(sso.TenantMiddlewareOptions{
			Timeout:          cfg.Tenant.LookupTimeout,
			IncludeSuspended: cfg.Tenant.IncludeSuspended,
		}))
	}
	if cfg.Tenant.SuspensionCheck.Enabled {
		b.opts = append(b.opts, sso.WithTenantSuspensionCheck(cfg.Tenant.SuspensionCheck.CacheTTL))
	}
	if err := b.wireTenantTokenStrategies(); err != nil {
		return err
	}
	// Per-tenant usage metering report (sso.WithTenantUsageAggregator →
	// GET /api/v1/admin/tenants/:id/usage). Reads the audit_events table.
	agg, err := serverbuildstore.BuildTenantUsageAggregator(cfg.Tenant.UsageMetering)
	if err != nil {
		return fmt.Errorf("tenant usage metering: %w", err)
	}
	if agg != nil {
		b.opts = append(b.opts, sso.WithTenantUsageAggregator(agg))
		logger.Info("tenant usage metering enabled", "backend", cfg.Tenant.UsageMetering.Backend)
	}
	return nil
}

// wireTenantTokenStrategies binds per-tenant token strategies. A seed tenant may
// pin a registered strategy ("jwt"|"session") so its tokens differ from the
// server default; an unregistered name would break login for that tenant at
// runtime, so fail loud at boot instead.
func (b *appBuilder) wireTenantTokenStrategies() error {
	for _, tn := range b.cfg.Tenant.Tenants {
		if tn.TokenStrategy == "" {
			continue
		}
		if tn.TokenStrategy != sso.TokenStrategyJWT && tn.TokenStrategy != sso.TokenStrategySession {
			return fmt.Errorf("tenant %q token_strategy %q is not a registered strategy (want %q or %q)",
				tn.ID, tn.TokenStrategy, sso.TokenStrategyJWT, sso.TokenStrategySession)
		}
		b.opts = append(b.opts, sso.WithTenantTokenIssuer(tn.ID, tn.TokenStrategy))
		b.logger.Info("tenant token strategy bound", "tenant", tn.ID, "strategy", tn.TokenStrategy)
	}
	return nil
}

// wireConnectionsAndCache wires B2B connections + home-realm discovery and the
// opt-in client-store / discovery / JWKS caches.
func (b *appBuilder) wireConnectionsAndCache() error {
	cfg := b.cfg
	// B2B enterprise connections + home-realm discovery (sso.WithConnectionStore
	// → /auth/home-realm). Seeded from config; nil when disabled so the endpoint
	// is not mounted (byte-identical).
	connectionStore, err := serverbuildstore.BuildConnectionStore(cfg, b.logger)
	if err != nil {
		return fmt.Errorf("connection store: %w", err)
	}
	b.connectionStore = connectionStore
	if connectionStore != nil {
		// Schema-version boot gate: refuse to start when the SQLite
		// connection store's live schema is ahead of what this binary
		// knows. Memory backend silently no-ops (no DB() method).
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, connectionStore, "connections", connectionssqlite.ConnectionsMaxVersion()); err != nil {
			return fmt.Errorf("schema check connections: %w", err)
		}
		b.opts = append(b.opts, sso.WithConnectionStore(connectionStore))
		// SQLite-backed connections store implements Ping → /readyz; memory
		// silently no-ops (serverbuildsign.AppendReadyCheck only registers satisfying types).
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-connections", connectionStore)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-connections", connectionStore)
	}
	// Opt-in per-login ClientStore metadata cache (identity.client_cache).
	// TTL 0 falls back to sso.DefaultClientStoreCacheTTL inside the SDK.
	// ValidateSecret bypasses it (§2); admin/DCR mutations evict via the
	// InvalidateClientCache bus wiring above.
	if cfg.Identity.ClientCache.Enabled {
		b.opts = append(b.opts, sso.WithClientStoreCache(cfg.Identity.ClientCache.TTL))
	}
	if cfg.Server.DiscoveryDocCacheTTL != 0 {
		// Negative TTL also passes through — the SDK treats <= 0 as
		// "disable body cache" so operators can flip caching off
		// from config without removing the field entirely.
		b.opts = append(b.opts, sso.WithDiscoveryDocCacheTTL(cfg.Server.DiscoveryDocCacheTTL))
	}
	if cfg.Server.DiscoveryCacheTTL != 0 {
		b.opts = append(b.opts, sso.WithDiscoveryCacheTTL(cfg.Server.DiscoveryCacheTTL))
	}
	if cfg.Server.JWKSCacheTTL != 0 {
		b.opts = append(b.opts, sso.WithJWKSCacheTTL(cfg.Server.JWKSCacheTTL))
	}
	return nil
}

// wireDPoP wires the DPoP nonce provider + proof iat-window tunables.
func (b *appBuilder) wireDPoP() error {
	cfg := b.cfg
	if cfg.Security.DPoPNonce.Enabled {
		provider, err := serverbuildstore.BuildDPoPNonceProvider(cfg.Security.DPoPNonce, b.logger)
		if err != nil {
			return fmt.Errorf("dpop nonce provider: %w", err)
		}
		b.opts = append(b.opts, sso.WithDPoPNonceProvider(provider))
	}
	// DPoP proof iat-window tunables. Both default to 60s in the SDK when
	// the option is not wired, so a zero value here is byte-identical to
	// the previous hardcoded behavior — we only append when set.
	if cfg.DPoP.ProofMaxAge > 0 {
		b.opts = append(b.opts, sso.WithDPoPProofMaxAge(cfg.DPoP.ProofMaxAge))
	}
	if cfg.DPoP.MaxClockSkew > 0 {
		b.opts = append(b.opts, sso.WithDPoPMaxClockSkew(cfg.DPoP.MaxClockSkew))
	}
	return nil
}

// wireOAuthGrantStores wires the auth-code, refresh-token, account-erase,
// device-code, PAR, JAR, CIBA, and JARM grant subsystems in order.
func (b *appBuilder) wireOAuthGrantStores() error {
	cfg := b.cfg
	if cfg.OAuth.AuthCode.Enabled {
		store, err := serverbuildstore.BuildAuthCodeStore(cfg.OAuth, b.redis)
		if err != nil {
			return fmt.Errorf("oauth.auth_code: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "auth_codes", sqlitestores.AuthCodesMaxVersion()); err != nil {
			return fmt.Errorf("schema check auth_codes: %w", err)
		}
		b.opts = append(b.opts, sso.WithAuthCodeStore(store, cfg.OAuth.AuthCode.TTL))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-oauth-auth-codes", store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-oauth-auth-codes", store)
	}
	if err := b.wireRefreshToken(); err != nil {
		return err
	}
	// GDPR Art. 17 self-service account erasure (/me/account/erase). Wired with
	// a complete eraser (incl. refresh-token revocation via the subject index
	// when the store supports it) so a self-deletion also cuts off tokens.
	// Opt-in + irreversible.
	if cfg.SelfService.AccountDeletion && b.userProvider != nil {
		var refreshIdx oauth.RefreshTokenSubjectIndex
		if idx, ok := b.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
			refreshIdx = idx
		}
		// Consent + MFAEnrollments are late-bound in finalize (their stores wire
		// after this runs); retain the eraser pointer so that binding lands.
		b.accountEraser = newSelfServiceEraser(b.userProvider, b.sessionMgr, refreshIdx, b.clientStore)
		b.opts = append(b.opts, sso.WithSelfServiceAccountErasure(b.accountEraser))
		b.logger.Info("self-service account erasure enabled (/me/account/erase)")
	}
	if err := b.wireDeviceCodePAR(); err != nil {
		return err
	}
	if jar := cfg.OAuth.JAR; jar.Enabled {
		f := security.NewHTTPJARFetcher()
		if jar.Timeout > 0 {
			f.Client.Timeout = jar.Timeout
		}
		if jar.MaxBytes > 0 {
			f.MaxBytes = jar.MaxBytes
		}
		b.opts = append(b.opts, sso.WithJARFetcher(f))
	}
	if err := b.wireCIBA(); err != nil {
		return err
	}
	return b.wireResponseSigners()
}

// wireResponseSigners wires the opt-in JARM (authorization response) and
// RFC 9701 (introspection response) JWT signers, in order. Split out of
// wireOAuthGrantStores to keep that function under the function-length
// budget (AGENTS.md §0.1) as the grant-store list grows.
func (b *appBuilder) wireResponseSigners() error {
	if err := b.wireJARM(); err != nil {
		return err
	}
	return b.wireIntrospectionSigning()
}

// wireRefreshToken wires the refresh-token store + the opt-in rotation-grace
// window, recording the store + TTL for downstream consumers.
func (b *appBuilder) wireRefreshToken() error {
	cfg := b.cfg
	if !cfg.OAuth.RefreshToken.Enabled {
		return nil
	}
	store, err := serverbuildstore.BuildRefreshTokenStore(cfg.OAuth, b.redis)
	if err != nil {
		return fmt.Errorf("oauth.refresh_token: %w", err)
	}
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "refresh_tokens", sqlitestores.RefreshTokensMaxVersion()); err != nil {
		return fmt.Errorf("schema check refresh_tokens: %w", err)
	}
	b.opts = append(b.opts, sso.WithRefreshTokenStore(store, cfg.OAuth.RefreshToken.TTL))
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-oauth-refresh-tokens", store)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-oauth-refresh-tokens", store)
	b.refreshTokenStore = store
	b.refreshTokenTTL = cfg.OAuth.RefreshToken.TTL
	return b.wireRefreshRotationGrace()
}

// wireRefreshRotationGrace opts into the refresh-rotation grace window for
// multi-replica resilience. Extracted from wireRefreshToken for function-length
// budget. 0 = strict single-use (no-op). Supports memory, sqlite, and redis.
func (b *appBuilder) wireRefreshRotationGrace() error {
	cfg := b.cfg
	if w := cfg.OAuth.RefreshToken.RotationGraceWindow; w > 0 {
		switch strings.ToLower(strings.TrimSpace(cfg.OAuth.RefreshToken.RotationGraceBackend)) {
		case "", "memory":
			b.opts = append(b.opts, sso.WithRefreshRotationGrace(w))
			b.logger.Info("refresh rotation grace enabled (memory; single-replica only)", "window", w)
		case "redis":
			if b.redis == nil {
				return errors.New("oauth.refresh_token.rotation_grace_backend=redis but no redis block configured (set redis.addrs)")
			}
			b.opts = append(b.opts, sso.WithRefreshRotationGraceStore(redisbackend.NewRefreshGraceStore(b.redis, w)))
			b.logger.Info("refresh rotation grace enabled (redis; cluster-shared)", "window", w)
		case "sqlite":
			if cfg.OAuth.SQLite.DSN == "" {
				return errors.New("oauth.refresh_token.rotation_grace_backend=sqlite but no oauth.sqlite.dsn set")
			}
			store, err := sqlitestores.NewRefreshGraceStoreWithDSN(cfg.OAuth.SQLite.DSN, w, 0)
			if err != nil {
				return fmt.Errorf("refresh rotation grace store: %w", err)
			}
			b.opts = append(b.opts, sso.WithRefreshRotationGraceStore(store))
			b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-refresh-grace", store)
			b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-refresh-grace", store)
			b.refreshGracePruneCancel = store.CleanupStop()
			b.refreshGracePruneDone = store.CleanupDone()
			b.logger.Info("refresh rotation grace enabled (sqlite; cluster-shared)", "window", w, "dsn", cfg.OAuth.SQLite.DSN)
		default:
			return fmt.Errorf("unknown oauth.refresh_token.rotation_grace_backend %q (supported: memory, sqlite, redis)", cfg.OAuth.RefreshToken.RotationGraceBackend)
		}
	}
	return nil
}

// wireDeviceCodePAR wires the device-code and PAR grant stores.
func (b *appBuilder) wireDeviceCodePAR() error {
	cfg := b.cfg
	if cfg.OAuth.DeviceCode.Enabled {
		store, err := serverbuildstore.BuildDeviceCodeStore(cfg.OAuth, b.redis)
		if err != nil {
			return fmt.Errorf("oauth.device_code: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "device_codes", sqlitestores.DeviceCodesMaxVersion()); err != nil {
			return fmt.Errorf("schema check device_codes: %w", err)
		}
		b.opts = append(b.opts, sso.WithDeviceCodeStore(
			store,
			cfg.OAuth.DeviceCode.TTL,
			cfg.OAuth.DeviceCode.PollInterval,
			cfg.OAuth.DeviceCode.VerificationBaseURL,
		))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-oauth-device-codes", store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-oauth-device-codes", store)
	}
	if cfg.OAuth.PAR.Enabled {
		store, err := serverbuildstore.BuildPARStore(cfg.OAuth, b.redis)
		if err != nil {
			return fmt.Errorf("par store: %w", err)
		}
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "par", sqlitestores.PARMaxVersion()); err != nil {
			return fmt.Errorf("schema check par: %w", err)
		}
		b.opts = append(b.opts, sso.WithPARStore(store, cfg.OAuth.PAR.TTL))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-oauth-par", store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-oauth-par", store)
	}
	return nil
}

// wireCIBA wires the CIBA poll/ping subsystem + the optional SQLite prune loop.
func (b *appBuilder) wireCIBA() error {
	cfg, logger := b.cfg, b.logger
	if !cfg.CIBA.Enabled {
		return nil
	}
	store, transport, sqliteStore, err := serverbuildstore.BuildCIBA(cfg.CIBA, logger, b.redis)
	if err != nil {
		return fmt.Errorf("ciba: %w", err)
	}
	b.opts = append(b.opts, sso.WithCIBA(store, transport, cfg.CIBA.RequestTTL, cfg.CIBA.Interval))
	if sqliteStore != nil {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, sqliteStore, "ciba_requests", sqlitestores.CIBARequestsMaxVersion()); err != nil {
			return fmt.Errorf("schema check ciba_requests: %w", err)
		}
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-ciba", sqliteStore)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-ciba", sqliteStore)
		if pi := cfg.CIBA.PruneInterval; pi > 0 {
			pruneCtx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			b.cibaPruneCancel = cancel
			b.cibaPruneDone = done
			go serverbuildstore.RunCIBAPrune(pruneCtx, done, sqliteStore, pi, logger, b.metricsRegistry)
			logger.Info("ciba: prune scheduler enabled", "interval", pi)
		}
	}
	mode := "poll"
	if cfg.CIBA.Ping.Enabled {
		b.opts = append(b.opts, sso.WithCIBAPingNotifier(newHTTPCIBAPingNotifier(cfg.CIBA.Ping, logger)))
		mode = "poll+ping"
	}
	logger.Info("ciba: enabled",
		"mode", mode,
		"backend", strings.ToLower(strings.TrimSpace(cfg.CIBA.Backend)),
		"transport", strings.ToLower(strings.TrimSpace(cfg.CIBA.Transport)))
	return nil
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

// wireIntrospectionSigning wires RFC 9701 JWT-formatted /token/introspect
// responses. Unlike wireJARM (which reuses b.jwtIssuer, the primary
// signing issuer), this builds a SEPARATE issuer from
// keys.introspection_signing — a distinct key with its own kid + rotation
// lifecycle — because a resource server trusting introspection JWTs must
// never be able to forge (or be forged by) a bearer access/ID token
// through key reuse (AGENTS.md: dedicated signer requirement).
func (b *appBuilder) wireIntrospectionSigning() error {
	cfg := b.cfg.Keys.IntrospectionSigning
	if !cfg.Enabled {
		return nil
	}
	issuer, alg, extSigner, err := serverbuildsign.BuildSigningIssuer(cfg.SigningConfig, b.cfg.Server, b.metricsRegistry, b.logger)
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
