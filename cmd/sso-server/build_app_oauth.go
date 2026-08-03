package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	connectionssqlite "github.com/yangwb1123/snaplink/domains/connections/sqlite"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantsqlite "github.com/yangwb1123/snaplink/domains/tenant/sqlite"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/security"
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
	b.wireTenantStoreOptions(tenantStore)
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

// wireTenantStoreOptions wires the tenant store's readiness check, storage
// health source, resolution middleware options, and suspension check. Split
// out of wireTenant to stay under the function-length budget.
func (b *appBuilder) wireTenantStoreOptions(tenantStore tenant.Store) {
	cfg, logger := b.cfg, b.logger
	b.opts = append(b.opts, sso.WithTenantStore(tenantStore))
	// SQLite-backed tenant store implements Ping → /readyz. Memory-backed
	// silently no-ops (Ping isn't on the interface; serverbuildsign.AppendReadyCheck only
	// registers when the concrete type satisfies it).
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-tenant", tenantStore)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-tenant", tenantStore)
	// Always wired (not gated on LookupTimeout/IncludeSuspended being set) so
	// OnError reaches the operator's logger regardless of those other
	// knobs — a tenant-store outage during resolution is fail-open by
	// design (the request still continues with no tenant set), but should
	// never be silent to the operator. Timeout/IncludeSuspended keep their
	// exact prior zero-value defaults when the corresponding config field
	// is unset.
	b.opts = append(b.opts, sso.WithTenantMiddlewareOptions(sso.TenantMiddlewareOptions{
		Timeout:          cfg.Tenant.LookupTimeout,
		IncludeSuspended: cfg.Tenant.IncludeSuspended,
		OnError: func(err error) {
			logger.Error("tenant resolution failed", "error", err)
		},
	}))
	if cfg.Tenant.SuspensionCheck.Enabled {
		b.opts = append(b.opts, sso.WithTenantSuspensionCheck(cfg.Tenant.SuspensionCheck.CacheTTL))
	}
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
	if err := b.wireConnectionStore(); err != nil {
		return err
	}
	cfg := b.cfg
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

// wireConnectionStore wires B2B enterprise connections + home-realm discovery
// (sso.WithConnectionStore → /auth/home-realm) and the runtime
// connection→authenticator factory. Seeded from config; nil store when
// disabled so the endpoint is not mounted (byte-identical).
func (b *appBuilder) wireConnectionStore() error {
	cfg := b.cfg
	connectionStore, err := serverbuildstore.BuildConnectionStore(cfg, b.logger)
	if err != nil {
		return fmt.Errorf("connection store: %w", err)
	}
	b.connectionStore = connectionStore
	if connectionStore == nil {
		return nil
	}
	// Schema-version boot gate: refuse to start when the SQLite
	// connection store's live schema is ahead of what this binary
	// knows. Memory backend silently no-ops (no DB() method).
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, connectionStore, "connections", connectionssqlite.ConnectionsMaxVersion()); err != nil {
		return fmt.Errorf("schema check connections: %w", err)
	}
	b.opts = append(b.opts, sso.WithConnectionStore(connectionStore))
	// Runtime half of enterprise connections: /auth/login dispatched with
	// provider=<connection id> builds the upstream authenticator from the
	// connection's stored config (build failures land in the audit trail —
	// b.recorder is populated by wireFoundation before wireDomains runs).
	b.opts = append(b.opts, sso.WithConnectionAuthenticatorFactory(
		serverbuildauthn.NewConnectionAuthenticatorFactoryWithLinker(b.recorder, b.logger, 0, b.identityLinker)))
	if cfg.Connections.Probe.Timeout > 0 {
		b.opts = append(b.opts, sso.WithConnectionProbeTimeout(cfg.Connections.Probe.Timeout))
	}
	// SQLite-backed connections store implements Ping → /readyz; memory
	// silently no-ops (serverbuildsign.AppendReadyCheck only registers satisfying types).
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-connections", connectionStore)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-connections", connectionStore)
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

// oauthBackend resolves the effective OAuth hot-store backend ("" and
// "memory" are equivalent) for the schema-gate and ready-check-name branches.
func oauthBackend(cfg config.OAuthConfig) string {
	return strings.ToLower(strings.TrimSpace(cfg.Backend))
}

// checkOAuthStoreSchema runs the per-namespace schema boot gate for the OAuth
// hot stores, branched by backend: SQLite gates via
// serverbuildsign.CheckSQLiteSchema (type-probed DB() *sql.DB); postgres gates
// via postgresbackend.CheckSchema on the shared pool. Running the SQLite
// version-table query against a pgx pool would falsely fail boot (the
// sqlite_master probe errors on a postgres connection), so the branch is
// mandatory — follows the checkIdentityLinkSchema precedent. Memory/redis
// stores expose no DB() and silently no-op, byte-identical to today.
func (b *appBuilder) checkOAuthStoreSchema(backend, namespace string, store any, sqliteMax, pgMax int) error {
	switch backend {
	case "sqlite":
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, namespace, sqliteMax); err != nil {
			return fmt.Errorf("schema check %s: %w", namespace, err)
		}
	case "postgres":
		if err := postgresbackend.CheckSchema(b.schemaCtx, b.pgDB, namespace, pgMax); err != nil {
			return fmt.Errorf("schema check %s: %w", namespace, err)
		}
	}
	return nil
}

// oauthReadyCheckName produces the backend-accurate /readyz + storage-health
// name for an OAuth store (sqlite-oauth-* vs postgres-oauth-*), so operators
// can tell which dependency failed and the two backends never collide.
func oauthReadyCheckName(backend, suffix string) string {
	prefix := "sqlite"
	if backend == "postgres" {
		prefix = "postgres"
	}
	return prefix + "-oauth-" + suffix
}

// wireOAuthGrantStores wires the auth-code, refresh-token, account-erase,
// device-code, PAR, JAR, CIBA, and JARM grant subsystems in order.
func (b *appBuilder) wireOAuthGrantStores() error {
	cfg := b.cfg
	backend := oauthBackend(cfg.OAuth)
	if cfg.OAuth.AuthCode.Enabled {
		store, err := serverbuildstore.BuildAuthCodeStore(cfg.OAuth, b.redis, b.pgDB, b.pgDialect)
		if err != nil {
			return fmt.Errorf("oauth.auth_code: %w", err)
		}
		if err := b.checkOAuthStoreSchema(backend, "auth_codes", store,
			sqlitestores.AuthCodesMaxVersion(), postgresbackend.AuthCodesMaxVersion()); err != nil {
			return err
		}
		b.opts = append(b.opts, sso.WithAuthCodeStore(store, cfg.OAuth.AuthCode.TTL))
		name := oauthReadyCheckName(backend, "auth-codes")
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, name, store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, name, store)
	}
	if err := b.wireRefreshToken(); err != nil {
		return err
	}
	b.wireAccountErasure()
	if err := b.wireDeviceCodePAR(); err != nil {
		return err
	}
	b.wireJARFetcher()
	if err := b.wireCIBA(); err != nil {
		return err
	}
	b.wireTokenExchangeChainLifetime()
	if err := b.wireJARM(); err != nil {
		return err
	}
	if err := b.wireIntrospection(); err != nil {
		return err
	}
	return b.wireIntrospectionSigning()
}

// wireAccountErasure wires GDPR Art. 17 self-service account erasure
// (/me/account/erase) with a complete eraser (incl. refresh-token revocation
// via the subject index when the store supports it) so a self-deletion also
// cuts off tokens. Opt-in + irreversible; extracted from
// wireOAuthGrantStores for the function-length budget.
func (b *appBuilder) wireAccountErasure() {
	if !b.cfg.SelfService.AccountDeletion || b.userProvider == nil {
		return
	}
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

// wireJARFetcher wires the RFC 9101 §5.2.2 request_uri fetcher. Extracted
// from wireOAuthGrantStores for the function-length budget.
func (b *appBuilder) wireJARFetcher() {
	jar := b.cfg.OAuth.JAR
	if !jar.Enabled {
		return
	}
	f := security.NewHTTPJARFetcher()
	if jar.Timeout > 0 {
		f.Client.Timeout = jar.Timeout
	}
	if jar.MaxBytes > 0 {
		f.MaxBytes = jar.MaxBytes
	}
	b.opts = append(b.opts, sso.WithJARFetcher(f))
}

// wireTokenExchangeChainLifetime wires the optional RFC 8693 token-exchange
// chain-lifetime cap. Extracted from wireOAuthGrantStores for the
// function-length budget.
func (b *appBuilder) wireTokenExchangeChainLifetime() {
	if d := b.cfg.OAuth.TokenExchange.MaxChainLifetime; d > 0 {
		b.opts = append(b.opts, sso.WithMaxTokenExchangeChainLifetime(d))
		b.logger.Info("token-exchange chain max lifetime enabled", "max_lifetime", d)
	}
}

// wireRefreshToken wires the refresh-token store + the opt-in rotation-grace
// window, recording the store + TTL for downstream consumers.
func (b *appBuilder) wireRefreshToken() error {
	cfg := b.cfg
	if !cfg.OAuth.RefreshToken.Enabled {
		return nil
	}
	backend := oauthBackend(cfg.OAuth)
	store, err := serverbuildstore.BuildRefreshTokenStore(cfg.OAuth, b.redis, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("oauth.refresh_token: %w", err)
	}
	if err := b.checkOAuthStoreSchema(backend, "refresh_tokens", store,
		sqlitestores.RefreshTokensMaxVersion(), postgresbackend.RefreshTokensMaxVersion()); err != nil {
		return err
	}
	b.opts = append(b.opts, sso.WithRefreshTokenStore(store, cfg.OAuth.RefreshToken.TTL))
	name := oauthReadyCheckName(backend, "refresh-tokens")
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, name, store)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, name, store)
	b.refreshTokenStore = store
	b.refreshTokenTTL = cfg.OAuth.RefreshToken.TTL
	if d := cfg.OAuth.RefreshToken.AbsoluteMaxLifetime; d > 0 {
		b.opts = append(b.opts, sso.WithRefreshAbsoluteMaxLifetime(d))
		b.logger.Info("refresh-token absolute max lifetime enabled", "max_lifetime", d)
	}
	return b.wireRefreshRotationGrace()
}

// wireRefreshRotationGrace opts into the refresh-rotation grace window for
// multi-replica resilience. Extracted from wireRefreshToken for function-length
// budget. 0 = strict single-use (no-op). Supports memory, sqlite, redis, and
// postgres.
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
		case "postgres":
			if b.pgDB == nil {
				return errors.New("oauth.refresh_token.rotation_grace_backend=postgres but no postgres block configured (set postgres.dsn)")
			}
			store, err := postgresbackend.NewRefreshGraceStoreWithDB(b.pgDB, b.pgDialect, w, 0)
			if err != nil {
				return fmt.Errorf("refresh rotation grace store: %w", err)
			}
			b.opts = append(b.opts, sso.WithRefreshRotationGraceStore(store))
			b.opts = serverbuildsign.AppendReadyCheck(b.opts, "postgres-refresh-grace", store)
			b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "postgres-refresh-grace", store)
			b.refreshGracePruneCancel = store.CleanupStop()
			b.refreshGracePruneDone = store.CleanupDone()
			b.logger.Info("refresh rotation grace enabled (postgres; cluster-shared)", "window", w)
		default:
			return fmt.Errorf("unknown oauth.refresh_token.rotation_grace_backend %q (supported: memory, sqlite, redis, postgres)", cfg.OAuth.RefreshToken.RotationGraceBackend)
		}
	}
	return nil
}

// wireDeviceCodePAR wires the device-code and PAR grant stores.
func (b *appBuilder) wireDeviceCodePAR() error {
	cfg := b.cfg
	backend := oauthBackend(cfg.OAuth)
	if cfg.OAuth.DeviceCode.Enabled {
		store, err := serverbuildstore.BuildDeviceCodeStore(cfg.OAuth, b.redis, b.pgDB, b.pgDialect)
		if err != nil {
			return fmt.Errorf("oauth.device_code: %w", err)
		}
		if err := b.checkOAuthStoreSchema(backend, "device_codes", store,
			sqlitestores.DeviceCodesMaxVersion(), postgresbackend.DeviceCodesMaxVersion()); err != nil {
			return err
		}
		b.opts = append(b.opts, sso.WithDeviceCodeStore(
			store,
			cfg.OAuth.DeviceCode.TTL,
			cfg.OAuth.DeviceCode.PollInterval,
			cfg.OAuth.DeviceCode.VerificationBaseURL,
		))
		name := oauthReadyCheckName(backend, "device-codes")
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, name, store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, name, store)
	}
	if cfg.OAuth.PAR.Enabled {
		store, err := serverbuildstore.BuildPARStore(cfg.OAuth, b.redis, b.pgDB, b.pgDialect)
		if err != nil {
			return fmt.Errorf("par store: %w", err)
		}
		if err := b.checkOAuthStoreSchema(backend, "par", store,
			sqlitestores.PARMaxVersion(), postgresbackend.PARMaxVersion()); err != nil {
			return err
		}
		b.opts = append(b.opts, sso.WithPARStore(store, cfg.OAuth.PAR.TTL))
		name := oauthReadyCheckName(backend, "par")
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, name, store)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, name, store)
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
	pushSuffix, err := b.wireCIBAPushDelivery(cfg.CIBA, logger)
	if err != nil {
		return err
	}
	mode += pushSuffix
	logger.Info("ciba: enabled",
		"mode", mode,
		"backend", strings.ToLower(strings.TrimSpace(cfg.CIBA.Backend)),
		"transport", strings.ToLower(strings.TrimSpace(cfg.CIBA.Transport)))
	return nil
}
