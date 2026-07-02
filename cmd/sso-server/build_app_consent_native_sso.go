package main

import (
	"fmt"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	redisbackend "github.com/snaplink/sso/infrastructure/redis"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"strings"
)

// wiredForPostgres returns true when the backend config targets PostgreSQL,
// so callers can skip SQLite-specific boot checks (schema version guard).
func (b *appBuilder) wiredForPostgres(backend string) bool {
	return strings.EqualFold(strings.TrimSpace(backend), "postgres")
}

// checkSchema is a convenience wrapper around serverbuildsign.CheckSQLiteSchema
// that produces a namespaced error message on failure. The store's concrete type
// determines whether the check runs (memory stores silently no-op).
func (b *appBuilder) checkSchema(v any, namespace string, maxVersion int) error {
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, v, namespace, maxVersion); err != nil {
		return fmt.Errorf("schema check %s: %w", namespace, err)
	}
	return nil
}

// wireConsentNativeSSOPRM wires the self-service consent store, the Native SSO
// device-secret store, and RFC 9728 protected-resource metadata.
func (b *appBuilder) wireConsentNativeSSOPRM() error {
	cfg, logger := b.cfg, b.logger
	if err := b.wireConsentStore(); err != nil {
		return err
	}
	if err := b.wireDeviceSecretStore(); err != nil {
		return err
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

// wireConsentStore builds and wires the self-service consent store.
func (b *appBuilder) wireConsentStore() error {
	cfg, logger := b.cfg, b.logger
	consentStore, err := serverbuildstore.BuildConsentStore(cfg.SelfService.Consent.SelfServiceStoreConfig, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("self_service consent store: %w", err)
	}
	if consentStore == nil {
		return nil
	}
	// Schema-version boot gate: refuse to start when the SQLite
	// consent store's live schema is ahead of what this binary
	// knows. Skip for postgres (its migrate ran at construction).
	if !b.wiredForPostgres(cfg.SelfService.Consent.Backend) {
		if err := b.checkSchema(consentStore, "consent", sqlitestores.ConsentMaxVersion()); err != nil {
			return err
		}
	}
	b.consentStore = consentStore // retained for the GDPR eraser
	b.opts = append(b.opts, sso.WithConsentStore(consentStore))
	logger.Info("self-service consent enabled", "backend", cfg.SelfService.Consent.Backend)
	// Server-wide consent grant TTL ceiling (self_service.consent.max_ttl).
	// Without this, WithConsentTTL was an SDK-only option the stock binary
	// could never reach — grants lived until explicitly revoked no matter
	// what an operator wrote in YAML.
	if cfg.SelfService.Consent.MaxTTL > 0 {
		b.opts = append(b.opts, sso.WithConsentTTL(cfg.SelfService.Consent.MaxTTL))
		logger.Info("consent grant max TTL enabled", "max_ttl", cfg.SelfService.Consent.MaxTTL)
	}
	// The consent GATE issues a single-use challenge nonce across two
	// requests; with a Redis cluster wired, keep it cluster-shared so the
	// approve re-POST consuming on a different replica doesn't loop forever.
	if b.redis != nil {
		b.opts = append(b.opts, sso.WithConsentChallengeStore(redisbackend.NewConsentChallengeStore(b.redis)))
		logger.Info("consent challenge store: redis (cluster-shared)")
	}
	return nil
}

// wireDeviceSecretStore builds and wires the Native SSO device_secret store.
func (b *appBuilder) wireDeviceSecretStore() error {
	cfg, logger := b.cfg, b.logger
	deviceSecretStore, err := serverbuildstore.BuildDeviceSecretStore(cfg.NativeSSO, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("native_sso device secret store: %w", err)
	}
	if deviceSecretStore == nil {
		return nil
	}
	// Schema-version boot gate: refuse to start when the SQLite
	// device_secret store's live schema is ahead of what this binary
	// knows. Skip for postgres (its migrate ran at construction).
	if !b.wiredForPostgres(cfg.NativeSSO.Backend) {
		if err := b.checkSchema(deviceSecretStore, "device_secrets", sqlitestores.DeviceSecretsMaxVersion()); err != nil {
			return err
		}
	}
	b.opts = append(b.opts, sso.WithDeviceSecretStore(deviceSecretStore, cfg.NativeSSO.TTL))
	logger.Info("native sso enabled", "backend", cfg.NativeSSO.Backend)
	return nil
}
