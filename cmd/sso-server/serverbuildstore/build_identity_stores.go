package serverbuildstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/tenant/activation"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	tenantactivation "github.com/yangwb1123/snaplink/infrastructure/postgres/tenantactivation"

	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"

	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

// errPostgresNotConfigured is the shared boot error for a backend:postgres
// selection with no postgres block (no shared pool was built). One message
// shape across every postgres-capable durable-store dispatcher in this package.
func errPostgresNotConfigured(domain string) error {
	return fmt.Errorf("%s.backend=postgres but no postgres block configured (set postgres.dsn)", domain)
}

func ConvertClientJWKs(in []config.ClientJWK) []sso.JWK {
	if len(in) == 0 {
		return nil
	}
	out := make([]sso.JWK, len(in))
	for i, j := range in {
		out[i] = sso.JWK{
			Kty: j.Kty,
			Use: j.Use,
			Alg: j.Alg,
			Kid: j.Kid,
			Crv: j.Crv,
			X:   j.X,
			N:   j.N,
			E:   j.E,
		}
	}
	return out
}

// The second return value is a human-readable mode label suitable
// for the boot log so operators can confirm the wiring matches the
// surrounding network topology.
//
// peerTrust (the compiled security.trusted_proxies checker; nil when the
// knob is unset) gates the header backend: the forwarded-cert header is
// honored only from a direct peer inside the trusted CIDRs, so a request
// that bypassed the TLS-terminating edge cannot mint mTLS-bound tokens for
// an arbitrary certificate. The tls backend reads the in-process handshake
// and needs no gate.
func BuildClientCertExtractor(cfg config.MTLSConfig, peerTrust *peertrust.Checker) (sso.ClientCertExtractor, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "tls", "peer":
		return sso.DefaultTLSPeerCertExtractor, "DefaultTLSPeerCertExtractor (in-process TLS termination)", nil
	case "header", "proxy":
		if cfg.Header.Name == "" {
			return nil, "", fmt.Errorf("security.mtls.header.name required when backend=%q", backend)
		}
		enc, err := ParseHeaderCertEncoding(cfg.Header.Encoding)
		if err != nil {
			return nil, "", err
		}
		extractor := &security.HeaderClientCertExtractor{HeaderName: cfg.Header.Name, Encoding: enc, PeerTrust: peerTrust}
		return extractor, fmt.Sprintf("HeaderClientCertExtractor (header=%q encoding=%q — TRUST EDGE MUST STRIP HEADER)", cfg.Header.Name, cfg.Header.Encoding), nil
	default:
		return nil, "", fmt.Errorf("security.mtls.backend %q (want tls|header)", cfg.Backend)
	}
}

func ParseHeaderCertEncoding(s string) (security.HeaderCertEncoding, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "url-pem", "urlpem", "url_pem":
		return security.HeaderCertEncodingURLPEM, nil
	case "pem":
		return security.HeaderCertEncodingPEM, nil
	case "base64-der", "base64der", "base64_der":
		return security.HeaderCertEncodingBase64DER, nil
	default:
		return 0, fmt.Errorf("security.mtls.header.encoding %q (want url-pem|pem|base64-der)", s)
	}
}

func BuildDPoPNonceProvider(cfg config.DPoPNonceConfig, logger spi.Logger) (sso.DPoPNonceProvider, error) {
	if cfg.KeyFile != "" {
		raw, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		// Trim any trailing whitespace/newline the operator likely
		// included when echo-ing the key.
		trimmed := strings.TrimSpace(string(raw))
		// Prefer hex when the file looks like hex; otherwise treat
		// as raw bytes. Hex is easier to inspect + copy.
		if key, err := hex.DecodeString(trimmed); err == nil && len(key) >= 16 {
			return sso.NewHMACNonceProviderWithKey(key, cfg.TTL)
		}
		return sso.NewHMACNonceProviderWithKey([]byte(trimmed), cfg.TTL)
	}
	logger.Info("dpop nonce: no key_file configured — generating process-local key (NOT safe for multi-replica)")
	return sso.NewHMACNonceProvider(cfg.TTL)
}

// BuildClientStore / BuildUserProvider pick the identity-domain
// backend. Memory keeps the simple-bootstrap story; SQLite persists
// DCR registrations + password users across restarts. Same DSN can
// be shared with OAuth.SQLite — SQLite OS-file-lock handles
// cross-pool coordination.
func BuildClientStore(cfg config.IdentityConfig, pg *sql.DB, dialect postgresbackend.Dialect) (sso.ClientStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryClientStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewClientStore(cfg.SQLite.DSN)
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("identity")
		}
		return postgresbackend.NewClientStoreWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildConsentStore selects the self-service consent store backend. An empty
// backend returns (nil, nil) — consent enforcement stays OFF and the routes
// stay unmounted (byte-identical). memory is dev/single-node; sqlite is durable
// and required for the GDPR consent-record retention a real deployment needs.
// BuildDeviceSecretStore selects the Native SSO device_secret backend. Empty
// backend returns (nil, nil) — the feature stays off (byte-identical). sqlite
// is durable + multi-replica-safe.
func BuildDeviceSecretStore(cfg config.NativeSSOConfig, pg *sql.DB, dialect postgresbackend.Dialect) (sso.DeviceSecretStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryDeviceSecretStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("native_sso.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewDeviceSecretStore(cfg.SQLite.DSN)
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("native_sso")
		}
		return postgresbackend.NewDeviceSecretStoreWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("unknown native_sso.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildPasswordResetStore selects the forgot-password reset-token backend.
// Empty backend = the flow stays disabled (byte-identical).
func BuildPasswordResetStore(cfg config.PasswordResetConfig, rdb goredis.Cmdable) (sso.PasswordResetStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryPasswordResetStore(), nil
	case "redis":
		// Reset tokens are hot/ephemeral and the flow is two requests (issue,
		// then emailed redeem) that can land on different replicas, so the token
		// store MUST be cluster-shared. SET+TTL / GETDEL single-use, cluster-safe.
		if rdb == nil {
			return nil, errors.New("self_service.password_reset.backend=redis but no redis block configured (set redis.addrs)")
		}
		return redisbackend.NewPasswordResetStore(rdb), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("self_service.password_reset.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewPasswordResetStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown self_service.password_reset.backend %q", cfg.Backend)
	}
}

func BuildConsentStore(cfg config.SelfServiceStoreConfig, pg *sql.DB, dialect postgresbackend.Dialect) (sso.ConsentStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryConsentStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("self_service.consent.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewConsentStore(cfg.SQLite.DSN)
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("self_service.consent")
		}
		return postgresbackend.NewConsentStoreWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("unknown self_service.consent.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildPasswordCredentialStore selects the self-service password store backend.
// Empty backend returns (nil, nil) — /me/password stays unmounted and the
// password authenticator keeps its YAML-only verifier (byte-identical). When
// set, the store is seeded from the YAML password users and login is served
// from it, so a password changed via /me/password takes effect on next login.
func BuildPasswordCredentialStore(cfg config.SelfServiceStoreConfig, pg *sql.DB, dialect postgresbackend.Dialect) (sso.PasswordCredentialStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryPasswordCredentialStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("self_service.password.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewPasswordCredentialStore(cfg.SQLite.DSN)
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("self_service.password")
		}
		return postgresbackend.NewPasswordCredentialStoreWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("unknown self_service.password.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildActivationStore selects the stock product-activation store. Empty
// backend keeps the public activation routes unmounted; both built-in
// backends hash seeded credentials and retain only short-lived tickets.
// BuildEmailChangeStore selects the verified-email-change token backend.
// Empty backend keeps the flow disabled; the stock server supports memory and
// SQLite because the token store has no Postgres or Redis peer.
func BuildEmailChangeStore(cfg config.SelfServiceStoreConfig, _ *sql.DB, _ postgresbackend.Dialect) (sso.EmailChangeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryEmailChangeStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("self_service.email_change.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewEmailChangeStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown self_service.email_change.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

func BuildActivationStore(cfg config.ActivationConfig, pg *sql.DB, dialect postgresbackend.Dialect) (activation.Store, error) {
	var store activation.Store
	switch backend := strings.ToLower(strings.TrimSpace(cfg.Backend)); backend {
	case "":
		return nil, nil
	case "memory":
		store = activation.NewMemoryStore(activation.WithTicketTTL(cfg.TicketTTL))
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("activation")
		}
		postgresStore, err := tenantactivation.NewWithDB(pg, dialect, tenantactivation.WithTicketTTL(cfg.TicketTTL))
		if err != nil {
			return nil, err
		}
		store = postgresStore
	default:
		return nil, fmt.Errorf("unknown activation.backend %q (supported: memory, postgres)", cfg.Backend)
	}
	if len(cfg.Codes) == 0 {
		return store, nil
	}
	provisioner, ok := store.(activation.CodeProvisioner)
	if !ok {
		return nil, errors.New("activation store does not support code provisioning")
	}
	for _, seed := range cfg.Codes {
		if err := provisioner.AddCode(context.Background(), activation.Code{
			ID: seed.ID, ProductID: seed.ProductID, TenantID: seed.TenantID,
			Key: seed.LicenseKey, InvitationCode: seed.InvitationCode,
			Entitlement: seed.Entitlement, ExpiresAt: seed.ExpiresAt,
			MaxClaims: seed.MaxClaims,
		}); err != nil {
			return nil, fmt.Errorf("activation code %q: %w", seed.ID, err)
		}
	}
	return store, nil
}

func BuildUserProvider(cfg config.IdentityConfig, pg *sql.DB, dialect postgresbackend.Dialect) (sso.UserProvider, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryUserProvider(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewUserProvider(cfg.SQLite.DSN)
	case "postgres":
		if pg == nil {
			return nil, errPostgresNotConfigured("identity")
		}
		return postgresbackend.NewUserProviderWithDB(pg, dialect)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q (supported: memory, sqlite, postgres)", cfg.Backend)
	}
}

// BuildSessionManager picks the SessionManager backend. Same memory|
// sqlite selector as the rest of identity-domain stores so operators
// running TokenStrategySession across multiple replicas get cross-
// replica session redemption against a shared SQLite file.
func BuildSessionManager(cfg config.IdentityConfig, ttl time.Duration, rdb goredis.Cmdable, pgDB *sql.DB, pgDialect postgresbackend.Dialect) (sso.SessionManager, error) {
	// Sessions may run on a different backend than clients/users: the hot,
	// ephemeral session store belongs in Redis Cluster for HA while identity
	// stays on a durable DB. session_backend overrides; empty falls back to
	// the identity backend. Postgres is a valid option for unified-stack
	// deployments (sessions are hot/ephemeral, but at moderate scale Postgres
	// handles them fine — for high traffic prefer redis or sqlite).
	backend := strings.ToLower(strings.TrimSpace(cfg.SessionBackend))
	if backend == "" {
		backend = strings.ToLower(strings.TrimSpace(cfg.Backend))
	}
	switch backend {
	case "", "memory":
		s := defaultimpl.NewMemorySessionManager(ttl)
		s.MaxEntries = cfg.SessionMaxEntries
		if cfg.SessionReapInterval > 0 {
			s.StartReaper(cfg.SessionReapInterval)
		}
		return s, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when sessions use backend=sqlite")
		}
		return sqlitestores.NewSessionManager(cfg.SQLite.DSN, ttl)
	case "redis":
		if rdb == nil {
			return nil, errors.New("identity session backend=redis but no redis block configured (set redis.addrs)")
		}
		return redisbackend.NewSessionManager(rdb, redisbackend.WithSessionTTL(ttl)), nil
	case "postgres":
		if pgDB == nil {
			return nil, errPostgresNotConfigured("identity")
		}
		return postgresbackend.NewSessionManagerWithDB(pgDB, pgDialect, ttl)
	default:
		return nil, fmt.Errorf("unknown identity session backend %q (supported: memory, sqlite, redis, postgres)", backend)
	}
}
