package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"

	"github.com/snaplink/sso/shared/security"
)

func convertClientJWKs(in []config.ClientJWK) []sso.JWK {
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
func buildClientCertExtractor(cfg config.MTLSConfig) (sso.ClientCertExtractor, string, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	switch backend {
	case "", "tls", "peer":
		return sso.DefaultTLSPeerCertExtractor, "DefaultTLSPeerCertExtractor (in-process TLS termination)", nil
	case "header", "proxy":
		if cfg.Header.Name == "" {
			return nil, "", fmt.Errorf("security.mtls.header.name required when backend=%q", backend)
		}
		enc, err := parseHeaderCertEncoding(cfg.Header.Encoding)
		if err != nil {
			return nil, "", err
		}
		return &security.HeaderClientCertExtractor{HeaderName: cfg.Header.Name, Encoding: enc}, fmt.Sprintf("HeaderClientCertExtractor (header=%q encoding=%q — TRUST EDGE MUST STRIP HEADER)", cfg.Header.Name, cfg.Header.Encoding), nil
	default:
		return nil, "", fmt.Errorf("security.mtls.backend %q (want tls|header)", cfg.Backend)
	}
}

func parseHeaderCertEncoding(s string) (security.HeaderCertEncoding, error) {
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

func buildDPoPNonceProvider(cfg config.DPoPNonceConfig, logger spi.Logger) (sso.DPoPNonceProvider, error) {
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

// buildClientStore / buildUserProvider pick the identity-domain
// backend. Memory keeps the simple-bootstrap story; SQLite persists
// DCR registrations + password users across restarts. Same DSN can
// be shared with OAuth.SQLite — SQLite OS-file-lock handles
// cross-pool coordination.
func buildClientStore(cfg config.IdentityConfig) (sso.ClientStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryClientStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewClientStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q", cfg.Backend)
	}
}

// buildConsentStore selects the self-service consent store backend. An empty
// backend returns (nil, nil) — consent enforcement stays OFF and the routes
// stay unmounted (byte-identical). memory is dev/single-node; sqlite is durable
// and required for the GDPR consent-record retention a real deployment needs.
// buildDeviceSecretStore selects the Native SSO device_secret backend. Empty
// backend returns (nil, nil) — the feature stays off (byte-identical). sqlite
// is durable + multi-replica-safe.
func buildDeviceSecretStore(cfg config.NativeSSOConfig) (sso.DeviceSecretStore, error) {
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
	default:
		return nil, fmt.Errorf("unknown native_sso.backend %q", cfg.Backend)
	}
}

// buildPasswordResetStore selects the forgot-password reset-token backend.
// Empty backend = the flow stays disabled (byte-identical).
func buildPasswordResetStore(cfg config.PasswordResetConfig) (sso.PasswordResetStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "":
		return nil, nil
	case "memory":
		return defaultimpl.NewMemoryPasswordResetStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("self_service.password_reset.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewPasswordResetStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown self_service.password_reset.backend %q", cfg.Backend)
	}
}

func buildConsentStore(cfg config.SelfServiceStoreConfig) (sso.ConsentStore, error) {
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
	default:
		return nil, fmt.Errorf("unknown self_service.consent.backend %q", cfg.Backend)
	}
}

// buildPasswordCredentialStore selects the self-service password store backend.
// Empty backend returns (nil, nil) — /me/password stays unmounted and the
// password authenticator keeps its YAML-only verifier (byte-identical). When
// set, the store is seeded from the YAML password users and login is served
// from it, so a password changed via /me/password takes effect on next login.
func buildPasswordCredentialStore(cfg config.SelfServiceStoreConfig) (sso.PasswordCredentialStore, error) {
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
	default:
		return nil, fmt.Errorf("unknown self_service.password.backend %q", cfg.Backend)
	}
}

func buildUserProvider(cfg config.IdentityConfig) (sso.UserProvider, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryUserProvider(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewUserProvider(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q", cfg.Backend)
	}
}

// buildSessionManager picks the SessionManager backend. Same memory|
// sqlite selector as the rest of identity-domain stores so operators
// running TokenStrategySession across multiple replicas get cross-
// replica session redemption against a shared SQLite file.
func buildSessionManager(cfg config.IdentityConfig, ttl time.Duration) (sso.SessionManager, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemorySessionManager(ttl), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("identity.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewSessionManager(cfg.SQLite.DSN, ttl)
	default:
		return nil, fmt.Errorf("unknown identity.backend %q", cfg.Backend)
	}
}
