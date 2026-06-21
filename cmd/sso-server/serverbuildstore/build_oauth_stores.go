package serverbuildstore

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/snaplink/sso/protocols/oauth"

	"github.com/snaplink/sso/config"

	"github.com/snaplink/sso/infrastructure/defaultimpl"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
)

// BuildAuthCodeStore / BuildRefreshTokenStore / BuildDeviceCodeStore
// pick between memory + sqlite per cfg.Backend. SQLite needs a DSN;
// memory needs nothing. Each SQLite call opens its own connection
// pool — for SQLite that's fine (OS-level file lock coordinates),
// for a future shared *sql.DB across stores a different abstraction
// is needed.
func BuildAuthCodeStore(cfg config.OAuthConfig) (oauth.AuthCodeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryAuthCodeStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewAuthCodeStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

func BuildRefreshTokenStore(cfg config.OAuthConfig) (oauth.RefreshTokenStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		s := defaultimpl.NewMemoryRefreshTokenStore()
		s.MaxRotationsPerWindow = cfg.RefreshToken.MaxRotationsPerWindow
		s.RotationWindow = cfg.RefreshToken.RotationWindow
		return s, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		s, err := sqlitestores.NewRefreshTokenStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, err
		}
		s.MaxRotationsPerWindow = cfg.RefreshToken.MaxRotationsPerWindow
		s.RotationWindow = cfg.RefreshToken.RotationWindow
		return s, nil
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

func BuildDeviceCodeStore(cfg config.OAuthConfig) (oauth.DeviceCodeStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryDeviceCodeStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewDeviceCodeStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

func BuildPARStore(cfg config.OAuthConfig) (oauth.PARStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryPARStore(), nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, errors.New("oauth.sqlite.dsn required when backend=sqlite")
		}
		return sqlitestores.NewPARStore(cfg.SQLite.DSN)
	default:
		return nil, fmt.Errorf("unknown oauth.backend %q", cfg.Backend)
	}
}

// ResolvePairwiseSalt reads the pairwise hash salt with the same
// file-wins-over-inline precedence the PII redactor uses. Empty
// salt falls back to security.DefaultPairwiseSalt — fine for tests, not
// fine for production (publicly known).
func ResolvePairwiseSalt(cfg config.PairwiseSubjectsConfig) (string, error) {
	if cfg.SaltFile != "" {
		b, err := os.ReadFile(cfg.SaltFile)
		if err != nil {
			return "", fmt.Errorf("read salt file: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return cfg.Salt, nil
}

// ResolvePIISalt reads the redaction salt from inline YAML or a file
// (file wins when both set — operators typically use file for prod).
// Returns an error when both are empty so a misconfiguration becomes
// loud at boot rather than silently degrading to an empty salt that
// makes hash inversion trivial.
func ResolvePIISalt(cfg config.AuditPIIRedactionConfig) (string, error) {
	if cfg.SaltFile != "" {
		b, err := os.ReadFile(cfg.SaltFile)
		if err != nil {
			return "", fmt.Errorf("read salt file: %w", err)
		}
		s := strings.TrimRight(string(b), "\r\n")
		if s == "" {
			return "", fmt.Errorf("salt file %q is empty", cfg.SaltFile)
		}
		return s, nil
	}
	if cfg.Salt == "" {
		return "", errors.New("salt or salt_file must be set when pii_redaction is enabled")
	}
	return cfg.Salt, nil
}
