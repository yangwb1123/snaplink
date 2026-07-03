package serverbuildplatform

import (
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/configaudit"
	configauditsqlite "github.com/snaplink/sso/platform/configaudit/sqlite"
	"github.com/snaplink/sso/platform/lifecycle/rotation"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/security/securityverify"
	"github.com/snaplink/sso/shared/spi"
)

// BuildCredentialRotation assembles the unified credential-rotation Registry +
// Scheduler when rotation.enabled. It registers the wave-1 webhook-HMAC secret
// rotator (securityverify.WebhookSecretRotator) — the only CredentialRotator
// the SDK currently ships — seeded from initialSecret (empty ⇒ a fresh random
// secret). The Registry backs the read-only GET /api/v1/admin/credentials
// inventory (sso.WithCredentialRotation); the Scheduler drives the background
// rotations and is Start/Stopped by the caller under the process lifecycle.
//
// Returns (nil, nil, nil) when disabled — byte-identical to a build without it.
func BuildCredentialRotation(cfg config.RotationConfig, initialSecret []byte, logger spi.Logger, m *metrics.Metrics) (*rotation.Registry, *rotation.Scheduler, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	if cfg.Interval <= 0 {
		return nil, nil, errors.New("rotation.interval must be > 0 when rotation.enabled")
	}
	secret, err := securityverify.NewRotatingWebhookSecret(initialSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("rotation: webhook secret: %w", err)
	}
	reg := rotation.NewRegistry()
	if err := reg.Register(securityverify.NewWebhookSecretRotator(secret, cfg.Overlap), cfg.Interval); err != nil {
		return nil, nil, fmt.Errorf("rotation: register webhook rotator: %w", err)
	}
	sched := rotation.NewScheduler(reg, credentialSchedulerOptions(cfg, logger, m)...)
	logger.Info("credential rotation scheduler enabled",
		"interval", cfg.Interval, "overlap", cfg.Overlap)
	return reg, sched, nil
}

// credentialSchedulerOptions maps the config knobs to rotation.SchedulerOptions,
// leaving the framework defaults in place for any zero-valued knob.
func credentialSchedulerOptions(cfg config.RotationConfig, logger spi.Logger, m *metrics.Metrics) []rotation.SchedulerOption {
	opts := []rotation.SchedulerOption{
		rotation.WithSchedulerLogger(logger),
		rotation.WithSchedulerMetrics(m),
	}
	if cfg.Tick > 0 {
		opts = append(opts, rotation.WithSchedulerTick(cfg.Tick))
	}
	if cfg.RetryBase > 0 || cfg.RetryMax > 0 {
		opts = append(opts, rotation.WithRetryBackoff(cfg.RetryBase, cfg.RetryMax))
	}
	return opts
}

// BuildConfigAuditStore builds the configaudit.Store backing the config-history
// admin endpoint (sso.WithConfigAuditStore) when config_audit.enabled. Memory
// is the default (a self-bounding ring buffer that resets on restart); sqlite
// persists across restarts. A returned store that is an io.Closer is closed by
// the caller at shutdown.
func BuildConfigAuditStore(cfg config.ConfigAuditConfig) (configaudit.Store, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return configaudit.NewMemoryStore(0), nil
	case "sqlite":
		if cfg.Sqlite.DSN == "" {
			return nil, errors.New("config_audit.sqlite.dsn required when config_audit.backend=sqlite")
		}
		s, err := configauditsqlite.New(cfg.Sqlite.DSN)
		if err != nil {
			return nil, fmt.Errorf("config_audit.sqlite: %w", err)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unknown config_audit.backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// EffectiveConfigSnapshot renders the fully-resolved *config.Config into the
// redacted map[string]any that the config-audit snapshot endpoints
// (running/applied/diff) and the cross-replica drift digest consume. It
// round-trips through YAML — the same schema the loader reads — so snapshot keys
// match the operator's config file, then scrubs credential-bearing leaves via
// configaudit.Redact before the map can leave this process.
func EffectiveConfigSnapshot(cfg *config.Config) (map[string]any, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("config snapshot: marshal: %w", err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("config snapshot: unmarshal: %w", err)
	}
	return configaudit.Redact(m), nil
}
