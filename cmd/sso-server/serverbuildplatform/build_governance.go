package serverbuildplatform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/tokenpolicy"
	tokenpolicymemory "github.com/snaplink/sso/domains/tokenpolicy/memory"
	"github.com/snaplink/sso/interfaces/sso"
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

// BuildTokenPolicyStore builds the tokenpolicy.Store backing sso.WithTokenPolicy
// when the token_policies section is present — either an external bundle (File,
// a standalone document whose top-level token_policies: list ParseYAML decodes)
// or the inline Policies list. Returns (nil, nil) when the section is absent
// (byte-identical to a build without the feature). File and inline Policies are
// mutually exclusive: an ambiguous dual source fails loud at boot.
func BuildTokenPolicyStore(cfg config.TokenPolicyConfig) (tokenpolicy.Store, error) {
	file := strings.TrimSpace(cfg.File)
	if file == "" && len(cfg.Policies) == 0 {
		return nil, nil
	}
	if file != "" && len(cfg.Policies) > 0 {
		return nil, errors.New("token_policies: set either file or inline policies, not both")
	}
	policies := cfg.Policies
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("token_policies.file: %w", err)
		}
		parsed, err := tokenpolicy.ParseYAML(data)
		if err != nil {
			return nil, fmt.Errorf("token_policies.file: %w", err)
		}
		policies = parsed
	}
	return tokenpolicymemory.NewFromSlice(policies), nil
}

// BuildConditionalAccess builds the conditionalaccess.Store + engine Config
// backing sso.WithConditionalAccess when the access_policies section is present
// — either an external bundle (File, parsed by the strict CAP loader) or the
// inline Policies list. Returns (nil, zero Config, nil) when absent
// (byte-identical to a build without the feature). File and inline Policies are
// mutually exclusive.
func BuildConditionalAccess(cfg config.AccessPolicyConfig) (conditionalaccess.Store, conditionalaccess.Config, error) {
	file := strings.TrimSpace(cfg.File)
	if file == "" && len(cfg.Policies) == 0 {
		return nil, conditionalaccess.Config{}, nil
	}
	if file != "" && len(cfg.Policies) > 0 {
		return nil, conditionalaccess.Config{}, errors.New("access_policies: set either file or inline policies, not both")
	}
	store := conditionalaccess.NewMemoryStore()
	if err := loadAccessPolicies(store, file, cfg.Policies); err != nil {
		return nil, conditionalaccess.Config{}, err
	}
	return store, conditionalaccess.Config{DegradedTrust: cfg.DegradedTrust, DefaultDeny: cfg.DefaultDeny}, nil
}

// loadAccessPolicies seeds store from the bundle file (strict loader, unknown
// keys rejected) or the inline list (validated on Put). Extracted to keep
// BuildConditionalAccess within the function-length budget. A returned error
// makes the caller discard the fresh store, so partial seeding never leaks.
func loadAccessPolicies(store *conditionalaccess.MemoryStore, file string, inline []conditionalaccess.Policy) error {
	ctx := context.Background()
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("access_policies.file: %w", err)
		}
		if err := conditionalaccess.LoadInto(ctx, store, data); err != nil {
			return fmt.Errorf("access_policies.file: %w", err)
		}
		return nil
	}
	for _, p := range inline {
		if err := store.Put(ctx, p); err != nil {
			return fmt.Errorf("access_policies: %w", err)
		}
	}
	return nil
}

// BuildDegradationManager builds the degraded-service Manager backing
// sso.WithDegradationManager when degradation.enabled, starting in the
// configured initial mode. Returns (nil, nil) when disabled — byte-identical to
// a build without the gate. An unrecognized initial_mode fails loud rather than
// silently booting into an unknown, request-shedding posture.
func BuildDegradationManager(cfg config.DegradationConfig) (*sso.DegradationManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	mode := sso.DegradationModeNormal
	if m := strings.TrimSpace(cfg.InitialMode); m != "" {
		mode = sso.DegradationMode(m)
		if !mode.Valid() {
			return nil, fmt.Errorf("degradation.initial_mode %q invalid (normal|read_only|auth_only|local_only|maintenance)", cfg.InitialMode)
		}
	}
	return sso.NewDegradationManager(mode), nil
}
