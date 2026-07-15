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
	"github.com/snaplink/sso/domains/threataction"
	threatactionmemory "github.com/snaplink/sso/domains/threataction/memory"
	"github.com/snaplink/sso/domains/tokenanomaly"
	tokenanomalymemory "github.com/snaplink/sso/domains/tokenanomaly/memory"
	"github.com/snaplink/sso/domains/tokenpolicy"
	tokenpolicymemory "github.com/snaplink/sso/domains/tokenpolicy/memory"
	"github.com/snaplink/sso/domains/tokenusage"
	tokenusagememory "github.com/snaplink/sso/domains/tokenusage/memory"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/configaudit"
	configauditsqlite "github.com/snaplink/sso/platform/configaudit/sqlite"
	"github.com/snaplink/sso/platform/lifecycle/rotation"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security/clientrotation"
	"github.com/snaplink/sso/shared/security/securityverify"
	"github.com/snaplink/sso/shared/spi"
)

// BuildCredentialRotation assembles the unified credential-rotation Registry +
// Scheduler when EITHER rotation.enabled (webhook-HMAC secret) or
// client_secret_rotation.enabled (OAuth client secrets) is set. Both
// rotators — securityverify.WebhookSecretRotator and
// clientrotation.ClientSecretRotator — register onto the SAME Registry and
// share ONE Scheduler: rotation.Registry.Register takes an interval PER
// rotator, so one Scheduler already supports multiple cadences, and a single
// background loop is simpler to run/Start/Stop than two. webhookSecret seeds
// the webhook rotator (empty ⇒ a fresh random secret); clientStore is the
// OAuth ClientStore the client-secret rotator sweeps (required, and must
// implement clientrotation.ClientRotationLister, when clientCfg.Enabled). The
// Registry backs the read-only GET /api/v1/admin/credentials inventory
// (sso.WithCredentialRotation); the Scheduler drives the background rotations
// and is Start/Stopped by the caller under the process lifecycle.
//
// Returns (nil, nil, nil) when both are disabled — byte-identical to a build
// without either feature.
func BuildCredentialRotation(cfg config.RotationConfig, clientCfg config.ClientSecretRotationConfig, webhookSecret []byte, clientStore core.ClientStore, logger spi.Logger, m *metrics.Metrics) (*rotation.Registry, *rotation.Scheduler, error) {
	if !cfg.Enabled && !clientCfg.Enabled {
		return nil, nil, nil
	}
	reg := rotation.NewRegistry()
	if cfg.Enabled {
		if err := registerWebhookRotator(reg, cfg, webhookSecret); err != nil {
			return nil, nil, err
		}
	}
	if clientCfg.Enabled {
		if err := registerClientSecretRotator(reg, clientCfg, clientStore, logger); err != nil {
			return nil, nil, err
		}
	}
	// Scheduler tick/backoff are configured ONCE under `rotation:` regardless
	// of which rotators are registered onto this shared Registry.
	sched := rotation.NewScheduler(reg, credentialSchedulerOptions(cfg, logger, m)...)
	logger.Info("credential rotation scheduler enabled",
		"webhook_enabled", cfg.Enabled, "client_secret_enabled", clientCfg.Enabled)
	return reg, sched, nil
}

// registerWebhookRotator seeds + registers the webhook-HMAC secret rotator.
func registerWebhookRotator(reg *rotation.Registry, cfg config.RotationConfig, webhookSecret []byte) error {
	if cfg.Interval <= 0 {
		return errors.New("rotation.interval must be > 0 when rotation.enabled")
	}
	secret, err := securityverify.NewRotatingWebhookSecret(webhookSecret)
	if err != nil {
		return fmt.Errorf("rotation: webhook secret: %w", err)
	}
	if err := reg.Register(securityverify.NewWebhookSecretRotator(secret, cfg.Overlap), cfg.Interval); err != nil {
		return fmt.Errorf("rotation: register webhook rotator: %w", err)
	}
	return nil
}

// registerClientSecretRotator validates + registers the OAuth client-secret
// rotator. Fails loud (rather than silently never rotating anything) when
// the configured store can't support scheduled due-listing — an operator who
// explicitly enabled this feature deserves a boot-time error, not a
// permanently-silent no-op.
func registerClientSecretRotator(reg *rotation.Registry, clientCfg config.ClientSecretRotationConfig, clientStore core.ClientStore, logger spi.Logger) error {
	if clientCfg.Interval <= 0 {
		return errors.New("client_secret_rotation.interval must be > 0 when client_secret_rotation.enabled")
	}
	if clientStore == nil {
		return errors.New("client_secret_rotation.enabled requires a configured client store")
	}
	if _, ok := clientStore.(clientrotation.ClientRotationLister); !ok {
		return fmt.Errorf("client_secret_rotation.enabled requires a ClientStore implementing "+
			"clientrotation.ClientRotationLister (the memory + sqlite defaultimpl backends do); got %T", clientStore)
	}
	rotator := clientrotation.NewClientSecretRotator(clientStore, clientCfg.Interval, logger)
	if err := reg.Register(rotator, clientCfg.Interval); err != nil {
		return fmt.Errorf("rotation: register client secret rotator: %w", err)
	}
	return nil
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
// mutually exclusive. cfg.Enforce passes straight through to Config.Enforce —
// false (the default) keeps the engine advisory-only even when policies are
// configured; see AccessPolicyConfig's doc for the staged-rollout pattern.
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
	return store, conditionalaccess.Config{DegradedTrust: cfg.DegradedTrust, DefaultDeny: cfg.DefaultDeny, Enforce: cfg.Enforce}, nil
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

// BuildThreatAction assembles the Active ITDR composite executor
// (domains/threataction) when threat_action.enabled: a ThreatExecutors that
// maps policy-selected actions to concrete handlers (suspend_session,
// revoke_family, step_up_mfa, challenge, notify) plus the in-memory ThreatPolicyStore
// seeded from cfg.Policies. sessionMgr/trustMgr/familyRevoker/subjectRevoker/bus
// are each independently optional (nil-safe) — the caller resolves
// familyRevoker, subjectRevoker, and trustMgr via a type assertion against
// its refresh-token store / session manager (all OPTIONAL extensions), so a
// build missing any of them still gets a working executor for the actions it
// CAN support. subjectRevoker is revoke_family's fallback for a threat with
// no FamilyID — see threataction.SubjectRevoker's doc for why that's the
// common case in production.
//
// Returns (nil, nil, nil) when disabled — byte-identical to a build without
// the feature. The returned executor is the SAME instance the caller should
// hand to both sso.WithThreatExecutor and anomaly.WithThreatExecutor /
// tokenanomaly.WithThreatExecutor, so the two detection sources share one
// rate-limiter + policy view.
func BuildThreatAction(
	cfg config.ThreatActionConfig,
	sessionMgr core.SessionManager,
	trustMgr core.SessionTrustManager,
	familyRevoker threataction.FamilyRevoker,
	subjectRevoker threataction.SubjectRevoker,
	bus cluster.Bus,
	recorder *audit.Recorder,
	logger spi.Logger,
) (*threataction.ThreatExecutors, threataction.ThreatPolicyStore, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	store := threatactionmemory.NewThreatPolicyStore()
	for _, p := range cfg.Policies {
		if err := store.Put(context.Background(), p); err != nil {
			return nil, nil, fmt.Errorf("threat_action.policies: %w", err)
		}
	}
	handlers := map[threataction.Action]threataction.ThreatExecutor{
		threataction.ActionSuspend:   threataction.NewSuspendSessionExecutor(sessionMgr, bus),
		threataction.ActionRevoke:    threataction.NewRevokeFamilyExecutor(familyRevoker, subjectRevoker, bus),
		threataction.ActionStepUpMFA: threataction.NewStepUpMFAExecutor(trustMgr, sessionMgr),
		threataction.ActionChallenge: threataction.NewChallengeExecutor(trustMgr, sessionMgr),
		threataction.ActionNotify:    threataction.NewNotifyExecutor(),
	}
	opts := []threataction.ThreatExecutorsOption{threataction.WithLogger(logger)}
	if cfg.DefaultAction != "" {
		opts = append(opts, threataction.WithDefaultAction(threataction.Action(cfg.DefaultAction)))
	}
	return threataction.NewThreatExecutors(store, handlers, recorder, opts...), store, nil
}

// BuildTokenAnomaly assembles the wave-4 token-behavior anomaly subsystem when
// token_anomaly.enabled: a bounded token-usage aggregation store, the
// tokenanomaly.Detector that DECORATES it (capturing per-thumbprint geo/velocity
// observations), and the tokenusage.Recorder whose drain goroutine feeds the
// detector off the request path. The detector is returned so the caller wires it
// as BOTH the recorder's store (already done here — the recorder drains into the
// detector) AND via sso.WithTokenAnomalyDetector; the recorder is returned so the
// caller can Start it and pass it to sso.WithTokenUsageRecorder.
//
// Returns (nil, nil, nil) when disabled — byte-identical to a build without it.
// The detector only observes what the recorder drains, so the two are co-wired:
// the token-usage recorder is not a separately-configurable feature this wave.
//
// threatExec is the optional Active ITDR executor (BuildThreatAction); nil
// leaves the detector's Analyze sweep audit/metric-only, exactly as before
// this option existed.
func BuildTokenAnomaly(cfg config.TokenAnomalyConfig, logger spi.Logger, threatExec threataction.ThreatExecutor) (*tokenusage.Recorder, *tokenanomaly.Detector, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	if cfg.SweepInterval <= 0 {
		return nil, nil, errors.New("token_anomaly.sweep_interval must be > 0 when token_anomaly.enabled")
	}
	// The detector decorates this store (forwarding Record/Query verbatim) and
	// the recorder drains into the detector — so every usage event both
	// aggregates into a bucket AND feeds the anomaly observation table.
	store := tokenusagememory.New(usageStoreOptions(cfg)...)
	findings := tokenanomalymemory.NewFindingStore(findingStoreOptions(cfg)...)
	detector := tokenanomaly.NewDetector(store, findings, detectorOptions(cfg, logger, threatExec)...)
	rec := tokenusage.NewRecorder(detector, recorderOptions(cfg, logger)...)
	return rec, detector, nil
}

// usageStoreOptions maps the bucket-cap knob to the memory usage store,
// leaving the package default in place when unset.
func usageStoreOptions(cfg config.TokenAnomalyConfig) []tokenusagememory.Option {
	if cfg.MaxBuckets > 0 {
		return []tokenusagememory.Option{tokenusagememory.WithMaxBuckets(cfg.MaxBuckets)}
	}
	return nil
}

// findingStoreOptions maps the finding-store cap to the memory finding store.
func findingStoreOptions(cfg config.TokenAnomalyConfig) []tokenanomalymemory.Option {
	if cfg.MaxFindings > 0 {
		return []tokenanomalymemory.Option{tokenanomalymemory.WithMaxFindings(cfg.MaxFindings)}
	}
	return nil
}

// recorderOptions maps the recorder knobs; the logger is always set so a drain
// error surfaces on the operator's configured logger rather than being silent.
func recorderOptions(cfg config.TokenAnomalyConfig, logger spi.Logger) []tokenusage.RecorderOption {
	opts := []tokenusage.RecorderOption{tokenusage.WithRecorderLogger(logger)}
	if cfg.QueueSize > 0 {
		opts = append(opts, tokenusage.WithQueueSize(cfg.QueueSize))
	}
	return opts
}

// detectorOptions maps the optional detector-tuning knobs; each zero value is
// left to the detector's adaptive package default (WithXxx ignores non-positive
// inputs, so passing zeros is safe, but skipping them keeps intent explicit).
// The logger is always set so a threatExec.Execute failure surfaces on the
// operator's configured logger rather than the NopLogger default, mirroring
// recorderOptions' equivalent always-set logger.
func detectorOptions(cfg config.TokenAnomalyConfig, logger spi.Logger, threatExec threataction.ThreatExecutor) []tokenanomaly.Option {
	opts := []tokenanomaly.Option{tokenanomaly.WithLogger(logger)}
	if threatExec != nil {
		opts = append(opts, tokenanomaly.WithThreatExecutor(threatExec))
	}
	if cfg.MaxThumbprints > 0 {
		opts = append(opts, tokenanomaly.WithMaxThumbprints(cfg.MaxThumbprints))
	}
	if cfg.Window > 0 {
		opts = append(opts, tokenanomaly.WithWindow(cfg.Window))
	}
	if cfg.VelocityGap > 0 {
		opts = append(opts, tokenanomaly.WithVelocityGap(cfg.VelocityGap))
	}
	if cfg.SpikeFactor > 1 {
		opts = append(opts, tokenanomaly.WithSpikeFactor(cfg.SpikeFactor))
	}
	if cfg.SpikeMinCount > 0 {
		opts = append(opts, tokenanomaly.WithSpikeMinCount(cfg.SpikeMinCount))
	}
	return opts
}
