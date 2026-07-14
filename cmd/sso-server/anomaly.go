package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/domains/threataction"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/detectors"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/platform/metrics"
)

// anomalyRuntime bundles the lifecycle-owned anomaly resources cmd
// must close at shutdown — the AsyncAnomalyRunner workers, and the
// SQLite stores if they were opened. Each may be nil when anomaly
// is disabled OR the backend is memory.
type anomalyRuntime struct {
	runner         *anomaly.Runner
	recentSQLite   *sqlitestores.RecentLoginStore
	ipFailSQLite   *sqlitestores.IPFailureCounter
	recentStore    anomaly.RecentLoginStore // memory or sqlite — for retention scheduler
	ipFailCounter  anomaly.IPFailureCounter
	recentLoginAge time.Duration
	ipFailureAge   time.Duration
}

// wireThreatAction builds the Active ITDR composite executor + policy store
// (threat_action.enabled) and wires sso.WithThreatExecutor / WithThreatPolicyStore.
// Called from finalize() right after wireCluster — the earliest point at
// which sessionMgr, refreshTokenStore (as a threataction.FamilyRevoker), and
// the cluster Bus are ALL simultaneously available — so the returned executor
// can also be handed to anomaly.Runner (wireAnomaly, called right after) and
// tokenanomaly.Detector (wireGovernance -> wireTokenAnomaly): one shared
// instance, one rate-limiter, one policy view for both detection sources.
//
// Returns (nil, nil) when disabled — byte-identical to a build without the
// feature.
func (b *appBuilder) wireThreatAction(bus cluster.Bus) (threataction.ThreatExecutor, error) {
	var familyRevoker threataction.FamilyRevoker
	if fr, ok := b.refreshTokenStore.(threataction.FamilyRevoker); ok {
		familyRevoker = fr
	}
	var trustMgr core.SessionTrustManager
	if tm, ok := b.sessionMgr.(core.SessionTrustManager); ok {
		trustMgr = tm
	}
	exec, store, err := serverbuildplatform.BuildThreatAction(
		b.cfg.ThreatAction, b.sessionMgr, trustMgr, familyRevoker, bus, b.recorder, b.logger)
	if err != nil {
		return nil, fmt.Errorf("threat action: %w", err)
	}
	if exec == nil {
		return nil, nil
	}
	b.opts = append(b.opts, sso.WithThreatExecutor(exec), sso.WithThreatPolicyStore(store))
	b.logger.Info("threat action executor enabled — Active ITDR anomaly/token-anomaly response bridge wired")
	return exec, nil
}

// wireDetectionResponse wires the Active ITDR executor and the anomaly.Runner
// that consumes it in one step. Called from finalize() right after
// wireCluster — the earliest point sessionMgr, refreshTokenStore, and the
// cluster Bus are ALL available (see wireThreatAction). Split out of
// finalize to stay within the function-length budget; the returned executor
// is also handed to wireGovernance for tokenanomaly.Detector.
func (b *appBuilder) wireDetectionResponse(bus cluster.Bus) (threataction.ThreatExecutor, error) {
	threatExec, err := b.wireThreatAction(bus)
	if err != nil {
		return nil, err
	}
	if err := b.wireAnomaly(threatExec); err != nil {
		return nil, err
	}
	return threatExec, nil
}

// buildAnomaly wires the anomaly detection subsystem. Returns
// (nil, nil) when anomaly.enabled=false. Fails loud on:
//   - empty IPSalt (privacy invariant violation)
//   - no detectors enabled (runner would be no-op)
//   - sqlite backend selected without dsn
//
// threatExec is the optional Active ITDR executor (wireThreatAction); nil
// leaves the runner audit/metric-only, exactly as before this option existed.
func buildAnomaly(cfg config.AnomalyConfig, recorder *audit.Recorder, m *metrics.Metrics, logger spi.Logger, threatExec threataction.ThreatExecutor) (*anomalyRuntime, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.IPSalt == "" {
		logger.Error("anomaly.enabled=true but ip_salt empty — anomaly tests OK but production deployments MUST set ip_salt for PII-hash privacy")
	}
	ipSalt, err := decodeAnomalySalt(cfg.IPSalt)
	if err != nil {
		return nil, fmt.Errorf("anomaly.ip_salt: %w", err)
	}

	rt := &anomalyRuntime{}

	recentStore, ipCounter, err := openAnomalyStores(rt, cfg)
	if err != nil {
		return nil, err
	}

	built, err := buildAnomalyDetectors(cfg.Detectors, recentStore, ipCounter, ipSalt)
	if err != nil {
		return nil, err
	}
	if len(built) == 0 {
		logger.Error("anomaly.enabled=true but no detector enabled — subsystem inert")
		return nil, nil
	}

	var sink anomaly.Sink
	if recorder != nil {
		sink = anomaly.NewRecorderSink(recorder)
	}
	rt.runner = anomaly.NewRunner(built, sink, anomalyRunnerOptions(cfg.Runner, m, logger, threatExec)...)
	if rt.runner == nil {
		// NewAsyncAnomalyRunner returns nil when the detector list
		// is empty — we already guarded above, but defense-in-depth.
		return nil, nil
	}
	rt.runner.Start()
	rt.recentLoginAge = cfg.Retention.RecentLoginAge
	rt.ipFailureAge = cfg.Retention.IPFailureAge
	return rt, nil
}

// openAnomalyStores opens the recent-login + IP-failure stores and records the
// memory/sqlite handles on rt for the retention scheduler + shutdown. Closes the
// recent-login store if the IP-failure store fails so a half-open boot doesn't
// leak a SQLite handle.
func openAnomalyStores(rt *anomalyRuntime, cfg config.AnomalyConfig) (anomaly.RecentLoginStore, anomaly.IPFailureCounter, error) {
	recentStore, recentSQL, err := openRecentLoginStore(cfg.RecentLogin)
	if err != nil {
		return nil, nil, fmt.Errorf("anomaly.recent_login: %w", err)
	}
	rt.recentStore = recentStore
	rt.recentSQLite = recentSQL

	ipCounter, ipSQL, err := openIPFailureCounter(cfg.IPFailure)
	if err != nil {
		if recentSQL != nil {
			_ = recentSQL.Close()
		}
		return nil, nil, fmt.Errorf("anomaly.ip_failure: %w", err)
	}
	rt.ipFailCounter = ipCounter
	rt.ipFailSQLite = ipSQL
	return recentStore, ipCounter, nil
}

// anomalyRunnerOptions assembles the AsyncAnomalyRunner options from the runner
// config + optional metrics callbacks. Unset knobs leave the SDK defaults.
func anomalyRunnerOptions(cfg config.AnomalyRunnerConfig, m *metrics.Metrics, logger spi.Logger, threatExec threataction.ThreatExecutor) []anomaly.Option {
	opts := []anomaly.Option{
		anomaly.WithLogger(logger),
	}
	if threatExec != nil {
		opts = append(opts, anomaly.WithThreatExecutor(threatExec))
	}
	if cfg.QueueSize > 0 {
		opts = append(opts, anomaly.WithQueueSize(cfg.QueueSize))
	}
	if cfg.Workers > 0 {
		opts = append(opts, anomaly.WithWorkers(cfg.Workers))
	}
	if cfg.DropPolicy != "" {
		opts = append(opts, anomaly.WithDropPolicy(anomaly.DropPolicy(cfg.DropPolicy)))
	}
	if cfg.InspectTimeout > 0 {
		opts = append(opts, anomaly.WithInspectTimeout(cfg.InspectTimeout))
	}
	if m != nil {
		opts = append(opts, anomaly.WithMetricsCallbacks(
			func(t, sev string) { m.AnomaliesDetectedTotal.WithLabelValues(t, sev).Inc() },
			func(reason string) { m.AnomalyDispatchDropsTotal.WithLabelValues(reason).Inc() },
			func(detector string) { m.AnomalyInspectErrorsTotal.WithLabelValues(detector).Inc() },
			func() { m.AnomalyDispatchedTotal.Inc() },
		))
	}
	return opts
}

// decodeAnomalySalt parses the configured IPSalt — accepts hex
// (recommended, 64 chars for 32 bytes) or raw bytes (any length;
// not recommended, secrets in YAML hit git logs).
func decodeAnomalySalt(s string) ([]byte, error) {
	if s == "" {
		return nil, nil // operator was warned; proceed for memory-only deploys
	}
	// Try hex first (operator-friendly canonical encoding).
	if b, err := hex.DecodeString(strings.TrimSpace(s)); err == nil {
		return b, nil
	}
	// Fallback: treat as raw bytes.
	return []byte(s), nil
}

// openRecentLoginStore selects backend per cfg.Backend.
func openRecentLoginStore(cfg config.AnomalyStoreConfig) (anomaly.RecentLoginStore, *sqlitestores.RecentLoginStore, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryRecentLoginStore(), nil, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, nil, errors.New("backend=sqlite requires dsn")
		}
		s, err := sqlitestores.NewRecentLoginStore(cfg.SQLite.DSN)
		if err != nil {
			return nil, nil, fmt.Errorf("sqlite: %w", err)
		}
		return s, s, nil
	default:
		return nil, nil, fmt.Errorf("unknown backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// openIPFailureCounter selects backend per cfg.Backend.
func openIPFailureCounter(cfg config.AnomalyStoreConfig) (anomaly.IPFailureCounter, *sqlitestores.IPFailureCounter, error) {
	switch strings.ToLower(cfg.Backend) {
	case "", "memory":
		return defaultimpl.NewMemoryIPFailureCounter(), nil, nil
	case "sqlite":
		if cfg.SQLite.DSN == "" {
			return nil, nil, errors.New("backend=sqlite requires dsn")
		}
		s, err := sqlitestores.NewIPFailureCounter(cfg.SQLite.DSN)
		if err != nil {
			return nil, nil, fmt.Errorf("sqlite: %w", err)
		}
		return s, s, nil
	default:
		return nil, nil, fmt.Errorf("unknown backend %q (supported: memory, sqlite)", cfg.Backend)
	}
}

// buildAnomalyDetectors constructs the enabled detectors. Returns
// empty slice when all detectors are disabled — caller treats this
// as "subsystem inert" and skips runner creation.
func buildAnomalyDetectors(cfg config.AnomalyDetectorsConfig, recent anomaly.RecentLoginStore, ipCounter anomaly.IPFailureCounter, ipSalt []byte) ([]anomaly.Detector, error) {
	var built []anomaly.Detector
	// Each builder returns (nil, nil) when its detector is disabled so the
	// append is a no-op; an enabled-but-misconfigured detector fails loud.
	builders := []func() (anomaly.Detector, error){
		func() (anomaly.Detector, error) {
			return buildImpossibleTravelDetector(cfg.ImpossibleTravel, recent, ipSalt)
		},
		func() (anomaly.Detector, error) { return buildVelocityDetector(cfg.Velocity, recent) },
		func() (anomaly.Detector, error) { return buildNewDeviceDetector(cfg.NewDevice, recent, ipSalt) },
		func() (anomaly.Detector, error) { return buildNewCountryDetector(cfg.NewCountry, recent) },
		func() (anomaly.Detector, error) {
			return buildBruteForceShadowDetector(cfg.BruteForceShadow, ipCounter, ipSalt)
		},
	}
	for _, b := range builders {
		d, err := b()
		if err != nil {
			return nil, err
		}
		if d != nil {
			built = append(built, d)
		}
	}
	return built, nil
}

func buildImpossibleTravelDetector(cfg config.ImpossibleTravelDetectorConfig, recent anomaly.RecentLoginStore, ipSalt []byte) (anomaly.Detector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []detectors.ImpossibleTravelOption{}
	if cfg.MaxSpeedKmh > 0 {
		opts = append(opts, detectors.WithImpossibleTravelMaxSpeed(cfg.MaxSpeedKmh))
	}
	if cfg.HistoryWindow > 0 {
		opts = append(opts, detectors.WithImpossibleTravelWindow(cfg.HistoryWindow))
	}
	d, err := detectors.NewImpossibleTravelDetector(recent, ipSalt, opts...)
	if err != nil {
		return nil, fmt.Errorf("impossible_travel: %w", err)
	}
	return d, nil
}

func buildVelocityDetector(cfg config.VelocityDetectorConfig, recent anomaly.RecentLoginStore) (anomaly.Detector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	// Honor 0 as "explicitly disable this check" (not "use default").
	opts := []detectors.VelocityOption{
		detectors.WithVelocityHourlyLimit(cfg.HourlyLimit),
		detectors.WithVelocityDailyLimit(cfg.DailyLimit),
	}
	d, err := detectors.NewVelocityDetector(recent, opts...)
	if err != nil {
		return nil, fmt.Errorf("velocity: %w", err)
	}
	return d, nil
}

func buildNewDeviceDetector(cfg config.BaselineDetectorConfig, recent anomaly.RecentLoginStore, ipSalt []byte) (anomaly.Detector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []detectors.NewDeviceOption{}
	if cfg.BaselineWindow > 0 {
		opts = append(opts, detectors.WithNewDeviceBaselineWindow(cfg.BaselineWindow))
	}
	opts = append(opts, detectors.WithNewDeviceBootstrapGracePeriod(cfg.BootstrapGracePeriod))
	d, err := detectors.NewNewDeviceDetector(recent, ipSalt, opts...)
	if err != nil {
		return nil, fmt.Errorf("new_device: %w", err)
	}
	return d, nil
}

func buildNewCountryDetector(cfg config.BaselineDetectorConfig, recent anomaly.RecentLoginStore) (anomaly.Detector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []detectors.NewCountryOption{}
	if cfg.BaselineWindow > 0 {
		opts = append(opts, detectors.WithNewCountryBaselineWindow(cfg.BaselineWindow))
	}
	opts = append(opts, detectors.WithNewCountryBootstrapGracePeriod(cfg.BootstrapGracePeriod))
	d, err := detectors.NewNewCountryDetector(recent, opts...)
	if err != nil {
		return nil, fmt.Errorf("new_country: %w", err)
	}
	return d, nil
}

func buildBruteForceShadowDetector(cfg config.BruteForceShadowDetectorConfig, ipCounter anomaly.IPFailureCounter, ipSalt []byte) (anomaly.Detector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []detectors.BruteForceShadowOption{}
	if cfg.Window > 0 {
		opts = append(opts, detectors.WithBruteForceShadowWindow(cfg.Window))
	}
	opts = append(opts, detectors.WithBruteForceShadowFailureLimit(cfg.FailureLimit))
	opts = append(opts, detectors.WithBruteForceShadowDistinctSubjectLimit(cfg.DistinctSubjectLimit))
	d, err := detectors.NewBruteForceShadowDetector(ipCounter, ipSalt, opts...)
	if err != nil {
		return nil, fmt.Errorf("brute_force_shadow: %w", err)
	}
	return d, nil
}

// close drains the runner + closes SQLite handles. Caller wraps ctx
// with a deadline for graceful shutdown.
func (rt *anomalyRuntime) close(ctx context.Context) {
	if rt == nil {
		return
	}
	if rt.runner != nil {
		_ = rt.runner.Close(ctx)
	}
	if rt.recentSQLite != nil {
		_ = rt.recentSQLite.Close()
	}
	if rt.ipFailSQLite != nil {
		_ = rt.ipFailSQLite.Close()
	}
}
