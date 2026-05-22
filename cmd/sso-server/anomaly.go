package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/defaultimpl/anomaly"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
	"github.com/snaplink/sso/metrics"
)

// anomalyRuntime bundles the lifecycle-owned anomaly resources cmd
// must close at shutdown — the AsyncAnomalyRunner workers, and the
// SQLite stores if they were opened. Each may be nil when anomaly
// is disabled OR the backend is memory.
type anomalyRuntime struct {
	runner         *sso.AsyncAnomalyRunner
	recentSQLite   *sqlitestores.RecentLoginStore
	ipFailSQLite   *sqlitestores.IPFailureCounter
	recentStore    sso.RecentLoginStore // memory or sqlite — for retention scheduler
	ipFailCounter  sso.IPFailureCounter
	recentLoginAge time.Duration
	ipFailureAge   time.Duration
}

// buildAnomaly wires the anomaly detection subsystem. Returns
// (nil, nil) when anomaly.enabled=false. Fails loud on:
//   - empty IPSalt (privacy invariant violation)
//   - no detectors enabled (runner would be no-op)
//   - sqlite backend selected without dsn
func buildAnomaly(cfg config.AnomalyConfig, recorder *audit.Recorder, m *metrics.Metrics, logger sso.Logger) (*anomalyRuntime, error) {
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

	recentStore, recentSQL, err := openRecentLoginStore(cfg.RecentLogin)
	if err != nil {
		return nil, fmt.Errorf("anomaly.recent_login: %w", err)
	}
	rt.recentStore = recentStore
	rt.recentSQLite = recentSQL

	ipCounter, ipSQL, err := openIPFailureCounter(cfg.IPFailure)
	if err != nil {
		if recentSQL != nil {
			_ = recentSQL.Close()
		}
		return nil, fmt.Errorf("anomaly.ip_failure: %w", err)
	}
	rt.ipFailCounter = ipCounter
	rt.ipFailSQLite = ipSQL

	detectors, err := buildAnomalyDetectors(cfg.Detectors, recentStore, ipCounter, ipSalt)
	if err != nil {
		return nil, err
	}
	if len(detectors) == 0 {
		logger.Error("anomaly.enabled=true but no detector enabled — subsystem inert")
		return nil, nil
	}

	var sink sso.AnomalySink
	if recorder != nil {
		sink = sso.NewRecorderAnomalySink(recorder)
	}
	opts := []sso.AnomalyRunnerOption{
		sso.WithAnomalyLogger(logger),
	}
	if cfg.Runner.QueueSize > 0 {
		opts = append(opts, sso.WithAnomalyQueueSize(cfg.Runner.QueueSize))
	}
	if cfg.Runner.Workers > 0 {
		opts = append(opts, sso.WithAnomalyWorkers(cfg.Runner.Workers))
	}
	if cfg.Runner.DropPolicy != "" {
		opts = append(opts, sso.WithAnomalyDropPolicy(sso.AnomalyDropPolicy(cfg.Runner.DropPolicy)))
	}
	if m != nil {
		opts = append(opts, sso.WithAnomalyMetricsCallbacks(
			func(t, sev string) { m.AnomaliesDetectedTotal.WithLabelValues(t, sev).Inc() },
			func(reason string) { m.AnomalyDispatchDropsTotal.WithLabelValues(reason).Inc() },
			func(detector string) { m.AnomalyInspectErrorsTotal.WithLabelValues(detector).Inc() },
		))
	}
	rt.runner = sso.NewAsyncAnomalyRunner(detectors, sink, opts...)
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
func openRecentLoginStore(cfg config.AnomalyStoreConfig) (sso.RecentLoginStore, *sqlitestores.RecentLoginStore, error) {
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
func openIPFailureCounter(cfg config.AnomalyStoreConfig) (sso.IPFailureCounter, *sqlitestores.IPFailureCounter, error) {
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
func buildAnomalyDetectors(cfg config.AnomalyDetectorsConfig, recent sso.RecentLoginStore, ipCounter sso.IPFailureCounter, ipSalt []byte) ([]sso.AnomalyDetector, error) {
	var detectors []sso.AnomalyDetector
	if cfg.ImpossibleTravel.Enabled {
		opts := []anomaly.ImpossibleTravelOption{}
		if cfg.ImpossibleTravel.MaxSpeedKmh > 0 {
			opts = append(opts, anomaly.WithImpossibleTravelMaxSpeed(cfg.ImpossibleTravel.MaxSpeedKmh))
		}
		if cfg.ImpossibleTravel.HistoryWindow > 0 {
			opts = append(opts, anomaly.WithImpossibleTravelWindow(cfg.ImpossibleTravel.HistoryWindow))
		}
		d, err := anomaly.NewImpossibleTravelDetector(recent, ipSalt, opts...)
		if err != nil {
			return nil, fmt.Errorf("impossible_travel: %w", err)
		}
		detectors = append(detectors, d)
	}
	if cfg.Velocity.Enabled {
		opts := []anomaly.VelocityOption{}
		// Honor 0 as "explicitly disable this check" (not "use default").
		opts = append(opts,
			anomaly.WithVelocityHourlyLimit(cfg.Velocity.HourlyLimit),
			anomaly.WithVelocityDailyLimit(cfg.Velocity.DailyLimit),
		)
		d, err := anomaly.NewVelocityDetector(recent, opts...)
		if err != nil {
			return nil, fmt.Errorf("velocity: %w", err)
		}
		detectors = append(detectors, d)
	}
	if cfg.NewDevice.Enabled {
		opts := []anomaly.NewDeviceOption{}
		if cfg.NewDevice.BaselineWindow > 0 {
			opts = append(opts, anomaly.WithNewDeviceBaselineWindow(cfg.NewDevice.BaselineWindow))
		}
		opts = append(opts, anomaly.WithNewDeviceBootstrapGracePeriod(cfg.NewDevice.BootstrapGracePeriod))
		d, err := anomaly.NewNewDeviceDetector(recent, ipSalt, opts...)
		if err != nil {
			return nil, fmt.Errorf("new_device: %w", err)
		}
		detectors = append(detectors, d)
	}
	if cfg.NewCountry.Enabled {
		opts := []anomaly.NewCountryOption{}
		if cfg.NewCountry.BaselineWindow > 0 {
			opts = append(opts, anomaly.WithNewCountryBaselineWindow(cfg.NewCountry.BaselineWindow))
		}
		opts = append(opts, anomaly.WithNewCountryBootstrapGracePeriod(cfg.NewCountry.BootstrapGracePeriod))
		d, err := anomaly.NewNewCountryDetector(recent, opts...)
		if err != nil {
			return nil, fmt.Errorf("new_country: %w", err)
		}
		detectors = append(detectors, d)
	}
	if cfg.BruteForceShadow.Enabled {
		opts := []anomaly.BruteForceShadowOption{}
		if cfg.BruteForceShadow.Window > 0 {
			opts = append(opts, anomaly.WithBruteForceShadowWindow(cfg.BruteForceShadow.Window))
		}
		opts = append(opts, anomaly.WithBruteForceShadowFailureLimit(cfg.BruteForceShadow.FailureLimit))
		opts = append(opts, anomaly.WithBruteForceShadowDistinctSubjectLimit(cfg.BruteForceShadow.DistinctSubjectLimit))
		d, err := anomaly.NewBruteForceShadowDetector(ipCounter, ipSalt, opts...)
		if err != nil {
			return nil, fmt.Errorf("brute_force_shadow: %w", err)
		}
		detectors = append(detectors, d)
	}
	return detectors, nil
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
