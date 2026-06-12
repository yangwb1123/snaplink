package main

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

func TestBuildAnomaly_DisabledReturnsNil(t *testing.T) {
	rt, err := buildAnomaly(config.AnomalyConfig{Enabled: false}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildAnomaly: %v", err)
	}
	if rt != nil {
		t.Errorf("disabled should return nil, got %v", rt)
	}
}

func TestBuildAnomaly_NoDetectorsEnabledReturnsNil(t *testing.T) {
	// Enabled=true but no detector toggled — runner would be inert,
	// cmd warns + returns nil so callers don't accidentally wire a
	// no-op runner.
	rt, err := buildAnomaly(config.AnomalyConfig{
		Enabled:     true,
		IPSalt:      hex.EncodeToString([]byte("0123456789abcdef")),
		RecentLogin: config.AnomalyStoreConfig{Backend: "memory"},
		IPFailure:   config.AnomalyStoreConfig{Backend: "memory"},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildAnomaly: %v", err)
	}
	if rt != nil {
		t.Errorf("no-detector should return nil, got %+v", rt)
	}
}

func TestBuildAnomaly_HappyPathMemory(t *testing.T) {
	rt, err := buildAnomaly(config.AnomalyConfig{
		Enabled:     true,
		IPSalt:      hex.EncodeToString([]byte("0123456789abcdef")),
		RecentLogin: config.AnomalyStoreConfig{Backend: "memory"},
		IPFailure:   config.AnomalyStoreConfig{Backend: "memory"},
		Detectors: config.AnomalyDetectorsConfig{
			ImpossibleTravel: config.ImpossibleTravelDetectorConfig{Enabled: true},
			Velocity:         config.VelocityDetectorConfig{Enabled: true, HourlyLimit: 25},
		},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildAnomaly: %v", err)
	}
	if rt == nil || rt.runner == nil {
		t.Fatal("happy path should return runtime + runner")
	}
	t.Cleanup(func() { rt.close(context.Background()) })
}

func TestBuildAnomaly_SQLiteBackendOpenedAndClosed(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "anom.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	rt, err := buildAnomaly(config.AnomalyConfig{
		Enabled:     true,
		IPSalt:      hex.EncodeToString([]byte("0123456789abcdef")),
		RecentLogin: config.AnomalyStoreConfig{Backend: "sqlite", SQLite: config.AnomalyStoreSQLiteConfig{DSN: dsn}},
		IPFailure:   config.AnomalyStoreConfig{Backend: "sqlite", SQLite: config.AnomalyStoreSQLiteConfig{DSN: dsn}},
		Detectors: config.AnomalyDetectorsConfig{
			ImpossibleTravel: config.ImpossibleTravelDetectorConfig{Enabled: true},
		},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildAnomaly: %v", err)
	}
	if rt == nil || rt.recentSQLite == nil || rt.ipFailSQLite == nil {
		t.Fatal("sqlite backends should be opened")
	}
	// Ping verifies they're alive.
	if err := rt.recentSQLite.Ping(context.Background()); err != nil {
		t.Errorf("recentSQLite ping: %v", err)
	}
	if err := rt.ipFailSQLite.Ping(context.Background()); err != nil {
		t.Errorf("ipFailSQLite ping: %v", err)
	}
	// Close drains + releases.
	rt.close(context.Background())
	if err := rt.recentSQLite.Ping(context.Background()); err == nil {
		t.Error("recentSQLite should be closed after rt.close")
	}
}

func TestBuildAnomaly_SQLiteRequiresDSN(t *testing.T) {
	_, err := buildAnomaly(config.AnomalyConfig{
		Enabled:     true,
		IPSalt:      hex.EncodeToString([]byte("0123456789abcdef")),
		RecentLogin: config.AnomalyStoreConfig{Backend: "sqlite"},
		Detectors:   config.AnomalyDetectorsConfig{ImpossibleTravel: config.ImpossibleTravelDetectorConfig{Enabled: true}},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("sqlite without DSN should error")
	}
	if !strings.Contains(err.Error(), "dsn") {
		t.Errorf("error should mention dsn: %v", err)
	}
}

func TestBuildAnomaly_RejectsUnknownBackend(t *testing.T) {
	_, err := buildAnomaly(config.AnomalyConfig{
		Enabled:     true,
		IPSalt:      hex.EncodeToString([]byte("0123456789abcdef")),
		RecentLogin: config.AnomalyStoreConfig{Backend: "redis"}, // not yet supported
		Detectors:   config.AnomalyDetectorsConfig{ImpossibleTravel: config.ImpossibleTravelDetectorConfig{Enabled: true}},
	}, nil, nil, quietLogger())
	if err == nil {
		t.Fatal("unknown backend should error")
	}
}

func TestBuildAnomaly_AllDetectorsEnable(t *testing.T) {
	rt, err := buildAnomaly(config.AnomalyConfig{
		Enabled:     true,
		IPSalt:      hex.EncodeToString([]byte("0123456789abcdef")),
		RecentLogin: config.AnomalyStoreConfig{Backend: "memory"},
		IPFailure:   config.AnomalyStoreConfig{Backend: "memory"},
		Detectors: config.AnomalyDetectorsConfig{
			ImpossibleTravel: config.ImpossibleTravelDetectorConfig{Enabled: true, MaxSpeedKmh: 600},
			Velocity:         config.VelocityDetectorConfig{Enabled: true, HourlyLimit: 25, DailyLimit: 200},
			NewDevice:        config.BaselineDetectorConfig{Enabled: true, BaselineWindow: 30 * 24 * time.Hour},
			NewCountry:       config.BaselineDetectorConfig{Enabled: true},
			BruteForceShadow: config.BruteForceShadowDetectorConfig{Enabled: true, FailureLimit: 50, DistinctSubjectLimit: 10},
		},
	}, nil, nil, quietLogger())
	if err != nil {
		t.Fatalf("buildAnomaly: %v", err)
	}
	if rt == nil {
		t.Fatal("all-detectors path should return runtime")
	}
	t.Cleanup(func() { rt.close(context.Background()) })
}

func TestDecodeAnomalySalt_HexEncodedAccepted(t *testing.T) {
	b, err := decodeAnomalySalt(hex.EncodeToString([]byte("hello")))
	if err != nil {
		t.Fatalf("decodeAnomalySalt: %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("hex roundtrip: %q", b)
	}
}

func TestDecodeAnomalySalt_NonHexFallsBackToRaw(t *testing.T) {
	b, _ := decodeAnomalySalt("not-hex-this-is-raw")
	if string(b) != "not-hex-this-is-raw" {
		t.Errorf("raw fallback: %q", b)
	}
}

func TestDecodeAnomalySalt_EmptyReturnsNilNoError(t *testing.T) {
	b, err := decodeAnomalySalt("")
	if err != nil {
		t.Fatalf("decodeAnomalySalt: %v", err)
	}
	if b != nil {
		t.Errorf("empty salt: got %v, want nil", b)
	}
}
